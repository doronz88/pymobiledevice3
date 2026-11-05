#!/usr/bin/env python3
"""Record the terminal sessions shown in the docs from a real device, as colored HTML transcripts.

Each scenario runs the real CLI in a pseudo-terminal, with the command line "typed" at a prompt and an
optional list of steps driving interactive programs (js-shell). The output is scrubbed of device
identifiers (``scrub()``), replayed through a terminal emulator (pyte), and the final screen is written
to docs/assets/terminal/<scenario>.html, colors included, for pages to include with
``--8<-- "docs/assets/terminal/<scenario>.html"``. The raw asciicast is kept next to it in a temporary
directory, so a transcript can be re-rendered without the device (``--render CAST``).

Review each transcript before committing it: it is a recording of a real device.

Usage (needs a connected device; one scenario at a time; requires pexpect and pyte):

    python3 misc/record_docs_casts.py pcap
    python3 misc/record_docs_casts.py --list
    python3 misc/record_docs_casts.py --render /path/to/pcap.cast
"""

import argparse
import html
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

import pexpect

TERMINAL_DIR = Path(__file__).resolve().parent.parent / "docs" / "assets" / "terminal"
CASTS_DIR = Path(tempfile.gettempdir()) / "pmd3-docs-casts"
COLS, ROWS = 110, 30
PROMPT = "\x1b[1;32m$\x1b[0m "
TYPE_DELAY = 0.045

# A step is ("expect", regex), ("type", text), ("keys", raw), ("sleep", seconds) or ("ctrl-c", None).
Step = tuple[str, Union[str, float, None]]


@dataclass
class Scenario:
    command: str
    duration: float = 12.0  # stop (Ctrl+C) after this many seconds unless the command exits first
    steps: list[Step] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    mask_frame_macs: bool = False  # hex dumps of Ethernet frames: mask the destination/source MACs
    trigger: str = ""  # a second command run in the background to cause activity...
    trigger_after: float = 3.0  # ...this many seconds after the recorded command starts


SCENARIOS: dict[str, Scenario] = {
    # Only Safari's traffic, caused by navigating it to example.com: ambient traffic can carry the
    # device's name (mDNS, DHCP) in its payload.
    "pcap": Scenario(
        "pymobiledevice3 pcap --process com.apple.WebKit -c 3",
        duration=30,
        mask_frame_macs=True,
        # A URL never visited before: a cached page sends no traffic. {nonce} is unique per recording.
        trigger="pymobiledevice3 webinspector js-shell --open-safari https://example.com/?from=pymobiledevice3-docs-{nonce}",
    ),
    "strace": Scenario(
        "pymobiledevice3 developer dvt core-profile-session parse-live --fs --process Preferences -c 60",
        duration=14,
        trigger="pymobiledevice3 developer dvt launch --kill-existing com.apple.Preferences",
    ),
    "js-shell": Scenario(
        "pymobiledevice3 webinspector js-shell --open-safari https://example.com",
        duration=60,
        env={"PROMPT_TOOLKIT_NO_CPR": "1"},
        steps=[
            ("expect", r">\s"),
            ("sleep", 1.0),
            ("type", "document.title\r"),
            ("expect", r">\s"),
            ("type", "document.querySelectorAll('a').length\r"),
            ("expect", r">\s"),
            ("type", "console.log('hello from ' + location.host)\r"),
            ("expect", r">\s"),
            ("sleep", 1.0),
            ("type", "navigator.userAg"),
            ("keys", "\t"),
            ("sleep", 1.2),
            ("keys", "\r"),
            ("expect", r">\s"),
            ("sleep", 1.5),
            ("keys", "\x04"),
        ],
    ),
}

# Literal identifiers to mask, read from the environment so they never live in this file:
#   PMD3_SCRUB="Device Name,My-Host.local=Studio-Mac.lan,..."  (comma-separated; SECRET masks it with
#   X's, SECRET=REPLACEMENT substitutes a replacement of the same length)
_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_UDID = re.compile(r"\b[0-9A-F]{8}-[0-9A-F]{16}\b|\b[0-9a-f]{40}\b")


_ANSI = r"(?:\x1b\[[0-9;]*m)*"
_HEX_LINE0 = re.compile(rf"{_ANSI}00000000{_ANSI}:")
_HEX_BYTE = re.compile(rf"{_ANSI}([0-9A-F]{{2}})(?=\x1b|\s)")
_VISIBLE = re.compile(rf"{_ANSI}(.)", re.DOTALL)
_MASKED_MACS = "020000000001020000000002"


def _mask_frame_macs(text: str) -> str:
    """Mask the first 12 bytes (destination and source MAC) of every hex dump, in hex and ASCII columns."""
    chars = list(text)
    for line0 in _HEX_LINE0.finditer(text):
        end_of_line = text.find("\n", line0.end())
        pos, hex_end = line0.end(), None
        for index in range(16):
            byte = _HEX_BYTE.search(text, pos, end_of_line)
            if byte is None:
                break
            if index < 12:
                chars[byte.start(1)], chars[byte.start(1) + 1] = _MASKED_MACS[2 * index : 2 * index + 2]
            pos = hex_end = byte.end()
        if hex_end is None:
            continue
        # The ASCII column follows the hex bytes after a run of spaces.
        masked, pos = 0, hex_end
        while masked < 12:
            ch = _VISIBLE.search(text, pos, end_of_line)
            if ch is None:
                break
            pos = ch.end()
            if masked == 0 and ch.group(1) == " ":
                continue
            chars[ch.start(1)] = "."
            masked += 1
    return "".join(chars)


def scrub(text: str, mask_frame_macs: bool = False) -> str:
    """Mask device identifiers. Every replacement keeps the length, so event boundaries survive."""
    for entry in filter(None, (s.strip() for s in os.environ.get("PMD3_SCRUB", "").split(","))):
        secret, _, replacement = entry.partition("=")
        replacement = replacement or "X" * len(secret)
        if len(replacement) != len(secret):
            raise ValueError(f"PMD3_SCRUB replacement for {secret!r} must have the same length")
        text = text.replace(secret, replacement)
    text = _UDID.sub(lambda m: "0" * len(m.group()), text)
    text = _MAC.sub("02:00:00:00:00:00", text)
    return _mask_frame_macs(text) if mask_frame_macs else text


class Recorder:
    def __init__(self) -> None:
        self.start = time.monotonic()
        self.events: list[tuple[float, str, str]] = []
        self.seen = ""  # everything the child printed, without escape sequences, for ("expect", ...)

    def out(self, data: str) -> None:
        self.events.append((round(time.monotonic() - self.start, 4), "o", data))

    def type(self, text: str) -> None:
        for ch in text:
            self.out(ch)
            time.sleep(TYPE_DELAY)

    def drain(self, child: pexpect.spawn, timeout: float) -> None:
        try:
            data = child.read_nonblocking(65536, timeout=timeout)
        except pexpect.TIMEOUT:
            return
        except pexpect.EOF:
            raise
        if data:
            self.out(data)
            self.seen += re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|[\b]", "", data)

    def save(self, path: Path, title: str, mask_frame_macs: bool = False) -> None:
        raw = "".join(event[2] for event in self.events)
        clean = scrub(raw, mask_frame_macs)
        if len(clean) != len(raw):
            raise AssertionError("scrub() must keep the length of the output")
        events, offset = [], 0
        for timestamp, kind, data in self.events:
            events.append((timestamp, kind, clean[offset : offset + len(data)]))
            offset += len(data)
        self.events = events
        header = {
            "version": 2,
            "width": COLS,
            "height": ROWS,
            "title": title,
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/zsh"},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            f.write(json.dumps(header) + "\n")
            for event in self.events:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")


def record(name: str, scenario: Scenario) -> Path:
    rec = Recorder()
    rec.out(PROMPT)
    time.sleep(0.6)
    rec.type(scenario.command)
    rec.out("\r\n")

    env = {**os.environ, "COLUMNS": str(COLS), "LINES": str(ROWS), "TERM": "xterm-256color", **scenario.env}
    # The cast shows `pymobiledevice3 ...`; PMD3_CMD runs something else in its place (for example
    # `uv run --no-project --with-editable . pymobiledevice3` to record the local checkout).
    argv = shlex.split(os.environ.get("PMD3_CMD", "pymobiledevice3")) + shlex.split(scenario.command)[1:]
    child = pexpect.spawn(argv[0], argv[1:], env=env, dimensions=(ROWS, COLS), encoding="utf-8", codec_errors="replace")
    deadline = time.monotonic() + scenario.duration
    trigger_at = time.monotonic() + scenario.trigger_after if scenario.trigger else None
    trigger: Union[subprocess.Popen[bytes], None] = None
    cursor = 0
    try:
        for kind, arg in scenario.steps:
            if kind == "expect":
                while not (match := re.compile(str(arg)).search(rec.seen, cursor)):
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"{name}: never saw {arg!r}")
                    rec.drain(child, 0.1)
                cursor = match.end()
            elif kind == "type":
                for ch in str(arg):
                    child.send(ch)
                    time.sleep(TYPE_DELAY)
                    rec.drain(child, 0.01)
            elif kind == "keys":
                child.send(str(arg))
            elif kind == "sleep":
                end = time.monotonic() + float(arg or 0)
                while time.monotonic() < end:
                    rec.drain(child, 0.05)
            elif kind == "ctrl-c":
                child.sendintr()
        while child.isalive() and time.monotonic() < deadline:
            rec.drain(child, 0.1)
            if trigger_at is not None and time.monotonic() >= trigger_at:
                trigger_at = None
                trigger_argv = shlex.split(os.environ.get("PMD3_CMD", "pymobiledevice3"))
                trigger_argv += shlex.split(scenario.trigger.replace("{nonce}", str(time.time_ns())))[1:]
                # Its own process group, so stopping it also stops what `uv run` started.
                trigger = subprocess.Popen(
                    trigger_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
        if child.isalive():
            child.sendintr()
            end = time.monotonic() + 5
            while child.isalive() and time.monotonic() < end:
                rec.drain(child, 0.1)
    except pexpect.EOF:
        pass
    finally:
        child.close(force=True)
        # A trigger left running keeps its device sessions (a Web Inspector one holds Safari).
        if trigger is not None and trigger.poll() is None:
            os.killpg(trigger.pid, signal.SIGINT)
            try:
                trigger.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(trigger.pid, signal.SIGKILL)
    rec.out(PROMPT)
    path = CASTS_DIR / f"{name}.cast"
    rec.save(path, scenario.command, scenario.mask_frame_macs)
    return path


# The 16 ANSI colors of a dark terminal theme; pyte reports 256-color and truecolor values as hex.
_PALETTE = {
    "black": "#3b4252", "red": "#e06c75", "green": "#98c379", "brown": "#e5c07b", "blue": "#61afef",
    "magenta": "#c678dd", "cyan": "#56b6c2", "white": "#dcdfe4", "brightblack": "#7f848e",
    "brightred": "#ff7b86", "brightgreen": "#b5e890", "brightbrown": "#ffd68a", "brightblue": "#7cc4ff",
    "brightmagenta": "#de94f2", "brightcyan": "#6fd2de", "brightwhite": "#ffffff",
}  # fmt: skip


def _css_color(color: str) -> str:
    if color in _PALETTE:
        return _PALETTE[color]
    return f"#{color}" if re.fullmatch(r"[0-9a-fA-F]{6}", color) else ""


def render(cast: Path) -> str:
    """Replay an asciicast through a terminal emulator and return its final screen as an HTML block."""
    import pyte  # only needed for rendering

    lines = cast.read_text().splitlines()
    header = json.loads(lines[0])
    screen = pyte.Screen(header["width"], 2000)
    stream = pyte.Stream(screen)
    for line in lines[1:]:
        stream.feed(json.loads(line)[2])

    classes: dict[str, str] = {}  # style -> short class name

    def span(text: str, style: str) -> str:
        if not style:
            return html.escape(text)
        name = classes.setdefault(style, f"t{len(classes)}")
        return f'<span class="{name}">{html.escape(text)}</span>'

    rows = []
    for y in range(screen.lines):
        row, run, run_style = [], "", ""
        for x in range(screen.columns):
            char = screen.buffer[y][x]
            if char.data.isspace() and run:
                run += char.data  # a space's color is invisible: keep the current run going
                continue
            fg = _css_color(char.fg) if char.fg != "default" else ""
            style = ";".join(filter(None, [f"color:{fg}" if fg else "", "font-weight:bold" if char.bold else ""]))
            if style != run_style and run:
                row.append(span(run, run_style))
                run = ""
            run_style = style
            run += char.data
        if run.rstrip():
            row.append(span(run.rstrip(), run_style))
        rows.append("".join(row))
    while rows and re.sub(r"<[^>]+>", "", rows[-1]).strip() in ("", "$"):
        rows.pop()  # trailing blank lines and the final prompt
    # No blank lines inside the block: Markdown would end the raw HTML block there.
    body = "\n".join(row if row else "&#8203;" for row in rows)
    css = "".join(f".pmd-terminal .{name}{{{style}}}" for style, name in classes.items())
    return f'<div class="pmd-terminal"><style>{css}</style><pre><code>{body}</code></pre></div>\n'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", nargs="?", choices=sorted(SCENARIOS))
    parser.add_argument("--list", action="store_true", help="List the scenarios and their commands")
    parser.add_argument("--render", type=Path, metavar="CAST", help="Only re-render an existing recording")
    args = parser.parse_args()
    if args.render:
        out = TERMINAL_DIR / f"{args.render.stem}.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render(args.render))
        print(f"wrote {out}", file=sys.stderr)
        return
    if args.list or not args.scenario:
        for name, scenario in SCENARIOS.items():
            print(f"{name:10} {scenario.command}")
        return
    cast = record(args.scenario, SCENARIOS[args.scenario])
    out = TERMINAL_DIR / f"{args.scenario}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(cast))
    print(f"wrote {out} (recording: {cast})", file=sys.stderr)


if __name__ == "__main__":
    main()
