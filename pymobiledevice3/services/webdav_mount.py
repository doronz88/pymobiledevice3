"""Cross-platform helpers for mounting a WebDAV URL locally and revealing it.

Pure stdlib (no ASGIWebDAV), so it is importable on every supported Python version and
can be used by the CLI's ``--mount`` precheck as well as by the serving code.

Per host:
- macOS:   ``mount_webdav`` mounts to a temp dir; ``open`` reveals it.
- Windows: ``net use`` maps a drive letter; ``explorer`` reveals it.
- Linux:   ``gio mount`` mounts the ``dav(s)://`` URL; ``xdg-open`` reveals it.

Everything is best-effort: if the host's tool is missing or the mount fails, the caller
falls back to printing the URL for the user to open manually.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from typing import Optional


@dataclass
class MountedVolume:
    """A mounted WebDAV volume: what to reveal, and how to unmount it."""

    reveal_target: str  # a local path or a URL to open in the file manager
    unmount_command: Optional[list[str]]


def webdav_mount_supported() -> bool:
    """Whether this host has a tool to auto-mount a WebDAV volume."""
    if sys.platform == "darwin":
        return shutil.which("mount_webdav") is not None
    if sys.platform == "win32":
        return shutil.which("net") is not None
    return shutil.which("gio") is not None


def _sanitize_label(label: str) -> str:
    """Make ``label`` safe as a single filesystem path component."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", label)
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-._")
    return (cleaned or "webdav")[:100]


def _dav_url(http_url: str) -> str:
    """Convert an http(s) URL to the dav(s) scheme understood by ``gio``."""
    if http_url.startswith("https://"):
        return "davs://" + http_url[len("https://") :]
    if http_url.startswith("http://"):
        return "dav://" + http_url[len("http://") :]
    return http_url


async def _run(command: list[str]) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    out, _ = await proc.communicate()
    return (proc.returncode or 0), out.decode(errors="replace")


async def mount_webdav_volume(url: str, *, label: str = "pmd-webdav") -> Optional[MountedVolume]:
    """Mount ``url`` locally using the host's native mechanism.

    :param url: the WebDAV URL to mount.
    :param label: a descriptive name for the mount point (macOS), so it is easy to spot in Finder;
        a random suffix is always appended.
    :return: a :class:`MountedVolume` on success, or ``None`` if unsupported or the mount failed.
    """
    try:
        if sys.platform == "darwin":
            if shutil.which("mount_webdav") is None:
                return None
            mount_point = tempfile.mkdtemp(prefix=_sanitize_label(label) + "-")
            rc, _ = await _run(["mount_webdav", "-S", url, mount_point])
            if rc != 0:
                return None
            return MountedVolume(mount_point, ["umount", mount_point])

        if sys.platform == "win32":
            if shutil.which("net") is None:
                return None
            rc, out = await _run(["net", "use", "*", url])
            if rc != 0:
                return None
            match = re.search(r"\b([A-Za-z]):", out)
            if match is None:
                return None
            drive = match.group(1) + ":"
            return MountedVolume(drive, ["net", "use", drive, "/delete", "/y"])

        # linux / other unixes
        if shutil.which("gio") is None:
            return None
        dav = _dav_url(url)
        rc, _ = await _run(["gio", "mount", dav])
        if rc != 0:
            return None
        return MountedVolume(dav, ["gio", "mount", "-u", dav])
    except OSError:
        return None


async def unmount_webdav_volume(mounted: MountedVolume) -> None:
    """Unmount a previously mounted volume, best-effort."""
    if mounted.unmount_command is not None:
        with suppress(OSError):
            await _run(mounted.unmount_command)


def _opener_command(target: str) -> Optional[list[str]]:
    """Command to open ``target`` (a path or URL) in the OS file manager, or ``None``."""
    if sys.platform == "darwin":
        return ["open", target]
    if sys.platform == "win32":
        return ["explorer", target]
    if shutil.which("xdg-open") is not None:
        return ["xdg-open", target]
    if shutil.which("gio") is not None:
        return ["gio", "open", target]
    return None


async def reveal_in_file_manager(target: str) -> None:
    """Open ``target`` in the OS file manager, best-effort (never raises)."""
    command = _opener_command(target)
    if command is None:
        return
    with suppress(OSError):
        await _run(command)
