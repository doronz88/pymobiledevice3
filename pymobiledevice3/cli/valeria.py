"""``pymobiledevice3 valeria`` -- H.264 screen capture over USB (macOS).

Exposes the unified :class:`pymobiledevice3.services.valeria.ValeriaScreenCapture`
service: enable iOS screen capture, write Annex-B-framed H.264 to a file or
stdout. Decode/render is the consumer's job; pipe the output to ``ffmpeg``
to render or transcode.

Examples
--------

    pymobiledevice3 valeria -o /tmp/out.h264
    pymobiledevice3 valeria -o - --duration 10 | ffplay -f h264 -
"""
from __future__ import annotations

import logging
import sys
import time
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.services.valeria import (
    BackendUnavailableError,
    DeviceNotFoundError,
    ValeriaScreenCapture,
    MultipleDevicesError,
    ScreenRecordingPermissionError,
)

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="valeria",
    help="iOS screen capture (H.264 over USB).",
    no_args_is_help=True,
)


def _open_sink(output: str) -> tuple:
    if output == "-":
        return sys.stdout.buffer, False
    return open(output, "wb"), True


@cli.callback(invoke_without_command=True)
def capture(
    output: Annotated[str, typer.Option(
        "--output", "-o",
        help="Output file path, or '-' for stdout (e.g. for piping into ffmpeg).",
    )],
    udid: Annotated[Optional[str], typer.Option(
        "--udid",
        help="Match a specific device by UDID (required when multiple devices "
             "are attached).",
    )] = None,
    duration: Annotated[int, typer.Option(
        "--duration",
        help="Stop after N seconds (0 = run until interrupted).",
    )] = 0,
) -> None:
    """Capture the iOS screen as Annex-B H.264 and write to OUTPUT."""
    try:
        cap = ValeriaScreenCapture.create(udid=udid)
    except (BackendUnavailableError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2)

    try:
        cap.start()
    except (DeviceNotFoundError, MultipleDevicesError,
            ScreenRecordingPermissionError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(f"error: failed to start capture: {exc}", err=True)
        raise typer.Exit(code=1)

    sink, close_sink = _open_sink(output)
    n_frames = 0
    n_bytes = 0

    def consume() -> None:
        nonlocal n_frames, n_bytes
        deadline = time.monotonic() + duration if duration > 0 else None
        try:
            for frame in cap.frames():
                data = frame.to_annex_b()
                sink.write(data)
                sink.flush()
                n_frames += 1
                n_bytes += len(data)
                if deadline is not None and time.monotonic() >= deadline:
                    break
        except KeyboardInterrupt:
            pass

    try:
        # cap.run() drives the main thread's CFRunLoop on the macOS CMIO
        # backend so callbacks dispatch event-driven to *consume* on a
        # worker thread.
        cap.run(consume)
    except KeyboardInterrupt:
        pass
    finally:
        if close_sink:
            sink.close()
        cap.stop()
        typer.echo(
            f"wrote {n_frames} frames ({n_bytes / 1024:.1f} KiB) "
            f"from {cap.device_name} ({cap.width}x{cap.height})",
            err=True,
        )
