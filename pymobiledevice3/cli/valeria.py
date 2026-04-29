"""``pymobiledevice3 valeria`` — H.264 screen capture over USB.

Exposes the unified :class:`pymobiledevice3.services.valeria.IOSScreenCapture`
service: enable iPad screen capture, write Annex-B-framed H.264 to a file or
stdout. Decode/render is the consumer's job — pipe the output to ``ffmpeg``
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
    IOSScreenCapture,
    MultipleDevicesError,
    ScreenRecordingPermissionError,
)

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="valeria",
    help="iOS screen capture (H.264 over USB).",
)


@cli.command("valeria")
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
    backend: Annotated[str, typer.Option(
        "--backend",
        help="auto (default; cmio on macOS, libusb elsewhere), cmio, or libusb.",
    )] = "auto",
    duration: Annotated[int, typer.Option(
        "--duration",
        help="Stop after N seconds (0 = run until interrupted).",
    )] = 0,
) -> None:
    """Capture the iOS screen as Annex-B H.264 and write to OUTPUT."""
    try:
        cap = IOSScreenCapture.create(udid=udid, backend=backend)  # type: ignore[arg-type]
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

    if output == "-":
        sink = sys.stdout.buffer
        close_sink = False
    else:
        sink = open(output, "wb")
        close_sink = True

    deadline = time.monotonic() + duration if duration > 0 else None
    n_frames = 0
    n_bytes = 0
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
    finally:
        if close_sink:
            sink.close()
        cap.stop()
        typer.echo(
            f"wrote {n_frames} frames ({n_bytes / 1024:.1f} KiB) "
            f"from {cap.device_name} ({cap.width}x{cap.height})",
            err=True,
        )
