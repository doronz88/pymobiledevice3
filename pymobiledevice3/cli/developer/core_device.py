import asyncio
import logging
import posixpath
import sys
import time
from pathlib import Path
from typing import IO, Annotated, Optional

import click
import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import RSDServiceProviderDep, async_command, print_json
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.configuration_service import ConfigurationService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService
from pymobiledevice3.remote.core_device.diagnostics_service import DiagnosticsServiceService
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.file_service import APPLE_DOMAIN_DICT, FileServiceService
from pymobiledevice3.remote.core_device.hid_service import (
    ASCII_TO_HID,
    DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
    DIGITIZER_SURFACE_TOUCHSCREEN_GESTURE,
    HID_BUTTON_STATE_CANCELED,
    HID_BUTTON_STATE_DOWN,
    HID_BUTTON_STATE_UP,
    KEY_LEFT_SHIFT,
    TOUCHSCREEN_STATE_CONTACT,
    TOUCHSCREEN_STATE_RELEASE,
    IndigoHIDService,
    UniversalHIDServiceService,
    touch_session,
)
from pymobiledevice3.remote.core_device.location_service import LocationService
from pymobiledevice3.remote.core_device.screen_capture_service import ScreenCaptureService
from pymobiledevice3.remote.core_device.screen_stream import (
    ScreenStreamServer,
    capture_audio_rtp_to_file,
    capture_rtp_to_file,
)
from pymobiledevice3.remote.core_device.vnc_server import VncStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.crash_reports import CrashReportsManager
from pymobiledevice3.utils import try_decode

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="core-device",
    help="Access DeveloperDiskImage services (files, processes, app launch, diagnostics).",
    no_args_is_help=True,
)


async def core_device_list_directory_task(
    service_provider: RemoteServiceDiscoveryService, domain: str, path: str, identifier: str
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        print_json(await file_service.retrieve_directory_list(path))


@cli.command("list-directory")
@async_command
async def core_device_list_directory(
    service_provider: RSDServiceProviderDep,
    domain: Annotated[
        str,
        typer.Argument(click_type=click.Choice(APPLE_DOMAIN_DICT)),
    ],
    path: str,
    identifier: Annotated[str, typer.Option()] = "",
) -> None:
    """List directory contents for a given domain/path."""
    await core_device_list_directory_task(service_provider, domain, path, identifier)


async def core_device_read_file_task(
    service_provider: RemoteServiceDiscoveryService,
    domain: str,
    path: str,
    identifier: str,
    output: Optional[IO],
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        buf = await file_service.retrieve_file(path)
        if output is not None:
            output.write(buf)
        else:
            print(try_decode(buf))


@cli.command("read-file")
@async_command
async def core_device_read_file(
    service_provider: RSDServiceProviderDep,
    domain: Annotated[
        str,
        typer.Argument(click_type=click.Choice(APPLE_DOMAIN_DICT)),
    ],
    path: str,
    *,
    identifier: Annotated[str, typer.Option()] = "",
    output: Annotated[
        Path,
        typer.Option("--output", "-o"),
    ],
) -> None:
    """Read a file from a domain/path to stdout or --output."""
    with output.open("wb") as output_file:
        await core_device_read_file_task(service_provider, domain, path, identifier, output_file)


async def core_device_propose_empty_file_task(
    service_provider: RemoteServiceDiscoveryService,
    domain: str,
    path: str,
    identifier: str,
    file_permissions: int,
    uid: int,
    gid: int,
    creation_time: int,
    last_modification_time: int,
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        await file_service.propose_empty_file(path, file_permissions, uid, gid, creation_time, last_modification_time)


@cli.command("propose-empty-file")
@async_command
async def core_device_propose_empty_file(
    service_provider: RSDServiceProviderDep,
    domain: Annotated[
        str,
        typer.Argument(click_type=click.Choice(APPLE_DOMAIN_DICT)),
    ],
    path: str,
    identifier: Annotated[str, typer.Option()] = "",
    file_permissions: Annotated[int, typer.Option()] = 0o644,
    uid: Annotated[int, typer.Option()] = 501,
    gid: Annotated[int, typer.Option()] = 501,
    creation_time: Annotated[Optional[int], typer.Option()] = None,
    last_modification_time: Annotated[Optional[int], typer.Option()] = None,
) -> None:
    """Create an empty file at the given domain/path with custom permissions/owner/timestamps."""
    await core_device_propose_empty_file_task(
        service_provider,
        domain,
        path,
        identifier,
        file_permissions,
        uid,
        gid,
        creation_time if creation_time is not None else int(time.time()),
        last_modification_time if last_modification_time is not None else int(time.time()),
    )


async def core_device_list_launch_application_task(
    service_provider: RemoteServiceDiscoveryService,
    bundle_identifier: str,
    argument: list[str],
    kill_existing: bool,
    suspended: bool,
    env: dict[str, str],
) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.launch_application(bundle_identifier, argument, kill_existing, suspended, env))


@cli.command("launch-application")
@async_command
async def core_device_launch_application(
    service_provider: RSDServiceProviderDep,
    bundle_identifier: str,
    argument: list[str],
    kill_existing: Annotated[
        bool,
        typer.Option(help="Whether to kill an existing instance of this process"),
    ] = True,
    suspended: Annotated[bool, typer.Option(help="Same as WaitForDebugger")] = False,
    env: Annotated[
        Optional[list[str]],
        typer.Option(
            help="Environment variable to pass to process given as key=value (can be specified multiple times)"
        ),
    ] = None,
) -> None:
    """Launch an app; optionally kill existing, wait for debugger, or set env vars."""
    await core_device_list_launch_application_task(
        service_provider,
        bundle_identifier,
        list(argument),
        kill_existing,
        suspended,
        dict(var.split("=", 1) for var in env or ()),
    )


async def core_device_list_processes_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.list_processes())


@cli.command("list-processes")
@async_command
async def core_device_list_processes(service_provider: RSDServiceProviderDep) -> None:
    """List running processes via CoreDevice."""
    await core_device_list_processes_task(service_provider)


async def core_device_uninstall_app_task(
    service_provider: RemoteServiceDiscoveryService, bundle_identifier: str
) -> None:
    async with AppServiceService(service_provider) as app_service:
        await app_service.uninstall_app(bundle_identifier)


@cli.command("uninstall")
@async_command
async def core_device_uninstall_app(service_provider: RSDServiceProviderDep, bundle_identifier: str) -> None:
    """Uninstall an app by bundle identifier via CoreDevice."""
    await core_device_uninstall_app_task(service_provider, bundle_identifier)


async def core_device_send_signal_to_process_task(
    service_provider: RemoteServiceDiscoveryService, pid: int, signal: int
) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.send_signal_to_process(pid, signal))


@cli.command("send-signal-to-process")
@async_command
async def core_device_send_signal_to_process(service_provider: RSDServiceProviderDep, pid: int, signal: int) -> None:
    """Send signal to process"""
    await core_device_send_signal_to_process_task(service_provider, pid, signal)


async def core_device_get_device_info_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_device_info())


@cli.command("get-device-info")
@async_command
async def core_device_get_device_info(service_provider: RSDServiceProviderDep) -> None:
    """Get device information"""
    await core_device_get_device_info_task(service_provider)


async def core_device_get_display_info_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_display_info())


@cli.command("get-display-info")
@async_command
async def core_device_get_display_info(service_provider: RSDServiceProviderDep) -> None:
    """Get display information"""
    await core_device_get_display_info_task(service_provider)


async def core_device_query_mobilegestalt_task(service_provider: RemoteServiceDiscoveryService, key: list[str]) -> None:
    """Query MobileGestalt"""
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.query_mobilegestalt(key))


@cli.command("query-mobilegestalt")
@async_command
async def core_device_query_mobilegestalt(service_provider: RSDServiceProviderDep, key: list[str]) -> None:
    """Query MobileGestalt"""
    await core_device_query_mobilegestalt_task(service_provider, key)


async def core_device_get_lockstate_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_lockstate())


@cli.command("get-lockstate")
@async_command
async def core_device_get_lockstate(service_provider: RSDServiceProviderDep) -> None:
    """Get lockstate"""
    await core_device_get_lockstate_task(service_provider)


@cli.command("user-interface-style")
@async_command
async def core_device_user_interface_style(
    service_provider: RSDServiceProviderDep,
    style: Annotated[Optional[str], typer.Argument(click_type=click.Choice(["dark", "light"]))] = None,
) -> None:
    """Get the active user-interface style; pass dark/light to set it."""
    async with ConfigurationService(service_provider) as config:
        if style is None:
            print_json(await config.get_user_interface_style())
        else:
            await config.set_user_interface_style(style)


async def core_device_list_apps_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.list_apps())


@cli.command("list-apps")
@async_command
async def core_device_list_apps(service_provider: RSDServiceProviderDep) -> None:
    """Get application list"""
    await core_device_list_apps_task(service_provider)


async def core_device_sysdiagnose_task(service_provider: RemoteServiceDiscoveryService, output: Path) -> None:
    async with DiagnosticsServiceService(service_provider) as service:
        response = await service.capture_sysdiagnose(False)
        logger.info(f"Operation response: {response}")
        if output.is_dir():
            output /= response.preferred_filename
        logger.info(f"Downloading sysdiagnose to: {output}")

        # get the file over lockdownd which is WAYYY faster
        lockdown = await create_using_usbmux(service_provider.udid)
        async with CrashReportsManager(lockdown) as crash_reports_manager:
            await crash_reports_manager.afc.pull(
                posixpath.join(f"/DiagnosticLogs/sysdiagnose/{response.preferred_filename}"), str(output)
            )


@cli.command("sysdiagnose")
@async_command
async def core_device_sysdiagnose(
    service_provider: RSDServiceProviderDep,
    output: Annotated[
        Path,
        typer.Argument(dir_okay=True, file_okay=True, exists=True),
    ],
) -> None:
    """Execute sysdiagnose and fetch the output file"""
    await core_device_sysdiagnose_task(service_provider, output)


screen_capture_cli = InjectingTyper(
    name="screen-capture",
    help="Capture content from the device's screen (com.apple.coredevice.screencaptureservice).",
    no_args_is_help=True,
)
cli.add_typer(screen_capture_cli)


async def core_device_screen_capture_screenshot_task(
    service_provider: RemoteServiceDiscoveryService, output: Path, display_unique_id: Optional[str]
) -> None:
    async with ScreenCaptureService(service_provider) as service:
        response = await service.capture_screenshot(display_unique_id=display_unique_id)
    output.write_bytes(response["image"])
    logger.info(f"Screenshot saved to: {output}")


@screen_capture_cli.command("screenshot")
@async_command
async def core_device_screen_capture_screenshot(
    service_provider: RSDServiceProviderDep,
    output: Annotated[Path, typer.Argument()],
    display_unique_id: Annotated[Optional[str], typer.Option("--display-unique-id")] = None,
) -> None:
    """Capture a PNG screenshot of the device's screen."""
    await core_device_screen_capture_screenshot_task(service_provider, output, display_unique_id)


# ---------------------------------------------------------------------------
# HID (Indigo) — com.apple.coredevice.hid.indigo
# ---------------------------------------------------------------------------
hid_cli = InjectingTyper(
    name="hid",
    help="Send HID button events (com.apple.coredevice.hid.indigo).",
    no_args_is_help=True,
)
cli.add_typer(hid_cli)


def _parse_int_auto(value: str) -> int:
    """Parse an int that may be decimal, ``0xHEX``, ``0o755``, ``0b1010``, etc."""
    return int(value, 0)


_BUTTON_STATE_CHOICES = {
    "down": HID_BUTTON_STATE_DOWN,
    "up": HID_BUTTON_STATE_UP,
    "canceled": HID_BUTTON_STATE_CANCELED,
}

# Named iOS hardware buttons → (usage_page, usage_code, hold_seconds).
# Most physical iOS buttons live on the Consumer page (0x0C). ``hold_seconds``
# is how long to keep DOWN before sending UP for the ``press`` shortcut --
# iOS distinguishes a tap (Home / Vol / Mute) from a hold (Lock = sleep,
# Siri = start listening) by the time the usage stays asserted. A 0 s hold
# (which the previous implementation effectively did via back-to-back
# send_button calls ~70 µs apart) reads to backboardd as bounce noise and
# only the tap-class buttons fire on it.
_NAMED_BUTTONS: dict[str, tuple[int, int, float]] = {
    "home": (0x0C, 0x40, 0.05),  # Consumer / Menu
    "lock": (0x0C, 0x30, 0.5),  # Consumer / Power, held long enough for iOS to sleep
    "volume-up": (0x0C, 0xE9, 0.05),  # Consumer / Volume Increment
    "volume-down": (0x0C, 0xEA, 0.05),  # Consumer / Volume Decrement
    "mute": (0x0C, 0xE2, 0.05),  # Consumer / Mute
    "siri": (0x0C, 0xCF, 1.0),  # Consumer / Voice Command, held to start listening
}


async def _send_button_press(
    service: IndigoHIDService, usage_page: int, usage_code: int, state: str, hold: float = 0.05
) -> None:
    """Dispatch a single button state (down/up/canceled), or down+up for ``press``."""
    if state == "press":
        await service.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
        await asyncio.sleep(hold)
        await service.send_button(usage_page, usage_code, HID_BUTTON_STATE_UP)
    else:
        await service.send_button(usage_page, usage_code, _BUTTON_STATE_CHOICES[state])
    # dtuhidd dispatches messages async; if we close immediately the FIN can arrive
    # before the last enqueued body gets delivered to the handler and the message is
    # dropped during channel cancel.
    await asyncio.sleep(0.1)


@hid_cli.command("button")
@async_command
async def core_device_hid_button(
    service_provider: RSDServiceProviderDep,
    name: Annotated[
        str,
        typer.Argument(
            click_type=click.Choice(list(_NAMED_BUTTONS)),
            help="Named hardware button (home, power, volume-up, ...)",
        ),
    ],
    state: Annotated[
        str,
        typer.Argument(
            click_type=click.Choice(["press", *_BUTTON_STATE_CHOICES]),
            help="press = send down+up; otherwise send a single state event",
        ),
    ] = "press",
) -> None:
    """Press a named iOS hardware button (home / power / volume-up / etc.)."""
    usage_page, usage_code, hold = _NAMED_BUTTONS[name]
    async with IndigoHIDService(service_provider) as service:
        await _send_button_press(service, usage_page, usage_code, state, hold)


@hid_cli.command("raw-button")
@async_command
async def core_device_hid_raw_button(
    service_provider: RSDServiceProviderDep,
    usage_page: Annotated[str, typer.Argument(help="HID usage page (decimal or 0xHEX), e.g. 0x0C for Consumer")],
    usage_code: Annotated[str, typer.Argument(help="HID usage code (decimal or 0xHEX)")],
    state: Annotated[
        str,
        typer.Argument(
            click_type=click.Choice(["press", *_BUTTON_STATE_CHOICES]),
            help="press = send down+up; otherwise send a single state event",
        ),
    ] = "press",
) -> None:
    """Send a HID button event by raw usage page/code (for buttons not in the named list)."""
    async with IndigoHIDService(service_provider) as service:
        await _send_button_press(service, _parse_int_auto(usage_page), _parse_int_auto(usage_code), state)


# ---------------------------------------------------------------------------
# Universal HID Service — com.apple.coredevice.hid.universalhidservice
# ---------------------------------------------------------------------------
universal_hid_service_cli = InjectingTyper(
    name="universal-hid-service",
    help="Register/inspect virtual HID services (com.apple.coredevice.hid.universalhidservice).",
    no_args_is_help=True,
)
cli.add_typer(universal_hid_service_cli)


@universal_hid_service_cli.command("list-connected")
@async_command
async def core_device_universal_hid_service_list(service_provider: RSDServiceProviderDep) -> None:
    """List currently connected virtual HID services."""
    async with UniversalHIDServiceService(service_provider) as service:
        print_json(await service.list_connected_services())


@universal_hid_service_cli.command("send-report")
@async_command
async def core_device_universal_hid_service_send_report(
    service_provider: RSDServiceProviderDep,
    service_id: Annotated[str, typer.Argument(help="Target _ServiceID (from list-connected; decimal or 0xHEX)")],
    report_hex: Annotated[str, typer.Argument(help="Raw HID report bytes as hex (first byte is the report ID)")],
) -> None:
    """Send a raw HID report to a connected HID surface.

    Use ``list-connected`` to discover ServiceIDs. Touch goes via 257
    (mainTouchscreen, true digitizer) or 1281 (touchscreenGesture, trackpad-like
    pointer). Report bytes are surface-specific — capture devicectl traffic with
    misc/remotexpc_sniffer.py to learn the layout.
    """
    async with UniversalHIDServiceService(service_provider) as service:
        await service.send_report(_parse_int_auto(service_id), bytes.fromhex(report_hex))


# ---------------------------------------------------------------------------
# Touch gestures (tap / drag / swipe / session) — composed atop send_report
# ---------------------------------------------------------------------------
# These commands auto-open a media stream via :func:`touch_session` so
# backboardd treats our connection as builtIn+authenticated and dispatches
# the reports to UIKit. See the module-level comment in hid_service.py.
#
# COORDINATE SYSTEM
# -----------------
# X/Y are 16-bit (0..65535) normalised across the device's display, so
# (0, 0) is top-left and (65535, 65535) is bottom-right *regardless of
# the device's pixel resolution*. To convert from a pixel target on a
# specific device, look up the screen size and scale linearly::
#
#     px_w, px_h = (828, 1792)            # e.g. iPhone 11; query with
#                                         # `developer core-device get-display-info`
#                                         # → displays[0].currentMode.size
#     hid_x = round(px_x * 65535 / px_w)
#     hid_y = round(px_y * 65535 / px_h)
#
# Useful anchors regardless of resolution:
#
#     center                (32768, 32768)
#     top-center            (32768,  5000)
#     bottom-center         (32768, 60000)
#     home-indicator area   (32768, 62000+)


async def _do_swipe(
    svc: UniversalHIDServiceService,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    steps: int,
    duration: float,
    *,
    sid: int,
) -> None:
    """Pure pointer-motion stream on the gesture surface — no touch contact."""
    frame_interval = duration / max(steps, 1)
    for i in range(steps + 1):
        t = i / steps if steps else 1.0
        x = round(x1 + (x2 - x1) * t)
        y = round(y1 + (y2 - y1) * t)
        await svc.send_digitizer(x, y, service_id=sid)
        if i < steps:
            await asyncio.sleep(frame_interval)


async def _do_tap(svc: UniversalHIDServiceService, x: int, y: int, *, tsid: int) -> None:
    """One CONTACT + one RELEASE at the same position."""
    await svc.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x, y, service_id=tsid)
    await asyncio.sleep(0.05)
    await svc.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, x, y, service_id=tsid)


async def _do_drag(
    svc: UniversalHIDServiceService,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    steps: int,
    duration: float,
    *,
    tsid: int,
) -> None:
    """Stream of CONTACT reports advancing X/Y, then one closing RELEASE."""
    frame_interval = duration / max(steps, 1)
    for i in range(steps):
        t = i / steps
        x = round(x1 + (x2 - x1) * t)
        y = round(y1 + (y2 - y1) * t)
        await svc.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x, y, service_id=tsid)
        await asyncio.sleep(frame_interval)
    await svc.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x2, y2, service_id=tsid)
    await svc.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, x2, y2, service_id=tsid)


@universal_hid_service_cli.command("tap")
@async_command
async def core_device_universal_hid_service_tap(
    service_provider: RSDServiceProviderDep,
    x: Annotated[int, typer.Argument(help="X (0..65535, 0=left, 65535=right)")],
    y: Annotated[int, typer.Argument(help="Y (0..65535, 0=top, 65535=bottom)")],
    touch_service_id: Annotated[
        str,
        typer.Option("--touch-service-id", help="mainTouchscreen _ServiceID"),
    ] = str(DIGITIZER_SURFACE_MAIN_TOUCHSCREEN),
) -> None:
    """Tap at (X, Y) — one mainTouchscreen CONTACT + RELEASE pair.

    X/Y are 0..65535 normalised across the device's screen — see the
    coordinate-system comment at the top of this section, or
    ``developer core-device get-display-info`` for pixel dimensions.
    Auto-opens a media stream so the touch reaches UIKit.
    """
    async with touch_session(service_provider) as service:
        await _do_tap(service, x, y, tsid=_parse_int_auto(touch_service_id))


@universal_hid_service_cli.command("drag")
@async_command
async def core_device_universal_hid_service_drag(
    service_provider: RSDServiceProviderDep,
    x1: Annotated[int, typer.Argument(help="Start X (0..65535, screen-normalised)")],
    y1: Annotated[int, typer.Argument(help="Start Y (0..65535, screen-normalised)")],
    x2: Annotated[int, typer.Argument(help="End X (0..65535)")],
    y2: Annotated[int, typer.Argument(help="End Y (0..65535)")],
    steps: Annotated[int, typer.Option("--steps")] = 30,
    duration: Annotated[float, typer.Option("--duration", help="Drag time, seconds")] = 0.6,
    touch_service_id: Annotated[
        str,
        typer.Option("--touch-service-id", help="mainTouchscreen _ServiceID"),
    ] = str(DIGITIZER_SURFACE_MAIN_TOUCHSCREEN),
) -> None:
    """Drag from (X1, Y1) to (X2, Y2) — streaming CONTACT reports, then RELEASE.

    X/Y are 0..65535 normalised across the device's screen. Use
    ``developer core-device get-display-info`` to look up the device's
    pixel dimensions if you need to convert from pixel coordinates.
    """
    async with touch_session(service_provider) as service:
        await _do_drag(service, x1, y1, x2, y2, steps, duration, tsid=_parse_int_auto(touch_service_id))


@universal_hid_service_cli.command("swipe")
@async_command
async def core_device_universal_hid_service_swipe(
    service_provider: RSDServiceProviderDep,
    x1: Annotated[int, typer.Argument(help="Start X (Int32)")],
    y1: Annotated[int, typer.Argument(help="Start Y (Int32)")],
    x2: Annotated[int, typer.Argument(help="End X (Int32)")],
    y2: Annotated[int, typer.Argument(help="End Y (Int32)")],
    steps: Annotated[int, typer.Option("--steps", help="Interpolated frames")] = 30,
    duration: Annotated[float, typer.Option("--duration", help="Swipe time, seconds")] = 0.3,
    service_id: Annotated[
        str,
        typer.Option("--service-id", help="Gesture surface _ServiceID; default 1281 = touchscreenGesture"),
    ] = str(DIGITIZER_SURFACE_TOUCHSCREEN_GESTURE),
) -> None:
    """Pure pointer-motion gesture — moves the cursor without a contact event."""
    async with touch_session(service_provider) as service:
        await _do_swipe(service, x1, y1, x2, y2, steps, duration, sid=_parse_int_auto(service_id))


@universal_hid_service_cli.command("session")
@async_command
async def core_device_universal_hid_service_session(
    service_provider: RSDServiceProviderDep,
    script: Annotated[
        Optional[Path],
        typer.Option("--script", help="Read gesture lines from this file (default: stdin)"),
    ] = None,
    gesture_service_id: Annotated[
        str,
        typer.Option("--gesture-service-id", help="Gesture surface _ServiceID (for `move`/`swipe`)"),
    ] = str(DIGITIZER_SURFACE_TOUCHSCREEN_GESTURE),
    touch_service_id: Annotated[
        str,
        typer.Option("--touch-service-id", help="mainTouchscreen _ServiceID (for `tap`/`drag`)"),
    ] = str(DIGITIZER_SURFACE_MAIN_TOUCHSCREEN),
) -> None:
    """Run a sequence of gestures inside ONE auth-gated media stream.

    Avoids stream-churn timeouts when firing many tap/drag calls back-to-back —
    the stream is opened once for the whole batch.

    Recognised commands (whitespace-separated; ``#`` and blank lines ignored)::

        tap   X Y                              # CONTACT + RELEASE
        drag  X1 Y1 X2 Y2 [STEPS [DURATION]]   # continuous contact with motion
        swipe X1 Y1 X2 Y2 [STEPS [DURATION]]   # pure pointer motion (no contact)
        move  X Y                              # one gesture-surface sample
        sleep SECONDS

    Example::

        printf 'tap 30000 40000\\nsleep 0.3\\ndrag 30000 8000 30000 60000\\n' | \\
            pymobiledevice3 developer core-device universal-hid-service session
    """
    gsid = _parse_int_auto(gesture_service_id)
    tsid = _parse_int_auto(touch_service_id)
    lines = (script.read_text() if script else sys.stdin.read()).splitlines()
    async with touch_session(service_provider) as service:
        for lineno, raw in enumerate(lines, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            op, args = parts[0], parts[1:]
            try:
                if op == "tap" and len(args) == 2:
                    await _do_tap(service, int(args[0]), int(args[1]), tsid=tsid)
                elif op == "move" and len(args) == 2:
                    await service.send_digitizer(int(args[0]), int(args[1]), service_id=gsid)
                elif op == "swipe" and 4 <= len(args) <= 6:
                    s = int(args[4]) if len(args) >= 5 else 30
                    d = float(args[5]) if len(args) >= 6 else 0.3
                    await _do_swipe(service, int(args[0]), int(args[1]), int(args[2]), int(args[3]), s, d, sid=gsid)
                elif op == "drag" and 4 <= len(args) <= 6:
                    s = int(args[4]) if len(args) >= 5 else 30
                    d = float(args[5]) if len(args) >= 6 else 0.6
                    await _do_drag(service, int(args[0]), int(args[1]), int(args[2]), int(args[3]), s, d, tsid=tsid)
                elif op == "sleep" and len(args) == 1:
                    await asyncio.sleep(float(args[0]))
                else:
                    raise ValueError(f"unrecognised command or wrong arg count: {line!r}")
            except Exception as e:
                raise typer.BadParameter(f"line {lineno}: {e}") from e


# ---------------------------------------------------------------------------
# Keyboard typing — virtual HID keyboard registered atop universalhidservice
# ---------------------------------------------------------------------------
@universal_hid_service_cli.command("type")
@async_command
async def core_device_universal_hid_service_type(
    service_provider: RSDServiceProviderDep,
    text: Annotated[str, typer.Argument(help="Text to type (printable ASCII)")],
    char_delay: Annotated[
        float,
        typer.Option("--char-delay", help="Seconds between key down and key up"),
    ] = 0.04,
    inter_delay: Annotated[
        float,
        typer.Option("--inter-delay", help="Seconds between characters"),
    ] = 0.02,
) -> None:
    """Type ``TEXT`` on the device via a host-registered virtual keyboard.

    Auto-opens a media stream (the dtuhidd auth gate) and registers a
    virtual keyboard surface, then emits one ``down``/``up`` HID Keyboard
    report pair per character. Capital letters and shifted symbols
    synthesise the matching Left-Shift bit in the bitmap.
    """
    async with touch_session(service_provider) as service:
        kb_service_id = await service.create_keyboard_service()
        for ch in text:
            mapping = ASCII_TO_HID.get(ch)
            if mapping is None:
                raise typer.BadParameter(f"unsupported character: {ch!r}")
            usage, needs_shift = mapping
            usages = (KEY_LEFT_SHIFT, usage) if needs_shift else (usage,)
            await service.send_keyboard(kb_service_id, usages)
            await asyncio.sleep(char_delay)
            await service.send_keyboard(kb_service_id, ())
            await asyncio.sleep(inter_delay)


# ---------------------------------------------------------------------------
# Display service — com.apple.coredevice.displayservice
# ---------------------------------------------------------------------------
display_cli = InjectingTyper(
    name="display",
    help="Query media-stream capabilities (com.apple.coredevice.displayservice).",
    no_args_is_help=True,
)
cli.add_typer(display_cli)


@display_cli.command("get-media-support-info")
@async_command
async def core_device_display_get_media_support_info(service_provider: RSDServiceProviderDep) -> None:
    """Return the device's supported media-stream features and AVC framework version."""
    async with DisplayService(service_provider) as service:
        print_json(await service.get_media_support_info())


@display_cli.command("get-media-stream-server-status")
@async_command
async def core_device_display_get_media_stream_server_status(service_provider: RSDServiceProviderDep) -> None:
    """Return the media-stream server's running state and active sessions."""
    async with DisplayService(service_provider) as service:
        print_json(await service.get_media_stream_server_status())


@display_cli.command("start-video-stream")
@async_command
async def core_device_display_start_video_stream(
    service_provider: RSDServiceProviderDep,
    output: Annotated[Path, typer.Argument(help="Write received RTP packet bytes to this file")],
    display_id: Annotated[int, typer.Option("--display-id")] = 1,
    duration: Annotated[float, typer.Option("--duration", help="Seconds to capture")] = 5.0,
    receiver_port: Annotated[int, typer.Option("--port")] = 0,
) -> None:
    """Capture raw RTP/HEVC packets from a display into a file.

    Each packet is written as ``[4-byte BE length][packet bytes]``. Use
    ``misc/rtp_dump.py`` to depacketize into an Annex-B ``.h265`` bitstream.
    """
    await capture_rtp_to_file(
        service_provider,
        output,
        display_id=display_id,
        duration=duration,
        receiver_port=receiver_port,
    )


@display_cli.command("start-audio-stream")
@async_command
async def core_device_display_start_audio_stream(
    service_provider: RSDServiceProviderDep,
    output: Annotated[Path, typer.Argument(help="Write received RTP packet bytes to this file")],
    duration: Annotated[float, typer.Option("--duration", help="Seconds to capture")] = 10.0,
    receiver_port: Annotated[int, typer.Option("--port")] = 0,
) -> None:
    """Capture raw RTP audio packets from the device's system-audio output.

    Each packet is written as ``[4-byte BE length][packet bytes]``. The
    device advertises ``RxPayloadType=101`` and ``AudioStreamMode=8`` —
    inspect the captured payloads to identify the codec before building
    browser playback.
    """
    await capture_audio_rtp_to_file(
        service_provider,
        output,
        duration=duration,
        receiver_port=receiver_port,
    )


@display_cli.command("serve-web")
@async_command
async def core_device_display_serve_web(
    service_provider: RSDServiceProviderDep,
    display_id: Annotated[int, typer.Option("--display-id")] = 1,
    bind: Annotated[str, typer.Option("--bind", help="Host to bind the webserver on")] = "127.0.0.1",
    http_port: Annotated[int, typer.Option("--http-port", help="Port for the webserver")] = 8080,
    no_audio: Annotated[
        bool,
        typer.Option(
            "--no-audio",
            help="Don't auto-enable sound in the viewer (user can still click Enable Sound).",
        ),
    ] = False,
    ltrp: Annotated[
        bool,
        typer.Option(
            "--ltrp",
            help=(
                "Opt back into LTRP (long-term reference pictures). LTRP is OFF "
                "by default because on-device probing showed the device honours "
                "the protobuf-level switch (`IsltrpEnabled: false` in the "
                "answer) and LTRP-off eliminates the mid-stream tearing pattern "
                "under UDP loss. Apple's captured Xcode offer used LTRP-on; "
                "this flag restores that for regression testing."
            ),
        ),
    ] = False,
    rtcp_fb: Annotated[
        bool,
        typer.Option(
            "--rtcp-fb",
            help=(
                "Negotiate `allowRTCPFB=True` in the mediaBlob. No observable "
                "effect in streamConfig but may influence internal encoder "
                "behaviour."
            ),
        ),
    ] = False,
) -> None:
    """Serve the device's screen via HTTP — view in any modern browser.

    Pipeline (no external executables):

        device → asyncio UDP receive → RFC 7798 RTP/HEVC depacketize
               → HTTP chunked stream → browser WebCodecs decoder → canvas

    Open ``http://<bind>:<http_port>/`` in Safari or Chrome (macOS Chrome needs
    HEVC support — recent versions enable it by default if the OS supports it).
    """
    server = ScreenStreamServer(
        service_provider,
        bind=bind,
        http_port=http_port,
        display_id=display_id,
        audio_default_on=not no_audio,
        allow_rtcp_fb=rtcp_fb,
        ltrp_enabled=ltrp,
    )
    await server.serve()


@display_cli.command("serve-vnc")
@async_command
async def core_device_display_serve_vnc(
    service_provider: RSDServiceProviderDep,
    display_id: Annotated[int, typer.Option("--display-id")] = 1,
    bind: Annotated[str, typer.Option("--bind", help="Host to bind the VNC listener on")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="TCP port for the VNC listener")] = 5901,
    audio: Annotated[
        bool,
        typer.Option(
            "--audio",
            help="Play device audio out the host Mac's speakers (off by default).",
        ),
    ] = False,
    decoder: Annotated[
        str,
        typer.Option(
            "--decoder",
            help=(
                "HEVC decoder: 'auto' (VideoToolbox on macOS, libav elsewhere), "
                "'vt' (force VideoToolbox -- macOS only), or 'av' (force libav / PyAV). "
                "Forcing 'av' on macOS comes with audio choppiness from GIL contention."
            ),
        ),
    ] = "auto",
    ltrp: Annotated[
        bool,
        typer.Option(
            "--ltrp",
            help="Opt back into LTRP (off by default; see serve-web for context).",
        ),
    ] = False,
    rtcp_fb: Annotated[
        bool,
        typer.Option(
            "--rtcp-fb",
            help="Negotiate allowRTCPFB=True in the mediaBlob (experimental).",
        ),
    ] = False,
) -> None:
    """Serve the device's screen as a VNC (RFB 3.8) server.

    Connect from any VNC client. macOS Finder: ``Cmd+K`` -> enter
    ``vnc://<bind>:<port>`` (default ``vnc://127.0.0.1:5901``; port
    5900 is owned by macOS's own Screen Sharing daemon). No browser
    involved -- the OS's native screen-sharing renders the framebuffer
    directly.

    Pipeline: device HEVC -> VideoToolbox (macOS) or libav (cross-platform)
    decode (BGRA output) -> RFB Raw framebuffer updates. No JPEG
    round-trip; the bytes that came out of the decoder go straight onto
    the wire. Mouse clicks in the screen-sharing window translate to HID
    touch events on the device.

    Audio: pass ``--audio`` to decode the device's AAC-ELD audio
    stream and play it through the host Mac's speakers (RFB has no
    audio of its own, so the playback is host-local).
    """
    server = VncStreamServer(
        service_provider,
        bind=bind,
        port=port,
        display_id=display_id,
        audio=audio,
        decoder=decoder,
        allow_rtcp_fb=rtcp_fb,
        ltrp_enabled=ltrp,
    )
    await server.serve()


# ---------------------------------------------------------------------------
# Location service — com.apple.coredevice.locationservice
# ---------------------------------------------------------------------------
location_cli = InjectingTyper(
    name="location",
    help="Simulate the device's location (com.apple.coredevice.locationservice).",
    no_args_is_help=True,
)
cli.add_typer(location_cli)


@location_cli.command("available-scenarios")
@async_command
async def core_device_location_available_scenarios(service_provider: RSDServiceProviderDep) -> None:
    """List the device's built-in simulation scenarios."""
    async with LocationService(service_provider) as service:
        print_json(await service.available_location_scenarios())
