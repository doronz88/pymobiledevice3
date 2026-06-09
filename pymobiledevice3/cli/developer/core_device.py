import asyncio
import logging
import posixpath
import time
from pathlib import Path
from typing import IO, Annotated, Optional

import click
import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import RSDServiceProviderDep, async_command, print_json
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService
from pymobiledevice3.remote.core_device.diagnostics_service import DiagnosticsServiceService
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.file_service import APPLE_DOMAIN_DICT, FileServiceService
from pymobiledevice3.remote.core_device.hid_service import (
    HID_BUTTON_STATE_CANCELED,
    HID_BUTTON_STATE_DOWN,
    HID_BUTTON_STATE_UP,
    IndigoHIDService,
    UniversalHIDServiceService,
)
from pymobiledevice3.remote.core_device.screen_capture_service import ScreenCaptureService
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer, capture_rtp_to_file
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

# Named iOS hardware buttons → (usage_page, usage_code).
# Most physical iOS buttons live on the Consumer page (0x0C).
_NAMED_BUTTONS: dict[str, tuple[int, int]] = {
    "home": (0x0C, 0x40),  # Consumer / Menu
    "power": (0x0C, 0x30),  # Consumer / Power
    "lock": (0x0C, 0x30),  # alias for power
    "sleep": (0x0C, 0x32),  # Consumer / Sleep
    "volume-up": (0x0C, 0xE9),  # Consumer / Volume Increment
    "volume-down": (0x0C, 0xEA),  # Consumer / Volume Decrement
    "mute": (0x0C, 0xE2),  # Consumer / Mute
    "siri": (0x0C, 0xCF),  # Consumer / Voice Command
}


async def _send_button_press(service: IndigoHIDService, usage_page: int, usage_code: int, state: str) -> None:
    """Dispatch a single button state (down/up/canceled), or down+up for ``press``."""
    if state == "press":
        await service.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
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
    usage_page, usage_code = _NAMED_BUTTONS[name]
    async with IndigoHIDService(service_provider) as service:
        await _send_button_press(service, usage_page, usage_code, state)


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


@display_cli.command("serve-video-stream")
@async_command
async def core_device_display_serve_video_stream(
    service_provider: RSDServiceProviderDep,
    display_id: Annotated[int, typer.Option("--display-id")] = 1,
    bind: Annotated[str, typer.Option("--bind", help="Host to bind the webserver on")] = "127.0.0.1",
    http_port: Annotated[int, typer.Option("--http-port", help="Port for the webserver")] = 8080,
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
    )
    await server.serve()
