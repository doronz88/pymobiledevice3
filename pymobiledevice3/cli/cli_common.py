import asyncio
import datetime
import json
import logging
import os
import sys
import uuid
from functools import wraps
from textwrap import dedent
from typing import Annotated, Any, Callable, Optional

import click
import coloredlogs
import hexdump
import inquirer3
import typer
from click import UsageError
from inquirer3.themes import GreenPassion
from pygments import formatters, highlight, lexers
from typer_injector import Depends

from pymobiledevice3.exceptions import AccessDeniedError, DeviceNotFoundError, NoDeviceConnectedError
from pymobiledevice3.lockdown import TcpLockdownClient, create_using_usbmux, get_mobdev2_lockdowns
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, async_get_tunneld_devices
from pymobiledevice3.usbmux import select_devices_by_connection_type

UDID_ENV_VAR = "PYMOBILEDEVICE3_UDID"
TUNNEL_ENV_VAR = "PYMOBILEDEVICE3_TUNNEL"
USBMUX_ENV_VAR = "PYMOBILEDEVICE3_USBMUX"
USBMUX_OPTION_HELP = (
    "Address of the usbmuxd daemon (unix socket path or HOST:PORT). Defaults to the platform usbmuxd if omitted."
)
DEVICE_OPTIONS_PANEL_TITLE = "Device Options"
OSUTILS = get_os_utils()

# Global options
COLORED_OUTPUT: bool = True


def default_json_encoder(obj):
    if isinstance(obj, bytes):
        return f"<{obj.hex()}>"
    if isinstance(obj, datetime.datetime):
        return str(obj)
    if isinstance(obj, uuid.UUID):
        return str(obj)
    raise TypeError()


def print_json(buf, colored: Optional[bool] = None, default=default_json_encoder) -> str:
    if colored is None:
        colored = user_requested_colored_output()
    formatted_json = json.dumps(buf, sort_keys=True, indent=4, default=default)
    if colored and os.isatty(sys.stdout.fileno()):
        colorful_json = highlight(
            formatted_json, lexers.JsonLexer(), formatters.Terminal256Formatter(style="stata-dark")
        )
        print(colorful_json)
        return colorful_json
    else:
        print(formatted_json)
        return formatted_json


def print_hex(data, colored=True) -> None:
    hex_dump = hexdump.hexdump(data, result="return")
    if colored:
        print(highlight(hex_dump, lexers.HexdumpLexer(), formatters.Terminal256Formatter(style="native")))
    else:
        print(hex_dump, end="\n\n")


def set_verbosity(level: int) -> None:
    coloredlogs.set_level(logging.INFO - (level * 10))


def set_color_flag(value: bool) -> None:
    global COLORED_OUTPUT
    COLORED_OUTPUT = value


def isatty() -> bool:
    return os.isatty(sys.stdout.fileno())


def user_requested_colored_output() -> bool:
    return COLORED_OUTPUT and isatty()


def get_last_used_terminal_formatting(buf: str) -> str:
    return "\x1b" + buf.rsplit("\x1b", 1)[1].split("m")[0] + "m"


def sudo_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not OSUTILS.is_admin:
            raise AccessDeniedError()
        else:
            func(*args, **kwargs)

    return wrapper


def prompt_selection(choices: list[Any], message: str, idx: bool = False) -> Any:
    question = [inquirer3.List("selection", message=message, choices=choices, carousel=True)]
    try:
        result = inquirer3.prompt(question, theme=GreenPassion(), raise_keyboard_interrupt=True)
    except KeyboardInterrupt:
        raise click.ClickException("No selection was made") from None
    return result["selection"] if not idx else choices.index(result["selection"])


def prompt_device_list(device_list: list):
    return prompt_selection(device_list, "Choose device")


def is_invoked_for_completion() -> bool:
    """Returns True if the command is invoked for autocompletion."""
    return any(env.startswith("_") and env.endswith("_COMPLETE") for env in os.environ)


async def get_mobdev2_devices(udid: Optional[str] = None) -> list[TcpLockdownClient]:
    return [lockdown async for _, lockdown in get_mobdev2_lockdowns(udid=udid)]


async def _tunneld(udid: Optional[str] = None) -> Optional[RemoteServiceDiscoveryService]:
    if udid is None:
        return

    udid = udid.strip()
    port = TUNNELD_DEFAULT_ADDRESS[1]
    if ":" in udid:
        udid, port = udid.split(":")

    rsds = await async_get_tunneld_devices((TUNNELD_DEFAULT_ADDRESS[0], int(port)))
    if len(rsds) == 0:
        raise NoDeviceConnectedError()

    if udid != "":
        service_provider = next((rsd for rsd in rsds if rsd.udid == udid), None)
        if service_provider is None:
            raise DeviceNotFoundError(udid) from None
    else:
        service_provider = rsds[0] if len(rsds) == 1 else prompt_device_list(rsds)

    for rsd in rsds:
        if rsd == service_provider:
            continue
        await rsd.close()

    return service_provider


def make_rsd_dependency(*, allow_none: bool) -> Callable[..., Optional[RemoteServiceDiscoveryService]]:
    def rsd_dependency(
        rsd: Annotated[
            Optional[tuple[str, int]],
            typer.Option(
                metavar="HOST PORT",
                help=dedent("""\
                    Hostname and port of a RemoteServiceDiscovery (from any of the `start-tunnel` subcommands).
                    Mutually exclusive with --tunnel.
                """),
                rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
            ),
        ] = None,
        tunnel: Annotated[
            Optional[str],
            typer.Option(
                envvar=TUNNEL_ENV_VAR,
                help=dedent("""\
                    Use a device discovered via tunneld. Provide a UDID (optionally with :PORT) or leave empty to pick
                    interactively. Mutually exclusive with --rsd.
                """),
                rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
            ),
        ] = None,
    ) -> Optional[RemoteServiceDiscoveryService]:
        if is_invoked_for_completion():
            # prevent lockdown connection establishment when in autocomplete mode
            return None

        if rsd is not None and tunnel is not None:
            raise UsageError("Illegal usage: --rsd is mutually exclusive with --tunnel.")

        if rsd is not None:
            rsd_service = RemoteServiceDiscoveryService(rsd)
            asyncio.run(rsd_service.connect(), debug=True)
            return rsd_service

        if tunnel is not None or not allow_none:
            return asyncio.run(_tunneld(tunnel or ""), debug=True)

    return rsd_dependency


def any_service_provider_dependency(
    rsd_service_provider: Annotated[
        Optional[RemoteServiceDiscoveryService],
        Depends(make_rsd_dependency(allow_none=True)),
    ] = None,
    mobdev2: Annotated[
        bool,
        typer.Option(
            help="Discover devices over bonjour/mobdev2 instead of usbmux.",
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = False,
    usbmux: Annotated[
        Optional[str],
        typer.Option(
            envvar=USBMUX_ENV_VAR,
            help=USBMUX_OPTION_HELP,
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = None,
    udid: Annotated[
        Optional[str],
        typer.Option(
            envvar=UDID_ENV_VAR,
            help="Target device UDID (defaults to the first USB device).",
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = None,
) -> LockdownServiceProvider:
    if is_invoked_for_completion():
        # prevent lockdown connection establishment when in autocomplete mode
        return  # type: ignore[return-value]

    if rsd_service_provider is not None:
        return rsd_service_provider

    if mobdev2:
        devices = asyncio.run(get_mobdev2_devices(udid=udid))
        if not devices:
            raise NoDeviceConnectedError()

        if len(devices) == 1:
            return devices[0]

        return prompt_device_list(devices)

    if udid is not None:
        return create_using_usbmux(serial=udid, usbmux_address=usbmux)

    devices = select_devices_by_connection_type(connection_type="USB", usbmux_address=usbmux)
    if len(devices) <= 1:
        return create_using_usbmux(usbmux_address=usbmux)

    return prompt_device_list([create_using_usbmux(serial=device.serial, usbmux_address=usbmux) for device in devices])


def no_autopair_service_provider_dependency(
    rsd_service_provider: Annotated[
        Optional[RemoteServiceDiscoveryService],
        Depends(make_rsd_dependency(allow_none=True)),
    ] = None,
    udid: Annotated[
        Optional[str],
        typer.Option(
            envvar=UDID_ENV_VAR,
            help="Target device UDID (defaults to the first USB device).",
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = None,
) -> LockdownServiceProvider:
    if is_invoked_for_completion():
        # prevent lockdown connection establishment when in autocomplete mode
        return  # type: ignore[return-value]

    if rsd_service_provider is not None:
        return rsd_service_provider

    return create_using_usbmux(serial=udid, autopair=False)


RSDServiceProviderDep = Annotated[
    RemoteServiceDiscoveryService,
    Depends(make_rsd_dependency(allow_none=False)),
]


ServiceProviderDep = Annotated[
    LockdownServiceProvider,
    Depends(any_service_provider_dependency),
]


NoAutoPairServiceProviderDep = Annotated[
    LockdownServiceProvider,
    Depends(no_autopair_service_provider_dependency),
]


class BasedIntParamType(click.ParamType):
    name = "based int"

    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail(f"{value!r} is not a valid int.", param, ctx)


BASED_INT = BasedIntParamType()
