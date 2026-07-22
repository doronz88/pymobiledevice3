import asyncio
import datetime
import json
import logging
import os
import sys
import uuid
from collections.abc import Coroutine
from contextlib import suppress
from functools import wraps
from textwrap import dedent
from typing import Annotated, Any, Callable, Optional, TypeVar

import click
import coloredlogs
import hexdump
import inquirer3
import typer
from click import UsageError
from inquirer3.themes import GreenPassion
from packaging.version import Version
from pygments import formatters, highlight, lexers
from typer_injector import Depends
from typing_extensions import ParamSpec

from pymobiledevice3 import usbmux as usbmuxd
from pymobiledevice3.exceptions import (
    AccessDeniedError,
    DeviceNotFoundError,
    NoDeviceConnectedError,
    UserspaceTunnelUnavailableError,
)
from pymobiledevice3.lockdown import LockdownClient, TcpLockdownClient, create_using_usbmux, get_mobdev2_lockdowns
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, get_tunneld_devices
from pymobiledevice3.utils import get_asyncio_loop

UDID_ENV_VAR = "PYMOBILEDEVICE3_UDID"
TUNNEL_ENV_VAR = "PYMOBILEDEVICE3_TUNNEL"
USERSPACE_ENV_VAR = "PYMOBILEDEVICE3_USERSPACE"
# When set (non-empty), the automatic tunnel fallback uses tunneld instead of the
# no-root userspace tunnel — restoring the pre-userspace-default behavior.
PREFER_TUNNELD_ENV_VAR = "PYMOBILEDEVICE3_PREFER_TUNNELD"
USBMUX_ENV_VAR = "PYMOBILEDEVICE3_USBMUX"
USBMUXD_SOCKET_ADDRESS_ENV_VAR = "USBMUXD_SOCKET_ADDRESS"
USBMUX_ENV_VARS = [USBMUX_ENV_VAR, USBMUXD_SOCKET_ADDRESS_ENV_VAR]
USBMUX_OPTION_HELP = (
    "Address of the usbmuxd daemon (unix socket path or HOST:PORT). Defaults to the platform usbmuxd if omitted."
)
DEVICE_OPTIONS_PANEL_TITLE = "Device Options"
OSUTILS = get_os_utils()

# Global options
COLORED_OUTPUT: bool = True
P = ParamSpec("P")
R = TypeVar("R")


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
    assert isinstance(hex_dump, str)  # result='return' always yields a str
    if colored:
        print(highlight(hex_dump, lexers.HexdumpLexer(), formatters.Terminal256Formatter(style="native")))
    else:
        print(hex_dump, end="\n\n")


def set_verbosity(level: int) -> None:
    coloredlogs.set_level(logging.INFO - (level * 10))
    # DTX message traffic is very chatty -- require -vv to see it
    logging.getLogger("pymobiledevice3.dtx").setLevel(logging.DEBUG if level >= 2 else logging.INFO)


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


cli_loop = get_asyncio_loop()


def async_command(func: Callable[P, Coroutine[Any, Any, R]]) -> Callable[P, R]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        task = cli_loop.create_task(func(*args, **kwargs))
        try:
            return cli_loop.run_until_complete(task)
        except KeyboardInterrupt:
            # Ensure graceful coroutine finalization on Ctrl-C; otherwise Python
            # may report "coroutine ignored GeneratorExit" during GC shutdown.
            task.cancel()
            with suppress(asyncio.CancelledError, asyncio.TimeoutError, Exception):
                cli_loop.run_until_complete(asyncio.wait_for(task, timeout=0.25))
            raise typer.Exit(code=130) from None

    return wrapper


async def get_mobdev2_devices(udid: Optional[str] = None) -> list[TcpLockdownClient]:
    return [lockdown async for _, lockdown in get_mobdev2_lockdowns(udid=udid)]


async def _tunneld(udid: Optional[str] = None) -> Optional[RemoteServiceDiscoveryService]:
    if udid is None:
        return

    udid = udid.strip()
    port = TUNNELD_DEFAULT_ADDRESS[1]
    if ":" in udid:
        udid, port = udid.split(":")

    rsds = await get_tunneld_devices((TUNNELD_DEFAULT_ADDRESS[0], int(port)))
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


def _cli_udid() -> Optional[str]:
    """The target device UDID for the in-process userspace tunnel. make_rsd_dependency can't
    declare a --udid option (it would collide with the device dependencies that already define
    it), and the Click context isn't reliably available during dependency resolution across
    typer versions — so read --udid from argv, falling back to the env var the option uses.
    (Mirrors the existing sys.argv inspection in __main__.)"""
    for i, arg in enumerate(sys.argv):
        if arg == "--udid" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if arg.startswith("--udid="):
            return arg.split("=", 1)[1]
    return os.getenv(UDID_ENV_VAR)


def _resolve_target_serial(serial: Optional[str]) -> Optional[str]:
    """Resolve the device the default (required) RSD tunnel should target.

    When the user passed an explicit UDID (--udid / env) use it. Otherwise, if more than one USB
    device is attached, prompt for one — mirroring the interactive selection the composing
    service-provider dependencies do — so the default tunnel does not silently pick the first
    device. Returns the chosen serial, or ``None`` when a single/zero device leaves the choice to
    the usbmux layer.

    usbmux exposes neither the device name nor the iOS version, so the chooser connects to each
    device via lockdown to show ID/VERSION/TYPE, then closes those connections — only the chosen
    serial is kept. These connections use ``autopair=False``: this is a display-only listing, so
    browsing must not pair every attached device. Only the chosen device is paired later, when the
    tunnel is established (``establish_userspace_rsd`` / ``tunneld`` use ``autopair=True``); the cost
    is that the ``PAIRED`` field reads ``False`` for all here (it is simply unchecked).
    """
    if serial is not None:
        return serial
    devices = cli_loop.run_until_complete(usbmuxd.select_devices_by_connection_type(connection_type="USB"))
    if len(devices) <= 1:
        return None
    lockdownds = [
        cli_loop.run_until_complete(create_using_usbmux(serial=device.serial, autopair=False)) for device in devices
    ]
    try:
        return prompt_device_list(lockdownds).identifier
    finally:
        for lockdown in lockdownds:
            cli_loop.run_until_complete(lockdown.close())


def requires_kernel_tunnel(product_version: str) -> bool:
    """True when a device needs the privileged kernel tunnel (``tunneld``) rather than the
    no-root in-process userspace tunnel.

    iOS 17.0-17.3 always qualifies: those versions predate the CoreDeviceProxy lockdown service
    (17.4+), so the userspace tunnel can only reach them over the RemotePairing/bonjour path — which
    is Wi-Fi-only and, on macOS, races ``remoted`` (the no-root path cannot ``stop_remoted()``
    without root). Rather than make the default depend on that fragile path, 17.0-17.3 routes to
    ``tunneld`` on every platform. iOS 17.4+ uses CoreDeviceProxy over USB and works root-free, so
    it stays on the userspace default. (``--userspace`` can still force the RemotePairing path on
    17.0-17.3 where it applies.)

    Used by the ``__main__`` exception-retry path, which already carries the product version from the
    raised exception. The required-RSD default path (:func:`make_rsd_dependency`) instead reuses the
    tunnel's own lockdown connection and routes via ``UserspaceTunnelUnavailableError``, so it needs
    no separate version query.
    """
    return Version("17.0") <= Version(product_version) < Version("17.4")


def make_rsd_dependency(*, allow_none: bool) -> Callable[..., Optional[RemoteServiceDiscoveryService]]:
    """Build the Typer dependency that resolves an RSD from --rsd/--tunnel/--userspace.

    ``allow_none`` decides what happens when the user passes none of those options:

    * ``allow_none=True`` — return ``None`` so the composing dependency
      (:func:`any_service_provider_dependency`, :func:`no_autopair_service_provider_dependency`)
      can fall back to a plain usbmux lockdown. Used by commands that work over either a
      lockdown or an RSD tunnel; on iOS 17+ the lockdown attempt raises InvalidServiceError /
      RSDRequiredError and ``__main__`` re-runs the command forcing a tunnel.
    * ``allow_none=False`` — the command requires an RSD (no lockdown equivalent, e.g.
      ``core-device`` / ``remote rsd-info``), so a default tunnel is established here rather than
      returning ``None``: the no-root userspace tunnel by default; a pre-17.4 device (iOS 17.0-17.3)
      raises :class:`~pymobiledevice3.exceptions.UserspaceTunnelUnavailableError` during
      establishment (RemotePairing fallback disabled), which is caught here and routed to tunneld
      (with the resolved UDID). Setting ``PYMOBILEDEVICE3_PREFER_TUNNELD`` skips the userspace
      attempt and goes straight to tunneld.
    """

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
        userspace: Annotated[
            bool,
            typer.Option(
                "--userspace",
                envvar=USERSPACE_ENV_VAR,
                help=dedent("""\
                    Establish the iOS 17+ tunnel in-process with a pure-Python userspace network stack, so NO
                    root/admin is required. Downloads (device->host, e.g. fetch-symbols) run at roughly the
                    kernel tunnel's throughput; host->device transfers (DDI mounts, file pushes) are slower, as
                    their send segments are kept small for reliable delivery through the pure-Python path. Use
                    when you cannot run a privileged tunnel.
                """),
                rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
            ),
        ] = False,
    ) -> Optional[RemoteServiceDiscoveryService]:
        if is_invoked_for_completion():
            # prevent lockdown connection establishment when in autocomplete mode
            return None

        if rsd is not None and tunnel is not None:
            raise UsageError("Illegal usage: --rsd is mutually exclusive with --tunnel.")
        if userspace and (rsd is not None or tunnel is not None):
            raise UsageError("Illegal usage: --userspace is mutually exclusive with --rsd/--tunnel.")

        # Explicit tunnel sources take precedence.
        if rsd is not None:
            rsd_service = RemoteServiceDiscoveryService(rsd)
            cli_loop.run_until_complete(rsd_service.connect())
            return rsd_service
        if tunnel is not None:
            return cli_loop.run_until_complete(_tunneld(tunnel))

        # Opt-in userspace tunnel (--userspace / PYMOBILEDEVICE3_USERSPACE): establish the
        # tunnel in-process with the pure-Python PyTCP stack — no root. Downloads run near the
        # kernel tunnel's rate; host->device transfers are slower (see the flag's help). PyTCP
        # (pmd-pytcp) is a regular dependency on Python 3.9+, so any failure here is a real
        # establishment error and is surfaced rather than masked by a tunneld fallback.
        if userspace:
            # Resolve (and, with multiple devices, prompt for) the target, like the other device
            # dependencies — otherwise --userspace would silently pick the first device.
            serial = _resolve_target_serial(_cli_udid())
            # Imported lazily: userspace_tunnel pulls in the pure-Python PyTCP network stack
            # (pmd-pytcp), whose import is expensive — keep it off the hot path of every CLI
            # command that never establishes a userspace tunnel.
            from pymobiledevice3.remote import userspace_tunnel

            return cli_loop.run_until_complete(userspace_tunnel.establish_userspace_rsd(serial=serial))

        # Default for a required RSD: prefer the no-root in-process userspace tunnel. A pre-17.4
        # device (no CoreDeviceProxy — i.e. iOS 17.0-17.3, reachable no-root only over the fragile
        # RemotePairing path) is served by tunneld instead: establishment is asked NOT to attempt
        # RemotePairing (remotepairing_fallback=False), so it raises UserspaceTunnelUnavailableError,
        # which we catch and route to tunneld. This reuses the single lockdown connection
        # establishment already opens — no separate version probe.
        if not allow_none:
            # Resolve (and, with multiple devices, prompt for) the target so both the userspace
            # attempt and the tunneld fallback act on the same user-chosen device.
            serial = _resolve_target_serial(_cli_udid())
            # PYMOBILEDEVICE3_PREFER_TUNNELD opts out of the userspace default entirely,
            # restoring the pre-userspace-default behavior (straight to tunneld).
            if os.getenv(PREFER_TUNNELD_ENV_VAR):
                return cli_loop.run_until_complete(_tunneld(serial or ""))
            # Imported lazily: see the --userspace branch above — the PyTCP stack import is
            # expensive and must stay off the hot path of commands that never need it.
            from pymobiledevice3.remote import userspace_tunnel

            try:
                return cli_loop.run_until_complete(
                    userspace_tunnel.establish_userspace_rsd(serial=serial, remotepairing_fallback=False)
                )
            except UserspaceTunnelUnavailableError:
                # Propagate the resolved UDID so tunneld targets the same device (empty => auto/prompt).
                return cli_loop.run_until_complete(_tunneld(serial or ""))

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
            envvar=USBMUX_ENV_VARS,
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
        devices = cli_loop.run_until_complete(get_mobdev2_devices(udid=udid))
        if not devices:
            raise NoDeviceConnectedError()

        if len(devices) == 1:
            return devices[0]

        return prompt_device_list(devices)

    if udid is not None:
        return cli_loop.run_until_complete(create_using_usbmux(serial=udid, usbmux_address=usbmux))

    devices = cli_loop.run_until_complete(
        usbmuxd.select_devices_by_connection_type(connection_type="USB", usbmux_address=usbmux)
    )
    if len(devices) <= 1:
        return cli_loop.run_until_complete(create_using_usbmux(usbmux_address=usbmux))

    lockdownds = [
        cli_loop.run_until_complete(create_using_usbmux(serial=device.serial, usbmux_address=usbmux))
        for device in devices
    ]
    return prompt_device_list(lockdownds)


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

    return cli_loop.run_until_complete(create_using_usbmux(serial=udid, autopair=False))


def _narrow_to_lockdown_client(service_provider: LockdownServiceProvider) -> LockdownClient:
    if is_invoked_for_completion():
        # the underlying dependency returned no real provider in autocomplete mode
        return service_provider  # type: ignore[return-value]
    if not isinstance(service_provider, LockdownClient):
        raise UsageError("This command requires a direct lockdown connection (remove --rsd/--tunnel).")
    return service_provider


def lockdown_client_dependency(
    service_provider: Annotated[LockdownServiceProvider, Depends(any_service_provider_dependency)],
) -> LockdownClient:
    """Variant of ``any_service_provider_dependency`` for commands only implemented over a direct
    lockdownd connection (pairing, recovery, ...); rejects RSD-backed providers with a usage error."""
    return _narrow_to_lockdown_client(service_provider)


def no_autopair_lockdown_client_dependency(
    service_provider: Annotated[LockdownServiceProvider, Depends(no_autopair_service_provider_dependency)],
) -> LockdownClient:
    """Like ``lockdown_client_dependency``, but without triggering autopair on connect."""
    return _narrow_to_lockdown_client(service_provider)


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

LockdownClientDep = Annotated[
    LockdownClient,
    Depends(lockdown_client_dependency),
]

NoAutoPairLockdownClientDep = Annotated[
    LockdownClient,
    Depends(no_autopair_lockdown_client_dependency),
]


def based_int(value: str) -> int:
    """``typer.Option(parser=...)`` hook accepting ints in any python-literal base (10, 0x, 0o, 0b)."""
    return int(value, 0)
