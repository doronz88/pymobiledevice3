import asyncio
import datetime
import json
import logging
import os
import platform
import sys
import uuid
from collections.abc import Coroutine
from contextlib import suppress
from enum import Enum
from functools import wraps
from textwrap import dedent
from typing import Annotated, Any, Callable, Optional, TypeVar, cast

import coloredlogs
import hexdump
import questionary
import typer
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
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, TunneldAddress, get_tunneld_devices
from pymobiledevice3.utils import ask_prompt, get_asyncio_loop

UDID_ENV_VAR = "PYMOBILEDEVICE3_UDID"
TUNNEL_ENV_VAR = "PYMOBILEDEVICE3_TUNNEL"
USERSPACE_ENV_VAR = "PYMOBILEDEVICE3_USERSPACE"
# macOS only: piggyback Apple's remoted tunnel via remotepairingd (no root, no Xcode).
NATIVE_ENV_VAR = "PYMOBILEDEVICE3_NATIVE"
# Overrides which transport the automatic fallback prefers — both the required-RSD default and the
# `__main__` retry. One of "native" (built-in default on macOS), "userspace" (built-in default
# elsewhere), or "tunneld".
DEFAULT_FALLBACK_ENV_VAR = "PYMOBILEDEVICE3_DEFAULT_FALLBACK"
_VALID_DEFAULT_FALLBACKS = ("native", "userspace", "tunneld")
# Internal one-shot marker set by the `__main__` retry: make a lockdown-or-RSD command establish the
# default RSD chain (like a required-RSD command) instead of returning None. Not user-facing.
FORCE_TUNNEL_ENV_VAR = "PYMOBILEDEVICE3_FORCE_TUNNEL"
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


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


OutputFormatOption = Annotated[
    OutputFormat,
    typer.Option(
        "--format",
        help="Output format. 'json' emits one JSON object per line (NDJSON) on stdout.",
        case_sensitive=False,
    ),
]


def default_json_encoder(obj: Any) -> Any:
    """Encode the non-JSON-native types found in device responses.

    ``bytes`` become a single-key ``{"$hex": "..."}`` object so consumers can detect
    and decode binary values unambiguously (``bytes.fromhex``); datetimes are ISO 8601.
    This is the machine-readable output contract — see docs/guides/machine-readable-output.md.
    """
    if isinstance(obj, bytes):
        return {"$hex": obj.hex()}
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    raise TypeError()


def print_json_line(obj: Any) -> None:
    """Emit one compact NDJSON record on stdout — the streaming counterpart of :func:`print_json`."""
    print(json.dumps(obj, default=default_json_encoder, ensure_ascii=False), flush=True)


def print_json(buf: Any, colored: Optional[bool] = None, default: Callable[[Any], Any] = default_json_encoder) -> str:
    if colored is None:
        colored = user_requested_colored_output()
    formatted_json = json.dumps(buf, sort_keys=True, indent=4, default=default)
    if colored and os.isatty(sys.stdout.fileno()):
        colorful_json = cast(
            str,
            highlight(
                formatted_json,
                cast(Any, lexers).JsonLexer(),
                cast(Any, formatters).Terminal256Formatter(style="stata-dark"),
            ),
        )
        print(colorful_json)
        return colorful_json
    else:
        print(formatted_json)
        return formatted_json


def print_hex(data: bytes, colored: bool = True) -> None:
    hex_dump = cast(Any, hexdump).hexdump(data, result="return")
    assert isinstance(hex_dump, str)  # result='return' always yields a str
    if colored:
        print(
            highlight(
                hex_dump, cast(Any, lexers).HexdumpLexer(), cast(Any, formatters).Terminal256Formatter(style="native")
            )
        )
    else:
        print(hex_dump, end="\n\n")


def set_verbosity(level: int) -> None:
    cast(Any, coloredlogs).set_level(logging.INFO - (level * 10))
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


def sudo_required(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        if not OSUTILS.is_admin:
            raise AccessDeniedError()
        else:
            func(*args, **kwargs)

    return wrapper


def prompt_selection(choices: list[Any], message: str, idx: bool = False, hint: Optional[str] = None) -> Any:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        # Scripts, CI, and agents cannot answer an interactive prompt — fail fast with the
        # candidates instead of garbling the output stream (or hanging) with escape sequences.
        typer.secho(f"{message}: interactive selection requires a terminal. Candidates:", err=True, fg="red")
        for choice in choices:
            typer.echo(f"  {choice}", err=True)
        if hint is not None:
            typer.echo(hint, err=True)
        raise typer.Exit(code=1)
    question = questionary.select(
        message, choices=[questionary.Choice(title=str(choice), value=i) for i, choice in enumerate(choices)]
    )
    try:
        selection = cast(int, ask_prompt(question))
    except KeyboardInterrupt:
        typer.echo(typer.style("No selection was made", fg="red"))
        raise typer.Exit(code=1) from None
    return selection if idx else choices[selection]


def prompt_device_list(device_list: list[Any]) -> Any:
    return prompt_selection(
        device_list,
        "Choose device",
        hint=f"Pass --udid or set {UDID_ENV_VAR} to choose a device non-interactively.",
    )


def is_invoked_for_completion() -> bool:
    """Returns True if the command is invoked for autocompletion."""
    return any(env.startswith("_") and env.endswith("_COMPLETE") for env in os.environ)


# UDID of the device the running command actually resolved to (explicit --udid, auto-pick, or
# interactive prompt). The global --reconnect machinery in __main__ reads it to wait for and
# re-target that same device — the selection would otherwise be lost when it came from a prompt.
_resolved_udid: Optional[str] = None


def resolved_udid() -> Optional[str]:
    """The UDID the current command's device dependency resolved to, if any."""
    return _resolved_udid


def _record_resolved(provider: LockdownServiceProvider) -> LockdownServiceProvider:
    """Remember which device a service-provider dependency picked (see ``resolved_udid``)."""
    global _resolved_udid
    if provider.udid is not None:
        _resolved_udid = provider.udid
    return provider


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


def require_webdav_mount_tool(mount: bool) -> None:
    """Fail early if ``--mount`` was requested but no WebDAV mount tool is available on this host."""
    from pymobiledevice3.services.webdav_mount import webdav_mount_supported

    if mount and not webdav_mount_supported():
        typer.secho(
            "--mount is unavailable: no supported WebDAV mount tool found "
            "(mount_webdav on macOS, net on Windows, gio on Linux)",
            fg="red",
            err=True,
        )
        raise typer.Exit(2)


async def run_afc_webdav_cli(
    afc: Any, *, path: str, mount: bool, host: str, bind_port: int, readonly: bool, label: str
) -> None:
    """Serve an open AFC service over WebDAV from a CLI command, and block until interrupted.

    The WebDAV dependencies require Python >= 3.10; on older interpreters a clear error is emitted.
    """
    require_webdav_mount_tool(mount)
    try:
        from pymobiledevice3.services.webdav import run_afc_webdav
    except ImportError as e:
        typer.secho("WebDAV support requires Python >= 3.10", fg="red", err=True)
        raise typer.Exit(1) from e
    await run_afc_webdav(afc, path=path, mount=mount, host=host, port=bind_port, readonly=readonly, label=label)


# Shared options for the `webdav` subcommands across the AFC-backed CLI groups.
WebDavPathArgument = Annotated[str, typer.Argument(help="AFC path to serve as the volume root (default: /)")]
WebDavMountOption = Annotated[
    bool, typer.Option("--mount", help="mount the served path locally and reveal it in your file manager")
]
WebDavHostOption = Annotated[str, typer.Option("--host", help="local interface to bind")]
WebDavBindPortOption = Annotated[int, typer.Option("--bind-port", help="local TCP port (0 picks a free port)")]
WebDavReadonlyOption = Annotated[bool, typer.Option("--readonly", help="expose the path read-only")]


async def get_mobdev2_devices(udid: Optional[str] = None) -> list[TcpLockdownClient]:
    return [lockdown async for _, lockdown in get_mobdev2_lockdowns(udid=udid)]


def _parse_tunnel_spec(tunnel: str) -> tuple[str, TunneldAddress]:
    """Split a --tunnel value (``UDID``, ``UDID:PORT`` or ``UDID:UDS_PATH``) into
    (udid, tunneld address). A numeric suffix is a TCP port on the default host;
    anything else after the ``:`` is a unix domain socket path."""
    udid, sep, address = tunnel.strip().partition(":")
    if not sep:
        return udid, TUNNELD_DEFAULT_ADDRESS
    if address.isdigit():
        return udid, (TUNNELD_DEFAULT_ADDRESS[0], int(address))
    return udid, address


async def _tunneld(udid: Optional[str] = None) -> Optional[RemoteServiceDiscoveryService]:
    if udid is None:
        return

    udid, tunneld_address = _parse_tunnel_spec(udid)
    rsds = await get_tunneld_devices(tunneld_address)
    if len(rsds) == 0:
        raise NoDeviceConnectedError()

    if udid != "":
        service_provider = next((rsd for rsd in rsds if rsd.udid == udid), None)
        if service_provider is None:
            where = (
                tunneld_address if isinstance(tunneld_address, str) else f"{tunneld_address[0]}:{tunneld_address[1]}"
            )
            raise DeviceNotFoundError(
                udid, f"Device not found: tunneld ({where}) serves no tunnel for udid {udid}"
            ) from None
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


def default_transport_preference() -> str:
    """Preferred transport for the automatic fallback (required-RSD default and the ``__main__`` retry).

    Returns one of ``"native"``, ``"userspace"`` or ``"tunneld"``. The built-in default is
    ``"native"`` on macOS (faster, no root, coexists with Xcode) and ``"userspace"`` elsewhere
    (``remoted`` only exists on macOS). Set via ``PYMOBILEDEVICE3_DEFAULT_FALLBACK`` to override; an
    unrecognized value is ignored (falls back to the built-in default).
    """
    value = os.getenv(DEFAULT_FALLBACK_ENV_VAR)
    if value:
        normalized = value.strip().lower()
        if normalized in _VALID_DEFAULT_FALLBACKS:
            return normalized
        logging.getLogger(__name__).warning(
            "ignoring invalid %s=%r (expected one of: %s)",
            DEFAULT_FALLBACK_ENV_VAR,
            value,
            ", ".join(_VALID_DEFAULT_FALLBACKS),
        )
    return "native" if platform.system() == "Darwin" else "userspace"


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
      establishment (RemotePairing fallback disabled), which is caught here and routed to the native
      tunnel (macOS) or tunneld (with the resolved UDID). ``PYMOBILEDEVICE3_DEFAULT_FALLBACK``
      selects the preferred transport (see :func:`default_transport_preference`).
    """

    def rsd_dependency(
        ctx: typer.Context,
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
                    Use a device discovered via tunneld. Provide a UDID (optionally with :PORT or :UDS_PATH for a
                    tunneld bound to a unix domain socket) or leave empty to pick interactively. Mutually exclusive
                    with --rsd.
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
        native: Annotated[
            bool,
            typer.Option(
                "--native",
                envvar=NATIVE_ENV_VAR,
                help=dedent("""\
                    macOS only: reach the iOS 17+ tunnel by piggybacking Apple's own `remoted` tunnel via the
                    `remotepairingd` service. NO root, no entitlement, no Xcode, and `remoted` is left running (so
                    it coexists with Xcode/devicectl). Rides Apple's kernel-routable tunnel, so throughput matches
                    the kernel tunnel. Mutually exclusive with --rsd/--tunnel/--userspace.
                """),
                rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
            ),
        ] = False,
    ) -> Optional[RemoteServiceDiscoveryService]:
        if is_invoked_for_completion():
            # prevent lockdown connection establishment when in autocomplete mode
            return None

        if rsd is not None and tunnel is not None:
            ctx.fail("Illegal usage: --rsd is mutually exclusive with --tunnel.")
        explicit_tunnel_sources = sum([rsd is not None, tunnel is not None, userspace, native])
        if explicit_tunnel_sources > 1:
            ctx.fail("Illegal usage: --rsd, --tunnel, --userspace and --native are mutually exclusive.")

        if native:
            serial = _resolve_target_serial(_cli_udid())
            from pymobiledevice3.remote import native_tunnel

            return cli_loop.run_until_complete(native_tunnel.establish_native_rsd(serial=serial))

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

        # Default for a required RSD. The preferred transport is configurable via
        # PYMOBILEDEVICE3_DEFAULT_FALLBACK (default: the no-root in-process userspace tunnel). A
        # pre-17.4 device (no CoreDeviceProxy — iOS 17.0-17.3) can't use the userspace path; on macOS
        # it is served no-root by the native tunnel (piggybacking remoted), elsewhere by tunneld.
        # Establish the default RSD chain when the command requires an RSD (allow_none=False) or the
        # `__main__` retry marked this run to force one (FORCE_TUNNEL_ENV_VAR) after a lockdown-only
        # attempt hit InvalidServiceError/RSDRequiredError.
        if not allow_none or os.getenv(FORCE_TUNNEL_ENV_VAR):
            # Resolve (and, with multiple devices, prompt for) the target so every attempt acts on
            # the same user-chosen device.
            serial = _resolve_target_serial(_cli_udid())
            preference = default_transport_preference()

            if preference == "tunneld":
                return cli_loop.run_until_complete(_tunneld(serial or ""))

            tried_native = False
            if preference == "native" and platform.system() == "Darwin":
                from pymobiledevice3.remote import native_tunnel

                tried_native = True
                try:
                    return cli_loop.run_until_complete(native_tunnel.establish_native_rsd(serial=serial))
                except Exception as e:
                    # Any native-path failure (unavailable, or an unexpected ctypes/libxpc error)
                    # degrades to the userspace path rather than aborting the command.
                    logging.getLogger(__name__).debug("native tunnel unavailable, falling back: %r", e)

            # Imported lazily: the PyTCP stack import is expensive and must stay off the hot path of
            # commands that never establish a userspace tunnel.
            from pymobiledevice3.remote import userspace_tunnel

            try:
                return cli_loop.run_until_complete(
                    userspace_tunnel.establish_userspace_rsd(serial=serial, remotepairing_fallback=False)
                )
            except UserspaceTunnelUnavailableError:
                # The userspace path can't serve this device (iOS 17.0-17.3 has no CoreDeviceProxy).
                # On macOS, piggyback remoted's own tunnel (no root) unless we already tried it above;
                # elsewhere remoted does not exist, so go straight to the privileged tunneld.
                if platform.system() == "Darwin" and not tried_native:
                    from pymobiledevice3.remote import native_tunnel

                    try:
                        return cli_loop.run_until_complete(native_tunnel.establish_native_rsd(serial=serial))
                    except Exception as e:
                        # Native path not viable either (or an unexpected error); fall through to tunneld.
                        logging.getLogger(__name__).debug("native tunnel unavailable, falling back: %r", e)
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
        return _record_resolved(rsd_service_provider)

    if mobdev2:
        devices = cli_loop.run_until_complete(get_mobdev2_devices(udid=udid))
        if not devices:
            raise NoDeviceConnectedError()

        if len(devices) == 1:
            return _record_resolved(devices[0])

        return _record_resolved(prompt_device_list(devices))

    if udid is not None:
        return _record_resolved(cli_loop.run_until_complete(create_using_usbmux(serial=udid, usbmux_address=usbmux)))

    devices = cli_loop.run_until_complete(
        usbmuxd.select_devices_by_connection_type(connection_type="USB", usbmux_address=usbmux)
    )
    if len(devices) <= 1:
        return _record_resolved(cli_loop.run_until_complete(create_using_usbmux(usbmux_address=usbmux)))

    lockdownds = [
        cli_loop.run_until_complete(create_using_usbmux(serial=device.serial, usbmux_address=usbmux))
        for device in devices
    ]
    return _record_resolved(prompt_device_list(lockdownds))


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
        return _record_resolved(rsd_service_provider)

    return _record_resolved(cli_loop.run_until_complete(create_using_usbmux(serial=udid, autopair=False)))


def _narrow_to_lockdown_client(ctx: typer.Context, service_provider: LockdownServiceProvider) -> LockdownClient:
    if is_invoked_for_completion():
        # the underlying dependency returned no real provider in autocomplete mode
        return service_provider  # type: ignore[return-value]
    if not isinstance(service_provider, LockdownClient):
        ctx.fail("This command requires a direct lockdown connection (remove --rsd/--tunnel).")
    return service_provider


def lockdown_client_dependency(
    ctx: typer.Context,
    service_provider: Annotated[LockdownServiceProvider, Depends(any_service_provider_dependency)],
) -> LockdownClient:
    """Variant of ``any_service_provider_dependency`` for commands only implemented over a direct
    lockdownd connection (pairing, recovery, ...); rejects RSD-backed providers with a usage error."""
    return _narrow_to_lockdown_client(ctx, service_provider)


def no_autopair_lockdown_client_dependency(
    ctx: typer.Context,
    service_provider: Annotated[LockdownServiceProvider, Depends(no_autopair_service_provider_dependency)],
) -> LockdownClient:
    """Like ``lockdown_client_dependency``, but without triggering autopair on connect."""
    return _narrow_to_lockdown_client(ctx, service_provider)


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
