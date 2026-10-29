import asyncio
import contextlib
import hashlib
import logging
import os
import plistlib
import re
import sys
import tempfile
import threading
from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import IO, Annotated, Any, Callable, Optional, TypeVar, Union, cast

import questionary
import requests
import typer
from ipsw_parser.ipsw import IPSW
from pygments import formatters, highlight, lexers
from rich.console import Console
from rich.panel import Panel
from typer_injector import Depends, InjectingTyper

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import (
    RSDServiceProviderDep,
    async_command,
    cli_loop,
    is_invoked_for_completion,
    print_json,
    prompt_selection,
)
from pymobiledevice3.exceptions import (
    ConnectionFailedError,
    ConnectionFailedToUsbmuxdError,
    IncorrectModeError,
    MissingValueError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import SERVICE_PORT as LOCKDOWN_PORT
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.restore import dfu_guide
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.deviceinterfaced import DeviceInterfacedControl
from pymobiledevice3.restore.preflight import UPDATER_FIRMWARE_PREFIXES, collect_device_side_preflight
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.usb import USB_BACKEND_ENV_VAR, power_delivery
from pymobiledevice3.utils import ask_prompt, file_download, start_ipython_shell

logger = logging.getLogger(__name__)


SHELL_USAGE = """
# use `irecv` variable to access Restore mode API
# for example:
print(irecv.getenv('build-version'))
"""
IPSWME_API = "https://api.ipsw.me/v4/device/"
IPSW_DIR_ENV_VAR = "PYMOBILEDEVICE3_IPSW_DIR"
APPLEDB_API = "https://api.appledb.dev/ios/"
APPLEDB_BETAS_TO_LIST = 8

T = TypeVar("T")


cli = InjectingTyper(
    name="restore",
    help="Restore/erase IPSWs, fetch blobs, and manage devices in Recovery/DFU.",
    no_args_is_help=True,
)


@cli.callback()
def callback(
    libusb: Annotated[
        bool,
        typer.Option(
            "--libusb",
            help=f"macOS: reach Recovery/DFU devices through libusb instead of IOKit (same as "
            f"{USB_BACKEND_ENV_VAR}=libusb). libusb cannot see A16-or-later devices in DFU mode.",
        ),
    ] = False,
) -> None:
    if libusb:
        os.environ[USB_BACKEND_ENV_VAR] = "libusb"


# How long the device prompt waits on each device for its description.
DEVICE_DESCRIPTION_TIMEOUT = 5.0
RESTORED_TYPE = "com.apple.mobile.restored"


async def _query_device_description(device: usbmux.MuxDevice) -> Optional[str]:
    service = await ServiceConnection.create_using_usbmux(device.serial, LOCKDOWN_PORT, connection_type="USB")
    try:
        query_type = await service.send_recv_plist({"Label": "pymobiledevice3", "Request": "QueryType"})
        if query_type.get("Type") == RESTORED_TYPE:
            return None
        values: list[Any] = []
        # lockdownd answers these before a session is started, so an unpaired device shows no Trust prompt.
        for key in ("DeviceName", "ProductType", "ProductVersion"):
            reply = await service.send_recv_plist({"Label": "pymobiledevice3", "Request": "GetValue", "Key": key})
            values.append(reply.get("Value"))
    finally:
        await service.close()
    name, product_type, product_version = values
    return f"{name} ({product_type}, iOS {product_version}) {device.serial}"


async def _describe_device(device: usbmux.MuxDevice) -> Optional[str]:
    """The device prompt's line for ``device``, or None while it is in restore mode (busy restoring).

    Asking lockdownd's port is the same QueryType Apple's own restore tools send to every device;
    on a device in restore mode, restored answers it.
    """
    try:
        return await asyncio.wait_for(_query_device_description(device), DEVICE_DESCRIPTION_TIMEOUT)
    except (OSError, asyncio.TimeoutError, PyMobileDevice3Exception):
        return device.serial


async def _device_dependency_async(
    ecid: Annotated[
        Optional[str],
        typer.Option(
            help="Target device ECID; defaults to the first connected USB device or waits for Recovery/DFU.",
        ),
    ] = None,
) -> Optional[Device]:
    if is_invoked_for_completion():
        # prevent lockdown connection establishment when in autocomplete mode
        return None

    # ECID comes in as a CLI string (decimal or 0x-hex) but is matched against the integer
    # UniqueChipID; parse it once so the comparisons below actually work.
    ecid_value = int(ecid, 0) if ecid is not None else None

    try:
        logger.debug("searching among connected devices via lockdownd")
        devices = [dev for dev in await usbmux.list_devices() if dev.connection_type == "USB"]
        if ecid_value is not None:
            # Leave devices whose UDID names another ECID alone: one may be in the middle of its own
            # restore, where even a probing connection reaches its restored.
            devices = [dev for dev in devices if dev.ecid is None or dev.ecid == ecid_value]
        elif len(devices) > 1:
            descriptions = await asyncio.gather(*(_describe_device(dev) for dev in devices))
            # A device in restore mode is in the middle of a restore: leave it out.
            candidates = [(dev, desc) for dev, desc in zip(devices, descriptions) if desc is not None]
            if len(candidates) > 1:
                selected = cast(
                    int,
                    prompt_selection(
                        [desc for _, desc in candidates],
                        "Choose device",
                        idx=True,
                        hint="Pass --ecid to choose a device non-interactively.",
                    ),
                )
                candidates = [candidates[selected]]
            devices = [dev for dev, _ in candidates]
        for device in devices:
            try:
                lockdown = await create_using_usbmux(serial=device.serial, connection_type="USB")
            except (ConnectionFailedError, IncorrectModeError):
                continue
            if (ecid_value is None) or (lockdown.ecid == ecid_value):
                logger.debug("found device")
                found = Device(lockdown=lockdown)
                # Over lockdown this is a GetValue round-trip; resolve it now so the "connected device"
                # log line can report it instead of "unknown".
                await found.get_is_image4_supported()
                return found
            else:
                continue
    except ConnectionFailedToUsbmuxdError:
        pass

    logger.debug("waiting for device to be available in Recovery mode")
    return Device(irecv=IRecv(ecid=ecid_value))


def device_dependency(
    ecid: Annotated[
        Optional[str],
        typer.Option(
            help="Target device ECID; defaults to the first connected USB device or waits for Recovery/DFU.",
        ),
    ] = None,
) -> Optional[Device]:
    return cli_loop.run_until_complete(_device_dependency_async(ecid))


DeviceDep = Annotated[
    Device,
    Depends(device_dependency),
]


@contextlib.asynccontextmanager
async def download_ipsw_ctx(
    url: str, ipsw_dir: Optional[Path], sha256: Optional[str] = None
) -> AsyncGenerator[IPSW, None]:
    """
    Download ``url`` into ``ipsw_dir`` (a temporary directory if None) and open it.

    A complete ``.ipsw`` already in ``ipsw_dir`` is trusted and reused as-is. A new download lands in
    ``<name>.part``, resumes from there if interrupted, and is only renamed into place once it matches
    its SHA-256: the one Apple's CDN publishes for the file, else ``sha256`` (from the build listing).
    """
    with contextlib.ExitStack() as stack:
        if ipsw_dir is None:
            ipsw_dir = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        ipsw_dir.mkdir(parents=True, exist_ok=True)
        ipsw_path = ipsw_dir / url.split("/")[-1]
        if ipsw_path.is_file():
            logger.info(f"Using {ipsw_path}")
        else:
            part_path = ipsw_path.with_name(ipsw_path.name + ".part")
            expected = await asyncio.to_thread(_published_sha256, url) or sha256
            await _run_stoppable(lambda stop: file_download(url, part_path, resume=True, stop=stop))
            if expected is None:
                logger.warning(f"No published SHA-256 for {ipsw_path.name}; using it unverified")
            elif await _run_stoppable(lambda stop: _file_sha256(part_path, stop)) != expected.lower():
                part_path.unlink()
                typer.secho(f"{ipsw_path.name} does not match its published SHA-256; discarded it.", err=True, fg="red")
                raise typer.Exit(code=1)
            part_path.replace(ipsw_path)
        async with ipsw_ctx(ipsw_path) as ipsw:
            yield ipsw


def _published_sha256(url: str) -> Optional[str]:
    """Return the SHA-256 Apple's CDN publishes for ``url`` in its object metadata, if any."""
    resp = requests.head(url, timeout=30, allow_redirects=True)
    # Some servers refuse HEAD; the download itself reports real errors
    return resp.headers.get("x-amz-meta-digest-sha256") if resp.ok else None


async def _run_stoppable(func: Callable[[threading.Event], T]) -> T:
    """
    Run blocking ``func`` on a worker thread, keeping the loop free for Ctrl-C.

    On cancellation, signal ``func`` through its stop event and wait for the thread to wind down.
    """
    stop = threading.Event()
    task = asyncio.create_task(asyncio.to_thread(func, stop))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        stop.set()
        await asyncio.gather(task, return_exceptions=True)
        raise


def _file_sha256(path: Path, stop: threading.Event) -> Optional[str]:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if stop.is_set():
                return None
            digest.update(chunk)
    return digest.hexdigest()


@contextlib.asynccontextmanager
async def ipsw_ctx(path: Union[str, Path]) -> AsyncGenerator[IPSW, None]:
    yield IPSW.create_from_path(str(path))


def ipsw_ctx_dependency(
    device: DeviceDep,
    ipsw: Annotated[
        Optional[str],
        typer.Option(
            "--ipsw",
            "-i",
            help="Path or URL to an IPSW. If omitted, choose a signed build interactively.",
        ),
    ] = None,
    ipsw_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--ipsw-dir",
            envvar=IPSW_DIR_ENV_VAR,
            help="Directory of downloaded IPSWs: reuse a build already there, and download new ones into it.",
        ),
    ] = None,
    beta: Annotated[
        bool,
        typer.Option(
            "--beta",
            help="Choose among the newest beta builds (listed by AppleDB) instead of signed releases (ipsw.me).",
        ),
    ] = False,
) -> contextlib.AbstractAsyncContextManager[IPSW]:
    if ipsw_dir is not None:
        # The env var is often set quoted, leaving "~" for us to expand
        ipsw_dir = ipsw_dir.expanduser()
    if ipsw and not ipsw.startswith(("http://", "https://")):
        return ipsw_ctx(ipsw)

    if ipsw is not None:
        if beta:
            raise typer.BadParameter("--beta only applies when choosing a build interactively", param_hint="--beta")
        return download_ipsw_ctx(ipsw, ipsw_dir)
    product_type = cli_loop.run_until_complete(device.get_product_type())
    firmware = query_appledb_betas(product_type, ipsw_dir) if beta else query_ipswme(product_type, ipsw_dir)
    return download_ipsw_ctx(firmware["url"], ipsw_dir, firmware.get("sha256sum"))


IPSWCtxDep = Annotated[
    contextlib.AbstractAsyncContextManager[IPSW],
    Depends(ipsw_ctx_dependency),
]


def tss_dependency(
    tss: Annotated[
        Optional[Path],
        typer.Option(help="Path to SHSH blob plist to use for signing requests."),
    ] = None,
) -> None:
    if tss is None:
        return
    with tss.open("rb") as tss_file:
        return plistlib.load(tss_file)


TSSDep = Annotated[
    Optional[dict[str, Any]],
    Depends(tss_dependency),
]


BehaviorOption = Annotated[
    Behavior,
    typer.Option(help="Restore behavior to use when selecting the BuildIdentity."),
]


def query_ipswme(identifier: str, ipsw_dir: Optional[Path] = None) -> dict[str, Any]:
    """Let the user pick a signed build from ipsw.me, marking the ones already in ``ipsw_dir``."""
    try:
        resp = requests.get(IPSWME_API + identifier, headers={"Accept": "application/json"}, timeout=30)
    except requests.RequestException as e:
        typer.secho(f"Could not reach ipsw.me to list signed builds: {e}", err=True, fg="red")
        raise typer.Exit(code=1) from e
    signed: list[dict[str, Any]] = [entry for entry in resp.json()["firmwares"] if entry["signed"]]
    return _choose_firmware(signed, ipsw_dir)


def query_appledb_betas(product_type: str, ipsw_dir: Optional[Path] = None) -> dict[str, Any]:
    """
    Let the user pick one of the newest beta builds AppleDB lists an IPSW of for ``product_type``.

    Costs one ~44 KB index plus one ~100 KB entry per candidate build, fetched in parallel. AppleDB's
    signing status is only a hint (shown as "unsigned"); TSS decides during the restore.
    """
    os_str = "iPadOS" if product_type.startswith("iPad") else "iOS"
    # Betas are <major><train><4 digits><letter>, e.g. 24B5110a; longer numbers are not betas
    beta_key = re.compile(rf"{os_str};(\d+)([A-Z])(\d{{4}})([a-z])")
    try:
        index: list[str] = _appledb_get("index.json")
        matches = [m for m in map(beta_key.fullmatch, index) if m is not None]
        matches.sort(key=lambda m: (int(m[1]), m[2], int(m[3]), m[4]), reverse=True)
        keys = [m[0] for m in matches[:APPLEDB_BETAS_TO_LIST]]
        with ThreadPoolExecutor(max_workers=len(keys) or 1) as pool:
            builds: list[dict[str, Any]] = list(pool.map(_appledb_get, [f"{key}.json" for key in keys]))
    except requests.RequestException as e:
        typer.secho(f"Could not reach AppleDB to list beta builds: {e}", err=True, fg="red")
        raise typer.Exit(code=1) from e

    firmwares: list[dict[str, Any]] = []
    for build in builds:
        sources: list[dict[str, Any]] = build.get("sources", [])
        source = next((s for s in sources if s["type"] == "ipsw" and product_type in s["deviceMap"]), None)
        if source is None:
            continue
        all_links: list[dict[str, Any]] = source.get("links", [])
        links = [link for link in all_links if link.get("active", True)]
        if not links:
            continue
        signed = build.get("signed")
        firmwares.append({
            "version": build["version"],
            "buildid": build["build"],
            "url": max(links, key=lambda link: bool(link.get("preferred")))["url"],
            "sha256sum": source.get("hashes", {}).get("sha2-256"),
            "signed": signed is True or (isinstance(signed, list) and product_type in signed),
        })
    if not firmwares:
        typer.secho(
            f"AppleDB lists no IPSW for {product_type} in the {len(keys)} newest {os_str} betas; "
            "the device may not support the current beta release.",
            err=True,
            fg="red",
        )
        raise typer.Exit(code=1)
    return _choose_firmware(firmwares, ipsw_dir)


def _appledb_get(path: str) -> Any:
    resp = requests.get(APPLEDB_API + path, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _choose_firmware(firmwares: list[dict[str, Any]], ipsw_dir: Optional[Path]) -> dict[str, Any]:
    """Prompt for one of ``firmwares``, marking the ones already in ``ipsw_dir`` and those known unsigned."""
    display_list: list[str] = []
    for entry in firmwares:
        local = ipsw_dir is not None and (ipsw_dir / entry["url"].split("/")[-1]).is_file()
        marks = (" (local)" if local else "") + ("" if entry.get("signed", True) else " (unsigned)")
        display_list.append(f"{entry['version']}: {entry['buildid']}{marks}")
    idx: int = prompt_selection(display_list, "Choose version", idx=True)
    return firmwares[idx]


async def restore_update_task(
    device: Device,
    ipsw: IPSW,
    tss: Optional[dict[str, Any]],
    erase: bool,
    ignore_fdr: bool,
    enable_tss_batch: bool = False,
) -> None:
    behavior = Behavior.Update
    if erase:
        behavior = Behavior.Erase

    await Restore(
        ipsw,
        device,
        tss=tss,
        behavior=behavior,
        ignore_fdr=ignore_fdr,
        enable_tss_batch=enable_tss_batch,
    ).update()


async def _choose_dfu_sequence(product_type: str, assisted: bool) -> dfu_guide.ButtonSequence:
    sequence = dfu_guide.iphone_sequence(product_type, assisted=assisted)
    if sequence is not None:
        return sequence
    if product_type.startswith("iPad"):
        has_home_button = ask_prompt(questionary.confirm("Does your iPad have a Home button?", default=False))
        return dfu_guide.HOME_BUTTON if has_home_button else dfu_guide.IPAD_WITHOUT_HOME_BUTTON
    raise typer.BadParameter(f"The DFU guide does not know the buttons of {product_type}.")


async def guide_into_dfu(device: Device, manual: bool = False) -> dfu_guide.UsbState:
    """
    Walk the user through putting ``device`` into DFU mode, retrying until it works or they give up.

    A booted device is restarted from here, so only the buttons that pick DFU mode are left to the user, unless
    ``manual`` asks for the whole button sequence.

    :returns: the DFU flavor the device came up in (``DFU`` or ``KIS``).
    """
    if device.irecv is not None and device.irecv.mode in (Mode.DFU_MODE, Mode.WTF_MODE):
        return dfu_guide.UsbState.DFU
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        typer.secho("Entering DFU mode is guided interactively and needs a terminal.", err=True, fg="red")
        raise typer.Exit(code=1)

    product_type = await device.get_product_type()
    lockdown = device.lockdown
    sequence = await _choose_dfu_sequence(product_type, assisted=lockdown is not None and not manual)
    udid = lockdown.udid if lockdown is not None else None

    async def restart() -> None:
        assert lockdown is not None
        # the device goes down once the service connection closes
        async with DiagnosticsService(lockdown) as diagnostics:
            await diagnostics.restart()
        await lockdown.close()

    if lockdown is not None and not any(step.restart_after for step in sequence.steps):
        # the device is about to drop off USB
        await lockdown.close()

    console = Console()
    console.print(
        Panel.fit(
            f"Let's put your [b]{product_type}[/b] into [b]DFU mode[/b].\n\n"
            f"Keep it plugged into this computer. You'll use {sequence.buttons}.\n"
            "Each step shows a countdown and what the device is doing, and moves on as soon as it reacts.\n"
            "Nothing on the device is erased by this.",
            title="DFU mode",
            border_style="cyan",
        )
    )
    while True:
        ask_prompt(
            questionary.press_any_key_to_continue(
                f"Rest your fingers on {sequence.buttons}, but don't press them yet. "
                "When ready, press any key on your KEYBOARD to start..."
            )
        )
        for count in (3, 2, 1):
            console.print(f"[bold]{count}...[/bold]")
            await asyncio.sleep(1)
        result = await dfu_guide.run_sequence(console, sequence, udid, restart)
        if result.in_dfu:
            console.print(
                f"\n[bold green]Done! The device is in {result.state.value}.[/bold green] You can let go of the buttons."
            )
            return result.state
        console.print(f"\n[bold red]Not in DFU mode yet[/bold red] (the device is {result.state.value}).")
        if result.hint is not None:
            console.print(result.hint)
        if not ask_prompt(questionary.confirm("Try again?", default=True)):
            raise typer.Exit(code=1)


async def _reconnect_in_dfu(ecid: int) -> Device:
    return Device(irecv=IRecv(ecid=ecid, is_recovery=False))


ManualDfuOption = Annotated[
    bool,
    typer.Option(
        "--manual",
        help="Do the whole DFU button sequence yourself, instead of having a booted device restarted from here.",
    ),
]


@cli.command("enter-dfu")
@async_command
async def restore_enter_dfu(device: DeviceDep, manual: ManualDfuOption = False) -> None:
    """Guide you, step by step, through the buttons that put the device into DFU mode."""
    await guide_into_dfu(device, manual=manual)


@cli.command("shell")
def restore_shell(device: DeviceDep) -> None:
    """create an IPython shell for interacting with iBoot"""
    start_ipython_shell(
        header=highlight(
            SHELL_USAGE, cast(Any, lexers).PythonLexer(), cast(Any, formatters).Terminal256Formatter(style="native")
        ),
        user_ns={
            "irecv": device.irecv,
        },
    )


@cli.command("enter")
@async_command
async def restore_enter(device: DeviceDep) -> None:
    """enter Recovery mode"""
    if await device.get_is_lockdown():
        assert device.lockdown is not None  # get_is_lockdown() guarantees it
        await device.lockdown.enter_recovery()


@cli.command("exit")
def restore_exit() -> None:
    """exit Recovery mode"""
    irecv = IRecv()
    irecv.set_autoboot(True)
    irecv.reboot()


def _choose_vdm_port(ecid: Optional[str]) -> power_delivery.ApplePort:
    ports = power_delivery.list_apple_ports()
    if ecid is not None:
        ecid_value = int(ecid, 0)
        ports = [port for port in ports if port.ecid == ecid_value]
    if not ports:
        typer.secho(
            "No Apple device is connected directly to a Thunderbolt/USB4 port of this Mac"
            + ("" if ecid is None else f" with ECID {ecid}")
            + ". Connect it to one of those ports with no hub in between (USB-C power messages only reach the "
            "device at the other end of the cable), or restart it without --vdm.",
            err=True,
            fg="red",
        )
        raise typer.Exit(code=1)
    if len(ports) == 1:
        return ports[0]
    selected = cast(
        int,
        prompt_selection(
            [port.describe() for port in ports],
            "Choose device",
            idx=True,
            hint="Pass --ecid to choose a device non-interactively.",
        ),
    )
    return ports[selected]


def _restart_over_power_delivery(ecid: Optional[str]) -> None:
    if sys.platform != "darwin":
        typer.secho("--vdm is only supported on macOS.", err=True, fg="red")
        raise typer.Exit(code=1)
    if os.geteuid() != 0:
        typer.secho("--vdm needs root: rerun the command with sudo.", err=True, fg="red")
        raise typer.Exit(code=1)
    try:
        port = _choose_vdm_port(ecid)
        logger.info(f"Restarting the {port.describe()}")
        power_delivery.reboot(port.port)
    except power_delivery.PowerDeliveryError as e:
        typer.secho(str(e), err=True, fg="red")
        raise typer.Exit(code=1) from e


@cli.command("restart")
@async_command
async def restore_restart(
    ecid: Annotated[
        Optional[str],
        typer.Option(
            help="Target device ECID; defaults to the first connected USB device or waits for Recovery/DFU.",
        ),
    ] = None,
    vdm: Annotated[
        bool,
        typer.Option(
            "--vdm",
            help="macOS, needs root: restart through the USB-C port controller with Apple's USB Power Delivery "
            "reboot message. Needs no pairing and works in Recovery mode; the device must be directly on a "
            "Thunderbolt/USB4 port.",
        ),
    ] = False,
) -> None:
    """restarts device"""
    if vdm:
        _restart_over_power_delivery(ecid)
        return
    device = await _device_dependency_async(ecid)
    assert device is not None  # only None while completing the command line
    if await device.get_is_lockdown():
        assert device.lockdown is not None  # get_is_lockdown() guarantees it
        async with DiagnosticsService(device.lockdown) as diagnostics:
            await diagnostics.restart()
    else:
        assert device.irecv is not None  # a Device is constructed with either lockdown or irecv
        device.irecv.reboot()


async def restore_tss_task(
    device: Device,
    ipsw_ctx: contextlib.AbstractAsyncContextManager[IPSW],
    out: Optional[IO[bytes]],
    behavior: Behavior = Behavior.Update,
) -> None:
    async with ipsw_ctx as ipsw:
        tss = await Recovery(ipsw, device, behavior=behavior).fetch_tss_record()
    if out:
        plistlib.dump(tss, out)
    print_json(tss)


@cli.command("tss")
@async_command
async def restore_tss(
    device: DeviceDep,
    ipsw_ctx: IPSWCtxDep,
    out: Optional[Path] = None,
    behavior: BehaviorOption = Behavior.Update,
) -> None:
    """query SHSH blobs"""
    with out.open("wb") if out else contextlib.nullcontext() as out_file:
        await restore_tss_task(device, ipsw_ctx, out_file, behavior=behavior)


@cli.command("preflight")
@async_command
async def restore_preflight(device: DeviceDep) -> None:
    """
    Show the preflight data lockdown reports before a restore: PreflightInfo (each peripheral
    updater's identity fields and current nonce), FirmwarePreflightInfo (baseband) and ApParameters
    (AP and SEP nonces). Requires normal mode.
    """
    if device.lockdown is None:
        raise typer.BadParameter("preflight data is only available from a device in normal mode")
    result: dict[str, Any] = {}
    for key in ("PreflightInfo", "FirmwarePreflightInfo", "ApParameters"):
        try:
            result[key] = await device.lockdown.get_value("", key)
        except MissingValueError:
            result[key] = None
    print_json(result)


@cli.command("preflight-requests")
@async_command
async def restore_preflight_requests(
    device: DeviceDep,
    ipsw_ctx: IPSWCtxDep,
    rsd: RSDServiceProviderDep,
    updater: Annotated[
        Optional[list[str]],
        typer.Option(
            help=f"Updater to query (repeatable); default: all of {', '.join(UPDATER_FIRMWARE_PREFIXES)} except Baseband.",
        ),
    ] = None,
) -> None:
    """
    Ask the device to build the TSS request of each peripheral updater for the given IPSW, the way
    restored does during a restore (restoreserviced getdevicesidepreflightinfo; needs a tunnel and
    uploads each updater's firmware to the device). Prints the requests, their ticket and manifest
    tags, and the updaters that failed.
    """
    async with ipsw_ctx as ipsw:
        build_identity = Recovery(ipsw, device).build_identity
        print_json(await collect_device_side_preflight(rsd, ipsw, build_identity, updater))


@cli.command("ramdisk")
@async_command
async def restore_ramdisk(device: DeviceDep, ipsw_ctx: IPSWCtxDep) -> None:
    """
    Boot only the update ramdisk without performing a restore (IPSW path or URL accepted).
    """
    async with ipsw_ctx as ipsw:
        await Recovery(ipsw, device).boot_ramdisk()


@cli.command("update")
@async_command
async def restore_update(
    device: DeviceDep,
    ipsw_ctx: IPSWCtxDep,
    tss: TSSDep,
    erase: Annotated[
        bool,
        typer.Option(help="Erase and restore (factory reset) instead of updating in place."),
    ] = False,
    ignore_fdr: Annotated[
        bool,
        typer.Option(help="Connect to the FDR service only (debug mode; no traffic proxying)."),
    ] = False,
    tss_batch: Annotated[
        bool,
        typer.Option(
            "--tss-batch",
            help=(
                "Opt-in: request the prefetchable peripheral tickets (SE/SE2, Rose, Savage, T200, "
                "Centauri, eUICC, Baseband) together with the AP ticket, in the same TSS request, and "
                "serve them during the restore whenever the device asks with the identical request "
                "(iOS 18+). Adds no request; chips whose nonce changed are signed live as usual."
            ),
        ),
    ] = False,
    exclusive_usb: Annotated[
        bool,
        typer.Option(
            "--exclusive-usb",
            help=(
                "Experimental, macOS only: keep deviceinterfaced from claiming the USB device during the "
                "restore (it can win the race while the device re-enumerates). Boots the "
                "daemon out, or keeps killing it where that is refused, and restores it afterwards; the launchctl "
                "calls run through sudo, which may prompt for your password."
            ),
        ),
    ] = False,
    dfu: Annotated[
        bool,
        typer.Option(
            "--dfu",
            help="Restore from DFU mode: first guide you, step by step, through the buttons that put the device into it.",
        ),
    ] = False,
    manual_dfu: ManualDfuOption = False,
) -> None:
    """
    Update or restore the device using an IPSW (local path or URL).
    """
    if exclusive_usb and sys.platform != "darwin":
        raise typer.BadParameter("--exclusive-usb is only supported on macOS", param_hint="--exclusive-usb")
    if dfu:
        ecid = await device.get_ecid()
        await guide_into_dfu(device, manual=manual_dfu)
        device = await _reconnect_in_dfu(ecid)
    if exclusive_usb and device.irecv is not None and device.irecv.is_kis:
        raise typer.BadParameter(
            "On macOS a device in DFU mode behind KIS is reached through deviceinterfaced, which --exclusive-usb "
            "boots out.",
            param_hint="--exclusive-usb",
        )
    async with ipsw_ctx as ipsw:
        with DeviceInterfacedControl() if exclusive_usb else contextlib.nullcontext():
            await restore_update_task(
                device,
                ipsw,
                tss,
                erase,
                ignore_fdr,
                enable_tss_batch=tss_batch,
            )
