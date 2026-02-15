import contextlib
import logging
import plistlib
import tempfile
import traceback
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Annotated, Optional
from zipfile import ZipFile

import click
import requests
import typer
from pygments import formatters, highlight, lexers
from typer_injector import Depends, InjectingTyper

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import (
    async_command,
    cli_loop,
    is_invoked_for_completion,
    print_json,
    prompt_selection,
)
from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionFailedToUsbmuxdError, IncorrectModeError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.utils import file_download, start_ipython_shell

logger = logging.getLogger(__name__)


SHELL_USAGE = """
# use `irecv` variable to access Restore mode API
# for example:
print(irecv.getenv('build-version'))
"""
IPSWME_API = "https://api.ipsw.me/v4/device/"


cli = InjectingTyper(
    name="restore",
    help="Restore/erase IPSWs, fetch blobs, and manage devices in Recovery/DFU.",
    no_args_is_help=True,
)


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

    logger.debug("searching among connected devices via lockdownd")
    devices = [dev for dev in await usbmux.list_devices() if dev.connection_type == "USB"]
    if len(devices) > 1:
        raise click.ClickException("Multiple device detected")
    try:
        for device in devices:
            try:
                lockdown = await create_using_usbmux(serial=device.serial, connection_type="USB")
            except (ConnectionFailedError, IncorrectModeError):
                continue
            if (ecid is None) or (lockdown.ecid == ecid):
                logger.debug("found device")
                return Device(lockdown=lockdown)
            else:
                continue
    except ConnectionFailedToUsbmuxdError:
        pass

    logger.debug("waiting for device to be available in Recovery mode")
    return Device(irecv=IRecv(ecid=ecid))


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


@contextlib.contextmanager
def tempzip_download_ctx(url: str) -> Iterator[ZipFile]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpzip = Path(tmpdir) / url.split("/")[-1]
        file_download(url, tmpzip)
        yield ZipFile(tmpzip)


@contextlib.contextmanager
def zipfile_ctx(path: str) -> Iterator[ZipFile]:
    yield ZipFile(path)


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
) -> contextlib.AbstractContextManager[ZipFile]:
    if ipsw and not ipsw.startswith(("http://", "https://")):
        return zipfile_ctx(ipsw)

    url = ipsw
    if url is None:
        url = query_ipswme(cli_loop.run_until_complete(device.get_product_type()))
    return tempzip_download_ctx(url)


IPSWCtxDep = Annotated[
    contextlib.AbstractContextManager[ZipFile],
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
    Optional[dict],
    Depends(tss_dependency),
]


def query_ipswme(identifier: str) -> str:
    resp = requests.get(IPSWME_API + identifier, headers={"Accept": "application/json"})
    firmwares = resp.json()["firmwares"]
    display_list = [f"{entry['version']}: {entry['buildid']}" for entry in firmwares if entry["signed"]]
    idx = prompt_selection(display_list, "Choose version", idx=True)
    return firmwares[idx]["url"]


async def restore_update_task(
    device: Device, ipsw: ZipFile, tss: Optional[dict], erase: bool, ignore_fdr: bool
) -> None:
    behavior = Behavior.Update
    if erase:
        behavior = Behavior.Erase

    try:
        await Restore(ipsw, device, tss=tss, behavior=behavior, ignore_fdr=ignore_fdr).update()
    except Exception:
        # click may "swallow" several exception types so we try to catch them all here
        traceback.print_exc()
        raise


@cli.command("shell")
def restore_shell(device: DeviceDep) -> None:
    """create an IPython shell for interacting with iBoot"""
    start_ipython_shell(
        header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
        user_ns={
            "irecv": device,
        },
    )


@cli.command("enter")
@async_command
async def restore_enter(device: DeviceDep) -> None:
    """enter Recovery mode"""
    if await device.get_is_lockdown():
        await device.lockdown.enter_recovery()


@cli.command("exit")
def restore_exit() -> None:
    """exit Recovery mode"""
    irecv = IRecv()
    irecv.set_autoboot(True)
    irecv.reboot()


@cli.command("restart")
@async_command
async def restore_restart(device: DeviceDep) -> None:
    """restarts device"""
    if await device.get_is_lockdown():
        async with DiagnosticsService(device.lockdown) as diagnostics:
            await diagnostics.restart()
    else:
        device.irecv.reboot()


async def restore_tss_task(
    device: Device, ipsw_ctx: contextlib.AbstractContextManager[ZipFile], out: Optional[IO]
) -> None:
    with ipsw_ctx as ipsw:
        tss = await Recovery(ipsw, device).fetch_tss_record()
    if out:
        plistlib.dump(tss, out)
    print_json(tss)


@cli.command("tss")
@async_command
async def restore_tss(device: DeviceDep, ipsw_ctx: IPSWCtxDep, out: Optional[Path] = None) -> None:
    """query SHSH blobs"""
    with out.open("wb") if out else contextlib.nullcontext() as out_file:
        await restore_tss_task(device, ipsw_ctx, out_file)


async def restore_ramdisk_task(device: Device, ipsw_ctx: contextlib.AbstractContextManager[ZipFile]) -> None:
    with ipsw_ctx as ipsw:
        await Recovery(ipsw, device).boot_ramdisk()


@cli.command("ramdisk")
@async_command
async def restore_ramdisk(device: DeviceDep, ipsw_ctx: IPSWCtxDep) -> None:
    """
    Boot only the update ramdisk without performing a restore (IPSW path or URL accepted).
    """
    await restore_ramdisk_task(device, ipsw_ctx)


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
) -> None:
    """
    Update or restore the device using an IPSW (local path or URL).
    """
    with ipsw_ctx as ipsw:
        await restore_update_task(device, ipsw, tss, erase, ignore_fdr)
