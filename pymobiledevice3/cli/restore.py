import asyncio
import contextlib
import logging
import os
import plistlib
import tempfile
import traceback
from pathlib import Path
from typing import IO, Generator, Optional, Union
from zipfile import ZipFile

import click
import IPython
import requests
from pygments import formatters, highlight, lexers

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import print_json, prompt_selection, set_verbosity
from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionFailedToUsbmuxdError, IncorrectModeError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.utils import file_download

SHELL_USAGE = """
# use `irecv` variable to access Restore mode API
# for example:
print(irecv.getenv('build-version'))
"""

logger = logging.getLogger(__name__)
IPSWME_API = 'https://api.ipsw.me/v4/device/'


class Command(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('device', '--ecid'), type=click.INT, callback=self.device),
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
        ]

    @staticmethod
    def device(ctx, param, value) -> Optional[Union[LockdownClient, IRecv]]:
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return

        ecid = value
        logger.debug('searching among connected devices via lockdownd')
        devices = [dev for dev in usbmux.list_devices() if dev.connection_type == 'USB']
        if len(devices) > 1:
            raise click.ClickException('Multiple device detected')
        try:
            for device in devices:
                try:
                    lockdown = create_using_usbmux(serial=device.serial, connection_type='USB')
                except (ConnectionFailedError, IncorrectModeError):
                    continue
                if (ecid is None) or (lockdown.ecid == value):
                    logger.debug('found device')
                    return lockdown
                else:
                    continue
        except ConnectionFailedToUsbmuxdError:
            pass

        logger.debug('waiting for device to be available in Recovery mode')
        return IRecv(ecid=ecid)


@contextlib.contextmanager
def tempzip_download_ctx(url: str) -> Generator[ZipFile, None, None]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpzip = Path(tmpdir) / url.split('/')[-1]
        file_download(url, tmpzip)
        yield ZipFile(tmpzip)


@contextlib.contextmanager
def zipfile_ctx(path: str) -> Generator[ZipFile, None, None]:
    yield ZipFile(path)


class IPSWCommand(Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.extend([click.Option(('ipsw_ctx', '-i', '--ipsw'), required=False,
                                         callback=self.ipsw_ctx, help='local IPSW file'),
                            click.Option(('tss', '--tss'), type=click.File('rb'), callback=self.tss)])

    @staticmethod
    def ipsw_ctx(ctx, param, value) -> Generator[ZipFile, None, None]:
        if value and not value.startswith(('http://', 'https://')):
            return zipfile_ctx(value)

        url = value
        if url is None:
            url = query_ipswme(ctx.params['device'].product_type)
        return tempzip_download_ctx(url)

    @staticmethod
    def tss(ctx, param, value) -> Optional[IO]:
        if value is None:
            return
        return plistlib.load(value)


def query_ipswme(identifier: str) -> str:
    resp = requests.get(IPSWME_API + identifier, headers={'Accept': 'application/json'})
    firmwares = resp.json()['firmwares']
    display_list = [f'{entry["version"]}: {entry["buildid"]}' for entry in firmwares if entry['signed']]
    idx = prompt_selection(display_list, 'Choose version', idx=True)
    return firmwares[idx]['url']


async def restore_update_task(device: Device, ipsw: ZipFile, tss: Optional[IO], erase: bool, ignore_fdr: bool) -> None:
    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device
    device = Device(lockdown=lockdown, irecv=irecv)

    behavior = Behavior.Update
    if erase:
        behavior = Behavior.Erase

    try:
        await Restore(ipsw, device, tss=tss, behavior=behavior, ignore_fdr=ignore_fdr).update()
    except Exception:
        # click may "swallow" several exception types so we try to catch them all here
        traceback.print_exc()
        raise


@click.group()
def cli() -> None:
    pass


@cli.group()
def restore() -> None:
    """ Restore an IPSW or access device in recovery mode """
    pass


@restore.command('shell', cls=Command)
def restore_shell(device):
    """ create an IPython shell for interacting with iBoot """
    IPython.embed(
        header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
        user_ns={
            'irecv': device,
        })


@restore.command('enter', cls=Command)
def restore_enter(device):
    """ enter Recovery mode """
    if isinstance(device, LockdownClient):
        device.enter_recovery()


@restore.command('exit')
def restore_exit():
    """ exit Recovery mode """
    irecv = IRecv()
    irecv.set_autoboot(True)
    irecv.reboot()


@restore.command('restart', cls=Command)
def restore_restart(device):
    """ restarts device """
    if isinstance(device, LockdownClient):
        with DiagnosticsService(device) as diagnostics:
            diagnostics.restart()
    else:
        device.reboot()


@restore.command('tss', cls=IPSWCommand)
@click.argument('out', type=click.File('wb'), required=False)
def restore_tss(device: Device, ipsw_ctx: Generator, out):
    """ query SHSH blobs """
    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device

    device = Device(lockdown=lockdown, irecv=irecv)
    with ipsw_ctx as ipsw:
        tss = Recovery(ipsw, device).fetch_tss_record()
    if out:
        plistlib.dump(tss, out)
    print_json(tss)


@restore.command('ramdisk', cls=IPSWCommand)
def restore_ramdisk(device: Device, ipsw_ctx: Generator, tss: IO):
    """
    don't perform an actual restore. just enter the update ramdisk

    ipsw can be either a filename or an url
    """
    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device
    device = Device(lockdown=lockdown, irecv=irecv)
    with ipsw_ctx as ipsw:
        Recovery(ipsw, device, tss=tss).boot_ramdisk()


@restore.command('update', cls=IPSWCommand)
@click.option('--erase', is_flag=True, help='use the Erase BuildIdentity (full factory-reset)')
@click.option('--ignore-fdr', is_flag=True, help='only establish an FDR service connection, but don\'t proxy any '
                                                 'traffic')
def restore_update(device: Device, ipsw_ctx: Generator, tss: IO, erase: bool, ignore_fdr: bool) -> None:
    """
    perform an update

    ipsw can be either a filename or an url
    """
    with ipsw_ctx as ipsw:
        asyncio.run(restore_update_task(device, ipsw, tss, erase, ignore_fdr), debug=True)
