import asyncio
import difflib
import logging
import os
import re
import sys
import textwrap
import traceback
from typing import List, Union

import coloredlogs
import typer
from typer.core import TyperGroup

from pymobiledevice3.cli.cli_common import TUNNEL_ENV_VAR, isatty
from pymobiledevice3.exceptions import AccessDeniedError, CloudConfigurationAlreadyPresentError, \
    ConnectionFailedError, ConnectionFailedToUsbmuxdError, DeprecationError, DeveloperModeError, \
    DeveloperModeIsNotEnabledError, DeviceHasPasscodeSetError, DeviceNotFoundError, FeatureNotSupportedError, \
    InternalError, InvalidServiceError, MessageNotSupportedError, MissingValueError, NoDeviceConnectedError, \
    NotEnoughDiskSpaceError, NotPairedError, OSNotSupportedError, PairingDialogResponsePendingError, \
    PasswordRequiredError, QuicProtocolNotSupportedError, RSDRequiredError, SetProhibitedError, \
    TunneldConnectionError, UserDeniedPairingError
from pymobiledevice3.lockdown import retry_create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils

coloredlogs.install(level=logging.INFO)

logging.getLogger('quic').disabled = True
logging.getLogger('asyncio').disabled = True
logging.getLogger('zeroconf').disabled = True
logging.getLogger('parso.cache').disabled = True
logging.getLogger('parso.cache.pickle').disabled = True
logging.getLogger('parso.python.diff').disabled = True
logging.getLogger('humanfriendly.prompts').disabled = True
logging.getLogger('blib2to3.pgen2.driver').disabled = True
logging.getLogger('urllib3.connectionpool').disabled = True

logger = logging.getLogger(__name__)

# For issue https://github.com/doronz88/pymobiledevice3/issues/1217, details: https://bugs.python.org/issue37373
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

INVALID_SERVICE_MESSAGE = """Failed to start service. Possible reasons are:
- If you were trying to access a developer service (developer subcommand):
    - If your device iOS version >= 15.0:
        - Make sure you first enabled "Developer Mode" via:
          > python3 -m pymobiledevice3 amfi enable-developer-mode

    - Make sure the DeveloperDiskImage/PersonalizedImage is mounted via:
      > python3 -m pymobiledevice3 mounter auto-mount

    - If your device iOS version >= 17.0:
        - Make sure you passed the --rsd option to the subcommand
          https://github.com/doronz88/pymobiledevice3#working-with-developer-tools-ios--170

- Apple removed this service, or your iOS version does not support it.

- A bug. Please file a bug report:
  https://github.com/doronz88/pymobiledevice3/issues/new?assignees=&labels=&projects=&template=bug_report.md&title=
"""

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'], max_content_width=400)

# Mapping of index options to import file names
CLI_GROUPS = {
    'activation': 'activation',
    'afc': 'afc',
    'amfi': 'amfi',
    'apps': 'apps',
    'backup2': 'backup',
    'bonjour': 'bonjour',
    'companion': 'companion_proxy',
    'crash': 'crash',
    'developer': 'developer',
    'diagnostics': 'diagnostics',
    'lockdown': 'lockdown',
    'mounter': 'mounter',
    'notification': 'notification',
    'pcap': 'pcap',
    'power-assertion': 'power_assertion',
    'processes': 'processes',
    'profile': 'profile',
    'provision': 'provision',
    'remote': 'remote',
    'restore': 'restore',
    'springboard': 'springboard',
    'syslog': 'syslog',
    'usbmux': 'usbmux',
    'webinspector': 'webinspector',
    'version': 'version',
    'install-completions': 'completions',
}

# Set if used the `--reconnect` option
RECONNECT = False


class Pmd3TyperGroup(TyperGroup):
    def list_commands(self, ctx):
        # Order is preserved by dict insertion; adjust if you want alphabetical
        return list(CLI_GROUPS.keys())

    def get_command(self, ctx, name):
        if name not in CLI_GROUPS:
            self.handle_invalid_command(ctx, name)
        return self.import_and_get_command(ctx, name)

    def handle_invalid_command(self, ctx, name: str) -> None:
        suggested_commands = self.search_commands(name)
        suggestion = self.format_suggestions(suggested_commands)
        # ctx.fail raises a ClickException underneath, which Typer displays nicely
        ctx.fail(f'No such command {name!r}{suggestion}')

    @staticmethod
    def format_suggestions(suggestions: List[str]) -> str:
        if not suggestions:
            return ''
        cmds = textwrap.indent('\n'.join(suggestions), ' ' * 4)
        return f'\nDid you mean this?\n{cmds}'

    @staticmethod
    def import_and_get_command(ctx, name: str):
        module_name = f'pymobiledevice3.cli.{CLI_GROUPS[name]}'
        mod = __import__(module_name, None, None, ['cli'])
        # submodules currently expose a Click/Typer Group named "cli"
        if isinstance(mod.cli, typer.Typer):
            command = typer.main.get_command(mod.cli)
            command.name = name
        else:
            command = mod.cli.get_command(ctx, name)
        if not command:
            # if module is a single-group, take its first command
            command_name = mod.cli.list_commands(ctx)[0]
            command = mod.cli.get_command(ctx, command_name)
        return command

    @staticmethod
    def highlight_keyword(text: str, keyword: str) -> str:
        # Typer uses the same styling helpers
        return re.sub(f'({re.escape(keyword)})', lambda m: typer.style(m.group(1), bold=True), text,
                      flags=re.IGNORECASE)

    @staticmethod
    def collect_commands(command) -> Union[str, List[str]]:
        # Works with both Click and Typer commands (Typer builds on Click)
        if hasattr(command, "commands"):  # group
            cmds = []
            for k, v in command.commands.items():
                child = Pmd3TyperGroup.collect_commands(v)
                if isinstance(child, list):
                    cmds.extend([f'{command.name} {c}' for c in child])
                else:
                    cmds.append(f'{command.name} {child}')
            return cmds
        return f'{command.name}'

    @staticmethod
    def load_all_commands() -> List[str]:
        all_commands: List[str] = []
        for key in CLI_GROUPS.keys():
            module_name = f'pymobiledevice3.cli.{CLI_GROUPS[key]}'
            mod = __import__(module_name, None, None, ['cli'])
            if isinstance(mod.cli, typer.Typer):
                cmd = Pmd3TyperGroup.collect_commands(typer.main.get_group(mod.cli))
            else:
                cmd = Pmd3TyperGroup.collect_commands(mod.cli.commands[key])
            if isinstance(cmd, list):
                all_commands.extend(cmd)
            else:
                all_commands.append(cmd)
        return all_commands

    @staticmethod
    def search_commands(pattern: str) -> List[str]:
        all_commands = Pmd3TyperGroup.load_all_commands()
        matched = sorted(filter(lambda cmd: re.search(pattern, cmd), all_commands))
        if not matched:
            matched = difflib.get_close_matches(pattern, all_commands, n=20, cutoff=0.4)
        if isatty():
            matched = [Pmd3TyperGroup.highlight_keyword(cmd, pattern) for cmd in matched]
        return matched


app = typer.Typer(
    cls=Pmd3TyperGroup,
    context_settings=CONTEXT_SETTINGS,
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="markdown",
    help=(
        "Interact with a connected iDevice (iPhone, iPad, ...)\n\n"
        "For more information please see: https://github.com/doronz88/pymobiledevice3"
    ),
)


@app.callback()
def _root(
        reconnect: bool = typer.Option(
            False,
            "--reconnect",
            help="Reconnect to device when disconnected.",
            show_default=False,
        ),
):
    """
    Top-level options for pymobiledevice3.
    """
    global RECONNECT
    RECONNECT = reconnect


def invoke_cli_with_error_handling() -> bool:
    """
    Invoke the command line interface and return `True` if the failure reason of the command was that the device was
    disconnected.
    """
    try:
        # Typer apps are callable; this executes the CLI with current sys.argv
        app()
    except NoDeviceConnectedError:
        logger.error('Device is not connected')
        return True
    except ConnectionAbortedError:
        logger.error('Device was disconnected')
        return True
    except NotPairedError:
        logger.error('Device is not paired')
    except UserDeniedPairingError:
        logger.error('User refused to trust this computer')
    except PairingDialogResponsePendingError:
        logger.error('Waiting for user dialog approval')
    except SetProhibitedError:
        logger.error('lockdownd denied the access')
    except MissingValueError:
        logger.error('No such value')
    except DeviceHasPasscodeSetError:
        logger.error('Cannot enable developer-mode when passcode is set')
    except DeveloperModeError as e:
        logger.error(f'Failed to enable developer-mode. Error: {e}')
    except ConnectionFailedToUsbmuxdError:
        logger.error("Failed to connect to usbmuxd socket. Make sure it's running.")
    except ConnectionFailedError:
        logger.error('Failed to connect to service port.')
        return True
    except MessageNotSupportedError:
        logger.error('Message not supported for this iOS version')
        traceback.print_exc()
    except InternalError:
        logger.error('Internal Error')
    except DeveloperModeIsNotEnabledError:
        logger.error('Developer Mode is disabled. You can try to enable it using: '
                     'python3 -m pymobiledevice3 amfi enable-developer-mode')
    except (InvalidServiceError, RSDRequiredError) as e:
        should_retry_over_tunneld = False
        if isinstance(e, RSDRequiredError):
            logger.warning('Trying again over tunneld since RSD is required for this command')
            should_retry_over_tunneld = True
        elif (getattr(e, "identifier", None) is not None) and ('developer' in sys.argv) and (
                '--tunnel' not in sys.argv):
            logger.warning('Got an InvalidServiceError. Trying again over tunneld since it is a developer command')
            should_retry_over_tunneld = True
        if should_retry_over_tunneld:
            # use a single space because Typer/Click will ignore envvars of empty strings
            os.environ[TUNNEL_ENV_VAR] = getattr(e, "identifier", None) or ' '
            return main()
        logger.error(INVALID_SERVICE_MESSAGE)
    except PasswordRequiredError:
        logger.error('Device is password protected. Please unlock and retry')
    except AccessDeniedError:
        logger.error(get_os_utils().access_denied_error)
    except BrokenPipeError:
        traceback.print_exc()
    except TunneldConnectionError:
        logger.error(
            'Unable to connect to Tunneld. You can start one using:\n'
            'sudo python3 -m pymobiledevice3 remote tunneld')
    except DeviceNotFoundError as e:
        logger.error(f'Device not found: {e.udid}')
    except NotEnoughDiskSpaceError:
        logger.error('Not enough disk space')
    except DeprecationError:
        logger.error('failed to query MobileGestalt, MobileGestalt deprecated (iOS >= 17.4).')
    except OSNotSupportedError as e:
        logger.error(
            f'Unsupported OS - {e.os_name}. To add support, consider contributing at '
            f'https://github.com/doronz88/pymobiledevice3.')
    except CloudConfigurationAlreadyPresentError:
        logger.error('A cloud configuration is already present on device. You must first erase the device in order '
                     'to install new one:\n'
                     '> pymobiledevice3 profile erase-device')
    except FeatureNotSupportedError as e:
        logger.error(
            f'Missing implementation of `{e.feature}` on `{e.os_name}`. To add support, consider contributing at '
            f'https://github.com/doronz88/pymobiledevice3.')
    except QuicProtocolNotSupportedError as e:
        logger.error(str(e))

    return False


def main() -> None:
    # Retry to invoke the CLI
    while invoke_cli_with_error_handling():
        # If reached here, this means the failure reason was that the device is disconnected
        if not RECONNECT:
            # If not invoked with the `--reconnect` option, break here
            break
        try:
            # Wait for the device to be available again
            lockdown = retry_create_using_usbmux(None)
            lockdown.close()
        except KeyboardInterrupt:
            print('Aborted.')
            break


if __name__ == '__main__':
    main()
