import asyncio
import difflib
import importlib
import logging
import os
import re
import shutil
import sys
import textwrap
import traceback
import warnings
from typing import Annotated, Union

import coloredlogs
import typer
from packaging.version import Version
from typer.core import TyperGroup
from typer_injector import InjectingTyper

try:
    import shellingham
except ImportError:  # pragma: no cover
    shellingham = None

from pymobiledevice3.cli.cli_common import TUNNEL_ENV_VAR, isatty, set_color_flag, set_verbosity
from pymobiledevice3.exceptions import (
    AccessDeniedError,
    AfcException,
    AfcFileNotFoundError,
    CloudConfigurationAlreadyPresentError,
    ConnectionFailedError,
    ConnectionFailedToUsbmuxdError,
    ConnectionTerminatedError,
    DeprecationError,
    DeveloperModeError,
    DeveloperModeIsNotEnabledError,
    DeviceHasPasscodeSetError,
    DeviceNotFoundError,
    FeatureNotSupportedError,
    InternalError,
    InvalidServiceError,
    MessageNotSupportedError,
    MissingValueError,
    NoDeviceConnectedError,
    NotEnoughDiskSpaceError,
    NotPairedError,
    OSNotSupportedError,
    PairingDialogResponsePendingError,
    PasswordRequiredError,
    QuicProtocolNotSupportedError,
    RSDRequiredError,
    SetProhibitedError,
    StartServiceError,
    TunneldConnectionError,
    UserDeniedPairingError,
)
from pymobiledevice3.lockdown import create_using_usbmux, retry_create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils

coloredlogs.install(level=logging.INFO)

logging.getLogger("quic").setLevel(logging.CRITICAL + 1)
logging.getLogger("asyncio").setLevel(logging.CRITICAL + 1)
logging.getLogger("parso").setLevel(logging.CRITICAL + 1)
logging.getLogger("humanfriendly").setLevel(logging.CRITICAL + 1)
logging.getLogger("blib2to3").setLevel(logging.CRITICAL + 1)
logging.getLogger("urllib3").setLevel(logging.CRITICAL + 1)

logger = logging.getLogger(__name__)

# For issue https://github.com/doronz88/pymobiledevice3/issues/1217, details: https://bugs.python.org/issue37373
if sys.platform == "win32":
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=DeprecationWarning)
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

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 400}

# Mapping of index options to import file names
CLI_GROUPS = {
    "activation": "activation",
    "acquisition": "acquisition",
    "afc": "afc",
    "amfi": "amfi",
    "apps": "apps",
    "backup2": "backup",
    "bonjour": "bonjour",
    "companion": "companion_proxy",
    "crash": "crash",
    "developer": "developer",
    "diagnostics": "diagnostics",
    "lockdown": "lockdown",
    "mounter": "mounter",
    "notification": "notification",
    "pcap": "pcap",
    "power-assertion": "power_assertion",
    "processes": "processes",
    "profile": "profile",
    "provision": "provision",
    "remote": "remote",
    "restore": "restore",
    "springboard": "springboard",
    "syslog": "syslog",
    "usbmux": "usbmux",
    "webinspector": "webinspector",
    "idam": "idam",
    "version": "version",
}

# Set if used the `--reconnect` option
RECONNECT = False
_ORIGINAL_SHELLINGHAM_DETECT = None


def _detect_shell_for_completion() -> tuple[str, str]:
    shell, executable = _ORIGINAL_SHELLINGHAM_DETECT()
    if shell == "xonsh":
        return ("fish" if shutil.which("fish") else "bash"), executable
    return shell, executable


def _patch_xonsh_completion_detection() -> None:
    """Let Typer install fish completions for xonsh when available, otherwise bash."""
    global _ORIGINAL_SHELLINGHAM_DETECT

    if shellingham is None:
        return

    detect_shell = shellingham.detect_shell
    _ORIGINAL_SHELLINGHAM_DETECT = getattr(detect_shell, "_pymobiledevice3_original", detect_shell)
    if getattr(detect_shell, "_pymobiledevice3_xonsh_patched", False):
        return

    _detect_shell_for_completion._pymobiledevice3_original = _ORIGINAL_SHELLINGHAM_DETECT
    _detect_shell_for_completion._pymobiledevice3_xonsh_patched = True
    shellingham.detect_shell = _detect_shell_for_completion


_patch_xonsh_completion_detection()


class Pmd3TyperGroup(TyperGroup):
    def list_commands(self, ctx) -> list[str]:
        # Order is preserved by dict insertion; adjust if you want alphabetical
        return list(CLI_GROUPS.keys())

    def get_command(self, ctx, cmd_name: str):
        if cmd_name not in CLI_GROUPS:
            self.handle_invalid_command(ctx, cmd_name)
        return self.import_and_get_command(ctx, cmd_name)

    def handle_invalid_command(self, ctx, name: str) -> None:
        suggested_commands = self.search_commands(name)
        suggestion = self.format_suggestions(suggested_commands)
        # ctx.fail raises a ClickException underneath, which Typer displays nicely
        ctx.fail(f"No such command {name!r}{suggestion}")

    @staticmethod
    def format_suggestions(suggestions: list[str]) -> str:
        if not suggestions:
            return ""
        cmds = textwrap.indent("\n".join(suggestions), " " * 4)
        return f"\nDid you mean:\n{cmds}"

    @staticmethod
    def import_and_get_command(ctx, name: str):
        module_name = f"pymobiledevice3.cli.{CLI_GROUPS[name]}"
        mod = importlib.import_module(module_name)
        # submodules expose a Typer Group named "cli"
        cli: typer.Typer = mod.cli
        return typer.main.get_command(cli)

    @staticmethod
    def highlight_keyword(text: str, keyword: str) -> str:
        return re.sub(f"({keyword})", typer.style("\\1", bold=True), text, flags=re.IGNORECASE)

    @staticmethod
    def collect_commands(command) -> Union[str, list[str]]:
        if isinstance(command, TyperGroup):  # group
            cmds = []
            for v in command.commands.values():
                child = Pmd3TyperGroup.collect_commands(v)
                if isinstance(child, list):
                    cmds.extend([f"{command.name} {c}" for c in child])
                else:
                    cmds.append(f"{command.name} {child}")
            return cmds
        return command.name or ""

    @staticmethod
    def search_commands(pattern: str) -> list[str]:
        all_commands = Pmd3TyperGroup.load_all_commands()
        matched = sorted(filter(lambda cmd: re.search(pattern, cmd), all_commands))
        if not matched:
            matched = difflib.get_close_matches(pattern, all_commands, n=20, cutoff=0.4)
        if isatty():
            matched = [Pmd3TyperGroup.highlight_keyword(cmd, pattern) for cmd in matched]
        return matched

    @staticmethod
    def load_all_commands() -> list[str]:
        all_commands: list[str] = []
        for key in CLI_GROUPS:
            module_name = f"pymobiledevice3.cli.{CLI_GROUPS[key]}"
            mod = importlib.import_module(module_name)
            if isinstance(mod.cli, typer.Typer):
                cmd = Pmd3TyperGroup.collect_commands(typer.main.get_group(mod.cli))
            else:
                cmd = Pmd3TyperGroup.collect_commands(mod.cli.commands[key])
            if isinstance(cmd, list):
                all_commands.extend(cmd)
            else:
                all_commands.append(cmd)
        return all_commands

    def resolve_command(self, ctx, args: list[str]):
        return super().resolve_command(ctx, args)


app = InjectingTyper(
    cls=Pmd3TyperGroup,
    context_settings=CONTEXT_SETTINGS,
    no_args_is_help=True,
    # add_completion=False,
    rich_markup_mode="markdown",
    help=(
        "Swiss-army CLI for pairing, inspecting, backing up, and automating iOS devices.\n\n"
        "Docs and examples: https://github.com/doronz88/pymobiledevice3"
    ),
)


@app.callback()
def _root(
    reconnect: Annotated[
        bool,
        typer.Option(
            "--reconnect",
            help="Automatically reconnect if the device disconnects mid-command.",
            show_default=False,
        ),
    ] = False,
    verbosity: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Increase logging verbosity (repeat for more detail).",
        ),
    ] = 0,
    color: Annotated[
        bool,
        typer.Option(help="Colorize output; disable with --no-color for plain logs."),
    ] = True,
) -> None:
    """
    Top-level options for pymobiledevice3.
    """
    global RECONNECT
    RECONNECT = reconnect
    set_verbosity(verbosity)
    set_color_flag(color)


def device_might_need_tunneld(identifier: str) -> bool:
    """
    Determines if the device might require tunneling based on its product version.

    This function uses the `create_using_usbmux` context manager to establish a lockdown
    session with the specified identifier. It retrieves the device's product version,
    and checks if it is greater than or equal to version "17.0". If so, the function
    returns True, indicating that the device might require tunneling. Otherwise, it
    returns False.

    :param identifier: A string representing the device identifier.
    :return: A boolean indicating whether the device might require tunneling.
    """

    async def _device_might_need_tunneld() -> bool:
        async with await create_using_usbmux(serial=identifier) as lockdown:
            return Version(lockdown.product_version) >= Version("17.0")

    return asyncio.run(_device_might_need_tunneld())


def invoke_cli_with_error_handling() -> bool:
    """
    Invoke the command line interface and return `True` if the failure reason of the command was that the device was
    disconnected.
    """
    try:
        # Typer apps are callable; this executes the CLI with current sys.argv
        app(args=["--help"] if len(sys.argv) == 1 else None)
    except NoDeviceConnectedError:
        logger.error("Device is not connected")
        return True
    except ConnectionTerminatedError:
        logger.error("Connection was terminated abruptly")
        return True
    except NotPairedError:
        logger.error("Device is not paired")
    except UserDeniedPairingError:
        logger.error("User refused to trust this computer")
    except PairingDialogResponsePendingError:
        logger.error("Waiting for user dialog approval")
    except SetProhibitedError:
        logger.error("lockdownd denied the access")
    except MissingValueError:
        logger.error("No such value")
    except DeviceHasPasscodeSetError:
        logger.error("Cannot enable developer-mode when passcode is set")
    except DeveloperModeError:
        logger.error("Failed to enable developer-mode.")
    except ConnectionFailedToUsbmuxdError:
        logger.error("Failed to connect to usbmuxd socket. Make sure it's running.")
    except ConnectionFailedError:
        logger.error("Failed to connect to service port.")
        return True
    except MessageNotSupportedError:
        logger.error("Message not supported for this iOS version")
        traceback.print_exc()
    except InternalError:
        logger.error("Internal Error")
    except DeveloperModeIsNotEnabledError:
        logger.error(
            "Developer Mode is disabled. You can try to enable it using: "
            "python3 -m pymobiledevice3 amfi enable-developer-mode"
        )
    except (InvalidServiceError, RSDRequiredError) as e:
        should_retry_over_tunneld = False
        if isinstance(e, RSDRequiredError):
            logger.warning("Trying again over tunneld since RSD is required for this command")
            should_retry_over_tunneld = True
        elif (
            (e.identifier is not None)
            and ("developer" in sys.argv)
            and ("--tunnel" not in sys.argv)
            and device_might_need_tunneld(e.identifier)
        ):
            logger.warning("Got an InvalidServiceError. Trying again over tunneld since it is a developer command")
            should_retry_over_tunneld = True
        if should_retry_over_tunneld:
            # use a single space because Typer/Click will ignore envvars of empty strings
            os.environ[TUNNEL_ENV_VAR] = e.identifier or " "
            main()
            return False
        logger.error(INVALID_SERVICE_MESSAGE)
    except PasswordRequiredError:
        logger.error("Device is password protected. Please unlock and retry")
    except AccessDeniedError:
        logger.error(get_os_utils().access_denied_error)
    except BrokenPipeError:
        traceback.print_exc()
    except TunneldConnectionError:
        logger.error(
            "Unable to connect to Tunneld. You can start one using:\nsudo python3 -m pymobiledevice3 remote tunneld"
        )
    except DeviceNotFoundError as e:
        logger.error(f"Device not found: {e.udid}")
    except NotEnoughDiskSpaceError:
        logger.error("Not enough disk space")
    except DeprecationError:
        logger.error("failed to query MobileGestalt, MobileGestalt deprecated (iOS >= 17.4).")
    except OSNotSupportedError as e:
        logger.error(
            f"Unsupported OS - {e.os_name}. To add support, consider contributing at "
            f"https://github.com/doronz88/pymobiledevice3."
        )
    except CloudConfigurationAlreadyPresentError:
        logger.error(
            "A cloud configuration is already present on device. You must first erase the device in order "
            "to install new one:\n"
            "> pymobiledevice3 profile erase-device"
        )
    except FeatureNotSupportedError as e:
        logger.error(
            f"Missing implementation of `{e.feature}` on `{e.os_name}`. To add support, consider contributing at "
            f"https://github.com/doronz88/pymobiledevice3."
        )
    except QuicProtocolNotSupportedError:
        logger.error("Encountered a QUIC protocol error.")
    except StartServiceError as e:
        if e.message == "ServiceProhibited" and e.service_name == "com.apple.pcapd.shim.remote":
            logger.error(
                f"The {e.service_name} service is USB only (at least for some iOS versions).\n"
                "Full discussion is available in: https://github.com/doronz88/pymobiledevice3/issues/1515"
            )
        else:
            logger.error(f"Failed to start: {e.service_name} with. Received error: {e.message}.")
    except AfcFileNotFoundError as e:
        logger.error(f"File [{e.filename}] not found during afc operation: {e}")
    except AfcException as e:
        logger.error(f"Failed to perform Afc operation: {e}")
    return False


def main() -> None:
    # Retry to invoke the CLI
    while invoke_cli_with_error_handling():
        # If reached here, this means the failure reason was that the device is disconnected
        if not RECONNECT:
            # If not invoked with the `--reconnect` option, break here
            break
        try:
            logger.info("Waiting for the device to be available again")
            lockdown = asyncio.run(retry_create_using_usbmux())
            logger.info("Device connected")
            asyncio.run(lockdown.close())
        except KeyboardInterrupt:
            print("Aborted.")
            break


if __name__ == "__main__":
    main()
