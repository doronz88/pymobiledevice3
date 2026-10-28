import asyncio
import logging
import os
import plistlib
import signal
import struct
import subprocess
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated, Optional
from zipfile import ZipFile

import typer
from packaging.version import Version
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import RSDServiceProviderDep, ServiceProviderDep, async_command, print_json
from pymobiledevice3.exceptions import RoutableTunnelRequiredError, RSDRequiredError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.debugserver_applist import DebugServerAppList
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.tcp_forwarder import LockdownTcpForwarder

DEBUGPROXY_SERVICE_NAME = "com.apple.internal.dt.remote.debugproxy"

DEBUGSERVER_CONNECTION_STEPS = """
Follow the following connections steps from LLDB:

(lldb) platform select remote-ios
(lldb) target create /path/to/local/application.app
(lldb) script lldb.target.module[0].SetPlatformFileSpec(lldb.SBFileSpec('/private/var/containers/Bundle/Application/<APP-UUID>/application.app'))
(lldb) process connect connect://[{host}]:{port}   <-- ACTUAL CONNECTION DETAILS!
(lldb) process launch
"""


logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="debugserver",
    help="Start and drive debugserver sessions (RSD for iOS 17+, usbmux for older).",
    no_args_is_help=True,
)


@cli.command("applist")
@async_command
async def debugserver_applist(service_provider: ServiceProviderDep) -> None:
    """Print the debugserver applist XML for the device."""
    print_json(await DebugServerAppList(service_provider).get())


@cli.command("start-server")
@async_command
async def debugserver_start_server(
    service_provider: ServiceProviderDep,
    local_port: Optional[int] = None,
    host: Annotated[
        str,
        typer.Option(help="Address to bind the local port to."),
    ] = "127.0.0.1",
) -> None:
    """
    Start debugserver and print the LLDB connect string.

    - For iOS < 17, you must forward to a local port (--local-port).
    - For iOS >= 17, if connected over RSD, the remote host:port is printed for LLDB.
    Connect quickly with your own LLDB client using the printed steps.
    """

    if Version(service_provider.product_version) < Version("17.0"):
        service_name = "com.apple.debugserver.DVTSecureSocketProxy"
    else:
        service_name = DEBUGPROXY_SERVICE_NAME

    if local_port is not None:
        print(DEBUGSERVER_CONNECTION_STEPS.format(host=host, port=local_port))
        print("Started port forwarding. Press Ctrl-C to close this shell when done")
        sys.stdout.flush()
        await LockdownTcpForwarder(service_provider, local_port, service_name).start(address=host)
    elif Version(service_provider.product_version) >= Version("17.0"):
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            assert isinstance(service_provider, LockdownClient)  # non-RSD providers are lockdown clients
            raise RSDRequiredError(service_provider.identifier, service_provider.product_version)
        if service_provider.is_in_process_tunnel:
            raise RoutableTunnelRequiredError(
                "Cannot print a remote LLDB connect address over a userspace tunnel: the device "
                "address is only reachable from this process, not from your external lldb. Re-run "
                "with --local-port to forward debugserver to a local port (this works over the "
                "userspace tunnel), or use a kernel-routable tunnel (root `tunneld` / --tunnel)."
            )
        debugserver_port = service_provider.get_service_port(service_name)
        print(DEBUGSERVER_CONNECTION_STEPS.format(host=service_provider.service.address[0], port=debugserver_port))
    else:
        print("local_port is required for iOS < 17.0")
        raise typer.Exit(1)


@cli.command("lldb")
@async_command
async def debugserver_lldb(
    service_provider: RSDServiceProviderDep,
    project_or_ipa_or_bundle_id: Annotated[
        str,
        typer.Argument(help="Path to .xcodeproj/.ipa or an installed app bundle identifier"),
    ],
    configuration: Annotated[
        str,
        typer.Option(help="Build configuration to invoke (e.g., Debug or Release)."),
    ] = "Debug",
    lldb_command: Annotated[
        str,
        typer.Option(help="Path to the lldb executable to run."),
    ] = "lldb",
    launch: Annotated[
        bool,
        typer.Option(help="Automatically launch the app after attaching."),
    ] = False,
    breakpoints: Annotated[
        Optional[list[str]],
        typer.Option("--break", "-b", help="Add multiple startup breakpoints"),
    ] = None,
    user_commands: Annotated[
        Optional[list[str]],
        typer.Option("--command", "-c", help="Additional commands to run at startup"),
    ] = None,
) -> None:
    """
    Automate lldb launch for a given xcodeproj, IPA, or installed bundle identifier.

    \b
    This will:
    - Build the given xcodeproj (if provided)
    - Extract the given IPA (if provided)
    - Install it (for xcodeproj/IPA inputs)
    - Start a debugserver attached to it
    - Place breakpoints if given any
    - Launch the application if requested
    - Execute any additional commands if requested
    - Switch to lldb shell
    """
    if Version(service_provider.product_version) < Version("17.0"):
        logger.error("lldb is only supported on iOS >= 17.0")
        raise typer.Exit(1)

    commands: list[str] = []
    temp_dir = None
    local_app: Optional[Path] = None
    install_source: Optional[Path] = None
    bundle_identifier: Optional[str] = None
    bundle_mode_attach_pid: Optional[int] = None

    target = project_or_ipa_or_bundle_id.strip()
    target_path = Path(target).expanduser()

    if target_path.suffix == ".xcodeproj":
        if not target_path.exists():
            logger.error(f"xcodeproj not found: {target_path}")
            raise typer.Exit(1)
        project_dir = target_path.absolute().parent
        logger.info(f"Building {target_path} for {configuration} configuration")
        build = subprocess.run(
            ["xcodebuild", "-project", str(target_path.absolute()), "-configuration", configuration, "build"],
            cwd=project_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        if build.returncode != 0:
            # Quiet on success, but a failed build is only explained by xcodebuild's own output
            sys.stderr.write(build.stdout)
            logger.error(f"xcodebuild failed with exit status {build.returncode}")
            raise typer.Exit(1)
        app_candidates = [app for app in (project_dir / "build").rglob("*.app") if (app / "Info.plist").exists()]
        if not app_candidates:
            logger.error("No built .app with Info.plist found under build/.")
            raise typer.Exit(1)
        app_candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        local_app = app_candidates[0]
        install_source = local_app
    elif target_path.suffix == ".ipa":
        if not target_path.exists():
            logger.error(f"IPA not found: {target_path}")
            raise typer.Exit(1)
        temp_dir = TemporaryDirectory()
        with ZipFile(target_path, "r") as ipa_zip:
            ipa_zip.extractall(temp_dir.name)
        payload_dir = Path(temp_dir.name) / "Payload"
        apps = list(payload_dir.glob("*.app"))
        if not apps:
            logger.error("No .app bundle found in IPA Payload.")
            temp_dir.cleanup()
            raise typer.Exit(1)
        if len(apps) > 1:
            logger.error("Multiple .app bundles found in IPA Payload; please provide a single-app IPA.")
            temp_dir.cleanup()
            raise typer.Exit(1)
        local_app = apps[0].absolute()
        install_source = target_path
    else:
        bundle_identifier = target

    if local_app is not None:
        logger.info(f"Using app: {local_app}")
        info_plist_path = local_app / "Info.plist"
        info_plist = plistlib.loads(info_plist_path.read_bytes())
        bundle_identifier = info_plist["CFBundleIdentifier"]

    logger.info(f"Bundle identifier: {bundle_identifier}")
    assert bundle_identifier is not None  # every non-returning branch above assigns it

    commands.append("platform select remote-ios")

    async with InstallationProxyService(lockdown=service_provider) as installation_proxy:
        if install_source is not None:
            logger.info("Installing app")
            await installation_proxy.install_from_local(install_source)

        apps = await installation_proxy.get_apps(bundle_identifiers=[bundle_identifier])
        if bundle_identifier not in apps:
            logger.error(f"App with bundle identifier '{bundle_identifier}' is not installed on the device")
            raise typer.Exit(1)

        remote_path = apps[bundle_identifier]["Path"]
        logger.info(f"Remote path: {remote_path}")
        if local_app is not None:
            commands.append(f'target create "{local_app.absolute()}"')
            commands.append(f'script lldb.target.module[0].SetPlatformFileSpec(lldb.SBFileSpec("{remote_path}"))')

    if local_app is None:
        async with DvtProvider(service_provider) as dvt, ProcessControl(dvt) as process_control:
            bundle_mode_attach_pid = await process_control.process_identifier_for_bundle_identifier(bundle_identifier)
            if bundle_mode_attach_pid <= 0:
                logger.info("App is not running; launching suspended for debugger attach")
                bundle_mode_attach_pid = await process_control.launch(
                    bundle_id=bundle_identifier, kill_existing=False, start_suspended=True
                )
            logger.info(f"Attaching to pid {bundle_mode_attach_pid}")

    try:
        # lldb is an external process, so it cannot reach an in-process (userspace) tunnel address.
        # Forwarding debugproxy to a loopback port works the same over every transport.
        async with _forward_debugproxy(service_provider) as local_port:
            # Add connection and launch commands
            commands.append(f"process connect connect://127.0.0.1:{local_port}")
            if bundle_mode_attach_pid is not None:
                commands.append(f"process attach --pid {bundle_mode_attach_pid}")

            if breakpoints:
                for bp in breakpoints:
                    commands.append(f'breakpoint set -n "{bp}"')

            if launch and local_app is not None:
                commands.append("process launch")
            elif launch:
                # Attaching stops the process, whether we launched it suspended or it was already running
                commands.append("process continue")

            if user_commands:
                # Add user commands
                commands += user_commands

            logger.info("Starting lldb with automated setup and connection")
            await _run_lldb(lldb_command, commands)
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


@asynccontextmanager
async def _forward_debugproxy(service_provider: LockdownServiceProvider) -> AsyncGenerator[int, None]:
    """Forward debugproxy to an ephemeral loopback port for the lifetime of the context."""
    listening = asyncio.Event()
    forwarder = LockdownTcpForwarder(service_provider, 0, DEBUGPROXY_SERVICE_NAME, listening_event=listening)
    forwarder_task = asyncio.create_task(forwarder.start())
    listening_task = asyncio.create_task(listening.wait())
    try:
        await asyncio.wait({forwarder_task, listening_task}, return_when=asyncio.FIRST_COMPLETED)
        if not listening.is_set():
            # The listener failed to bind; surface its error
            forwarder_task.result()
        port = forwarder.listening_port
        assert port is not None  # set once the listener is up
        yield port
    finally:
        listening_task.cancel()
        forwarder.stop()
        await asyncio.gather(forwarder_task, return_exceptions=True)


async def _run_lldb(lldb_command: str, commands: list[str]) -> None:
    """Run lldb on a pty, feed it the setup commands, then hand the terminal over to the user."""
    # Works only on unix-based systems, so keep these imports here
    import fcntl
    import pty
    import termios
    import tty

    loop = asyncio.get_running_loop()
    master, slave = pty.openpty()

    process = None  # Initialize process variable for signal handler

    # Copy terminal size from the current terminal to PTY
    def resize_pty() -> None:
        """Update PTY size to match current terminal size"""
        size = struct.unpack(
            "HHHH", fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0))
        )
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", *size))
        # Send SIGWINCH to the child process to notify it of the resize
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGWINCH)

    # Initial resize
    resize_pty()

    # Set up signal handler for window resize
    loop.add_signal_handler(signal.SIGWINCH, resize_pty)

    # Save original terminal settings
    old_tty = termios.tcgetattr(sys.stdin)

    try:
        # Set TERM environment variable to enable colors
        env = os.environ.copy()
        env["TERM"] = os.environ.get("TERM", "xterm-256color")

        process = subprocess.Popen([lldb_command], stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)

        # Put terminal in raw mode for proper interaction
        tty.setraw(sys.stdin.fileno())
        # Send all commands through stdin
        for command in commands:
            os.write(master, (command + "\n").encode())

        # Now redirect stdin from the terminal to lldb so user can interact. Relay on the event loop
        # so the debugproxy forwarder keeps running alongside.
        done = loop.create_future()

        def finish() -> None:
            if not done.done():
                done.set_result(None)

        def relay(src: int, dst: int) -> None:
            try:
                data = os.read(src, 1024)
            except OSError:
                data = b""
            if not data:
                finish()
                return
            os.write(dst, data)

        loop.add_reader(sys.stdin.fileno(), relay, sys.stdin.fileno(), master)
        loop.add_reader(master, relay, master, sys.stdout.fileno())
        try:
            await done
        finally:
            loop.remove_reader(sys.stdin.fileno())
            loop.remove_reader(master)
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        # Restore terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
        loop.remove_signal_handler(signal.SIGWINCH)
        os.close(master)
        if process is not None:
            process.terminate()
            process.wait()
