import re
import subprocess
import sys

import pytest
import typer
from typer.core import TyperGroup
from typer.testing import CliRunner

from pymobiledevice3 import __main__

pytestmark = [pytest.mark.cli]
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def test_cli_main_interface():
    # No-argument behavior is covered by test_cli_from_python_m_without_args, which
    # exercises the real entry point; invoking the Typer app directly without
    # arguments behaves inconsistently across click versions
    runner = CliRunner()
    result = runner.invoke(__main__.app, ["--help"])
    assert result.exit_code == 0


def test_cli_from_python_m_without_args():
    result = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "NoArgsIsHelpError" not in result.stderr


def test_mutually_exclusive_rsd_tunnel_renders_usage_error():
    # Regression: raising real click's UsageError under typer's vendored click (typer >= 0.20)
    # escaped the CLI as a raw traceback instead of a usage error; ctx.fail() must be used instead
    runner = CliRunner()
    result = runner.invoke(
        __main__.app,
        ["developer", "dvt", "ls", "/", "--rsd", "1.2.3.4", "1234", "--tunnel", "x"],
    )

    assert result.exit_code == 2
    assert "mutually exclusive with --tunnel" in ANSI_ESCAPE.sub("", result.output)
    assert "Traceback" not in result.output


def test_cli_from_python_m_with_invalid_option():
    result = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3", "--definitely-invalid"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "No such option: --definitely-invalid" in ANSI_ESCAPE.sub("", result.stderr)
    assert "Traceback" not in result.stderr


def test_install_completion_uses_fish_for_xonsh_when_available(monkeypatch, tmp_path):
    monkeypatch.setattr(__main__, "_ORIGINAL_SHELLINGHAM_DETECT", lambda: ("xonsh", "/bin/xonsh"))
    monkeypatch.setattr(__main__.shutil, "which", lambda command: "/usr/bin/fish" if command == "fish" else None)

    result = CliRunner().invoke(
        __main__.app,
        ["--install-completion"],
        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)},
        prog_name="pymobiledevice3",
    )

    assert result.exit_code == 0, result.output
    assert "fish completion installed" in result.output

    completion_path = tmp_path / ".config" / "fish" / "completions" / "pymobiledevice3.fish"
    assert completion_path.is_file()
    assert "_PYMOBILEDEVICE3_COMPLETE=complete_fish" in completion_path.read_text()


def test_install_completion_falls_back_to_bash_for_xonsh(monkeypatch, tmp_path):
    monkeypatch.setattr(__main__, "_ORIGINAL_SHELLINGHAM_DETECT", lambda: ("xonsh", "/bin/xonsh"))
    monkeypatch.setattr(__main__.shutil, "which", lambda command: None)

    result = CliRunner().invoke(
        __main__.app,
        ["--install-completion"],
        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)},
        prog_name="pymobiledevice3",
    )

    assert result.exit_code == 0, result.output
    assert "bash completion installed" in result.output

    completion_path = tmp_path / ".bash_completions" / "pymobiledevice3.sh"
    assert completion_path.is_file()
    assert "_PYMOBILEDEVICE3_COMPLETE=complete_bash" in completion_path.read_text()
    assert f"source '{completion_path}'" in (tmp_path / ".bashrc").read_text()


@pytest.mark.parametrize(
    "keyword,suggestions",
    [
        ("kill", ["developer dvt kill", "developer dvt pkill"]),
        ("sysdi", ["crash sysdiagnose"]),
        (
            "shell",
            [
                "afc shell",
                "crash shell",
                "developer accessibility shell",
                "developer dvt shell",
                "developer shell",
                "restore shell",
                "springboard shell",
                "webinspector js-shell",
                "webinspector shell",
            ],
        ),
        (
            "shall",
            [
                "afc shell",
                "crash pull",
                "crash shell",
                "apps install",
                "crash ls",
                "afc pull",
                "restore shell",
                "apps uninstall",
                "profile install",
                "developer shell",
            ],
        ),
    ],
)
def test_cli_suggestions(keyword, suggestions):
    output = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3", keyword],
        capture_output=True,
        text=True,
    )
    for suggestion in suggestions:
        assert suggestion in output.stderr


def test_suggestion_index_matches_runtime_command_tree():
    """Every "Did you mean" suggestion must be invocable exactly as printed.

    Single-command groups without a callback (btlogger, pcap, power-assertion,
    version) are collapsed by Typer at runtime, so they must be indexed under
    their group name alone — not as phantom paths like "btlogger capture".
    """
    root = typer.main.get_command(__main__.app)
    suggestions = __main__.Pmd3TyperGroup.load_all_commands()

    for collapsed in ("btlogger", "pcap", "power-assertion", "version"):
        assert collapsed in suggestions

    for suggestion in suggestions:
        tokens = suggestion.split(" ")
        assert tokens[0] in __main__.CLI_GROUPS, f"{suggestion!r} does not start with a top-level command"
        command = root
        for token in tokens:
            assert isinstance(command, TyperGroup), f"{suggestion!r}: {token!r} is not reachable at runtime"
            command = command.get_command(None, token)  # pyright: ignore[reportArgumentType]
            assert command is not None, f"{suggestion!r}: {token!r} is not reachable at runtime"


@pytest.mark.parametrize("group", __main__.CLI_GROUPS.keys())
def test_top_level_command_is_named_after_its_dispatch_key(group):
    """The rich help panel shows each resolved command's click name, so it must
    match the CLI_GROUPS key it is dispatched by. A collapsed single-command
    module would otherwise be listed under its inner command name (e.g.
    "capture"), which `pymobiledevice3 capture` cannot actually invoke."""
    root = typer.main.get_command(__main__.app)
    assert isinstance(root, TyperGroup)
    command = root.get_command(None, group)  # pyright: ignore[reportArgumentType]
    assert command is not None
    assert command.name == group


@pytest.mark.parametrize("group", __main__.CLI_GROUPS.keys())
def test_cli_groups(group):
    runner = CliRunner()
    group_help_result = runner.invoke(__main__.app, [group, "--help"])
    assert group_help_result.exit_code == 0


@pytest.mark.parametrize("group", __main__.CLI_GROUPS.keys())
def test_cli_from_python_m_flag(group):
    subprocess.run([sys.executable, "-m", "pymobiledevice3", group, "--help"], check=True)


def _patch_isolated_asyncio_run(monkeypatch):
    """``main()`` uses ``asyncio.run``, whose cleanup unsets the main-thread event loop and breaks
    later sync tests on Python 3.9 (``asyncio.Lock()`` there binds ``get_event_loop()`` at creation).
    Run coroutines on a private loop instead, leaving global loop state untouched."""
    import asyncio

    def isolated_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr(asyncio, "run", isolated_run)


def test_reconnect_waits_for_the_target_device(monkeypatch):
    """`--reconnect` must wait for the device the command targeted (--udid), not just any device."""
    _patch_isolated_asyncio_run(monkeypatch)
    captured: dict[str, str] = {}

    async def fake_retry_create_using_usbmux(*args, **kwargs):
        captured.update(kwargs)

        class _FakeLockdown:
            async def close(self) -> None:
                pass

        return _FakeLockdown()

    invocations = iter([True, False])
    monkeypatch.setattr(__main__, "invoke_cli_with_error_handling", lambda: next(invocations))
    monkeypatch.setattr(__main__, "RECONNECT", True)
    monkeypatch.setattr(__main__, "retry_create_using_usbmux", fake_retry_create_using_usbmux)
    monkeypatch.setattr(sys, "argv", ["pymobiledevice3", "--reconnect", "afc", "webdav", "--udid", "TARGET-UDID"])

    __main__.main()

    assert captured.get("serial") == "TARGET-UDID"


def test_device_not_found_is_a_reconnectable_failure(monkeypatch):
    """A device-not-found failure must keep the `--reconnect` retry loop alive: after a disconnect,
    the target device may still be enumerating while other devices are attached."""
    from pymobiledevice3.exceptions import DeviceNotFoundError

    def raise_not_found(*args, **kwargs):
        raise DeviceNotFoundError("TARGET-UDID")

    monkeypatch.setattr(__main__, "app", raise_not_found)
    assert __main__.invoke_cli_with_error_handling() is True


def test_tunneld_device_not_found_names_the_tunneld_instance(monkeypatch):
    """The tunneld lookup must say which tunneld was queried, on top of the `udid` member."""
    import asyncio

    from pymobiledevice3.cli import cli_common
    from pymobiledevice3.exceptions import DeviceNotFoundError

    class _FakeRsd:
        udid = "OTHER-UDID"

        async def close(self):
            pass

    async def fake_get_tunneld_devices(address, bridge=None):
        return [_FakeRsd()]

    monkeypatch.setattr(cli_common, "get_tunneld_devices", fake_get_tunneld_devices)

    # A private loop, not asyncio.run: its cleanup unsets the main-thread event loop and breaks
    # later sync tests on Python 3.9 (see _patch_isolated_asyncio_run above).
    loop = asyncio.new_event_loop()
    try:
        with pytest.raises(DeviceNotFoundError) as exc_info:
            loop.run_until_complete(cli_common._tunneld("TARGET-UDID:1234"))
    finally:
        loop.close()

    assert exc_info.value.udid == "TARGET-UDID"
    assert str(exc_info.value) == ("Device not found: tunneld (127.0.0.1:1234) serves no tunnel for udid TARGET-UDID")


def test_native_tunnel_device_not_found_is_reconnectable(monkeypatch):
    """The native tunnel's "no such device" error is both a DeviceNotFoundError and a native-path
    failure; it must be handled as the former (reconnectable, keeps its explanatory message)."""
    from pymobiledevice3.remote.native_tunnel import _RemotePairingDeviceNotFoundError

    def raise_not_found(*args, **kwargs):
        raise _RemotePairingDeviceNotFoundError(
            "X", "Device not found: remotepairingd reported no device matching udid X"
        )

    monkeypatch.setattr(__main__, "app", raise_not_found)
    assert __main__.invoke_cli_with_error_handling() is True


def test_reconnect_reuses_interactively_selected_device(monkeypatch):
    """When the device was chosen at the interactive prompt (no --udid on argv/env), `--reconnect`
    must wait for and re-target that same device, not whichever device appears first."""
    import os

    from pymobiledevice3.cli import cli_common

    _patch_isolated_asyncio_run(monkeypatch)

    captured: dict[str, str] = {}

    async def fake_retry_create_using_usbmux(*args, **kwargs):
        captured.update(kwargs)

        class _FakeLockdown:
            async def close(self) -> None:
                pass

        return _FakeLockdown()

    invocations = iter([True, False])
    monkeypatch.setattr(__main__, "invoke_cli_with_error_handling", lambda: next(invocations))
    monkeypatch.setattr(__main__, "RECONNECT", True)
    monkeypatch.setattr(__main__, "retry_create_using_usbmux", fake_retry_create_using_usbmux)
    monkeypatch.setattr(sys, "argv", ["pymobiledevice3", "--reconnect", "afc", "webdav"])
    monkeypatch.setattr(os, "environ", dict(os.environ))  # isolate env mutations done by main()
    os.environ.pop(cli_common.UDID_ENV_VAR, None)
    monkeypatch.setattr(cli_common, "_resolved_udid", "PROMPTED-UDID")  # as recorded on dependency resolution

    __main__.main()

    assert captured.get("serial") == "PROMPTED-UDID"
    # Stamped so the re-invocation resolves the same device instead of prompting/auto-picking.
    assert os.environ[cli_common.UDID_ENV_VAR] == "PROMPTED-UDID"


def test_service_provider_dependency_records_resolved_udid(monkeypatch):
    """Dependency resolution must record which device it picked, for `--reconnect` to reuse."""
    from pymobiledevice3.cli import cli_common

    class _FakeProvider:
        udid = "RESOLVED-UDID"

    async def fake_create_using_usbmux(*args, **kwargs):
        return _FakeProvider()

    monkeypatch.setattr(cli_common, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(cli_common, "_resolved_udid", None)

    provider = cli_common.any_service_provider_dependency(
        rsd_service_provider=None, mobdev2=False, usbmux=None, udid="RESOLVED-UDID"
    )

    assert provider is not None
    assert cli_common.resolved_udid() == "RESOLVED-UDID"


@pytest.mark.parametrize("command", ["wifi-connections", "assistive-touch"])
def test_lockdown_on_off_state_is_a_positional_argument(command):
    """Regression: the Typer migration turned these `on`/`off` arguments into a `--state` option."""
    runner = CliRunner()
    result = runner.invoke(__main__.app, ["lockdown", command, "--help"])

    assert result.exit_code == 0
    # Rich interleaves ANSI codes inside option names and wraps text in panel borders
    output = " ".join(ANSI_ESCAPE.sub("", result.output).replace("│", " ").split())
    assert "Arguments" in output
    assert "--state" not in output
