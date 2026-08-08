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
