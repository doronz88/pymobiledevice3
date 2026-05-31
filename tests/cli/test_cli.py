import re
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from pymobiledevice3 import __main__

pytestmark = [pytest.mark.cli]
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@pytest.mark.xfail(reason="Looks like click broke something")
def test_cli_main_interface():
    runner = CliRunner()
    r1 = runner.invoke(__main__.app, ["--help"])
    assert r1.exit_code == 0

    r2 = runner.invoke(__main__.app)
    assert r2.exit_code == 0


def test_cli_from_python_m_without_args():
    result = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "NoArgsIsHelpError" not in result.stderr


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


@pytest.mark.parametrize("group", __main__.CLI_GROUPS.keys())
def test_cli_groups(group):
    runner = CliRunner()
    group_help_result = runner.invoke(__main__.app, [group, "--help"])
    assert group_help_result.exit_code == 0


@pytest.mark.parametrize("group", __main__.CLI_GROUPS.keys())
def test_cli_from_python_m_flag(group):
    subprocess.run([sys.executable, "-m", "pymobiledevice3", group, "--help"], check=True)
