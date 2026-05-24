from typer.testing import CliRunner

from pymobiledevice3 import __main__


def test_backup_only_regex_invalid_pattern(tmp_path):
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--only-regex", "[", str(tmp_path)])

    assert result.exit_code != 0
    assert "Invalid value for '--only-regex'" in result.output
    assert "Invalid regex pattern '['" in result.output


def test_backup_command_has_password_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--password" in result.output
