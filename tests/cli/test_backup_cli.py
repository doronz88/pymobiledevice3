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


def test_backup_command_has_unback_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--unback" in result.output


def test_backup_full_help_describes_conditional_default():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    # Rich wraps the help text inside panel borders, so strip the box-drawing
    # characters before joining lines back into a single string
    normalized_output = " ".join(result.output.replace("│", " ").split())
    assert "incremental" in normalized_output
    assert "valid local metadata exists" in normalized_output
    assert "full for an" in normalized_output
    assert "empty or incomplete backup" in normalized_output
    assert "directory" in normalized_output
