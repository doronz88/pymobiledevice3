import pytest
import typer
from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli.backup import validate_backup_filter_options


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


def test_backup_command_has_patch_manifest_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--patch-manifest" in result.output


def test_filtered_unback_requires_patched_manifest():
    with pytest.raises(typer.BadParameter, match="requires --patch-manifest"):
        validate_backup_filter_options(filtered=True, patch_manifest=False, unback=True)


def test_unback_accepts_unfiltered_or_patched_backup():
    validate_backup_filter_options(filtered=False, patch_manifest=False, unback=True)
    validate_backup_filter_options(filtered=True, patch_manifest=True, unback=True)


def test_backup_command_offers_messages_selection():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "messages" in result.output


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
