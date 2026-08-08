import re

import pytest
import typer
from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli.backup import validate_backup_filter_options

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def plain_cli_output(output: str) -> str:
    """Return CLI output as plain text suitable for substring assertions.

    On GitHub Actions typer forces rich terminal rendering, which interleaves ANSI
    style codes even inside option names (``--password`` renders as ``-`` and
    ``-password`` in separate style spans), and rich wraps text inside panel borders.
    Strip the styling and borders and collapse whitespace so assertions see the words.
    """
    return " ".join(ANSI_ESCAPE.sub("", output).replace("│", " ").split())


def test_backup_only_regex_invalid_pattern(tmp_path):
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--only-regex", "[", str(tmp_path)])

    assert result.exit_code != 0
    output = plain_cli_output(result.output)
    assert "Invalid value for '--only-regex'" in output
    assert "Invalid regex pattern '['" in output


def test_backup_command_has_password_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--password" in plain_cli_output(result.output)


def test_backup_command_has_unback_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--unback" in plain_cli_output(result.output)


def test_backup_command_has_patch_manifest_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--patch-manifest" in plain_cli_output(result.output)


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
    assert "messages" in plain_cli_output(result.output)


def test_encryption_mode_without_password_fails_with_usage_error():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "encryption", "on"])

    assert result.exit_code != 0
    assert "PASSWORD is required" in plain_cli_output(result.output)


def test_encryption_help_documents_no_args_state_query():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "encryption", "--help"])

    assert result.exit_code == 0
    assert "current encryption state" in plain_cli_output(result.output)


def test_backup_full_help_describes_conditional_default():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    normalized_output = plain_cli_output(result.output)
    assert "incremental" in normalized_output
    assert "valid local metadata exists" in normalized_output
    assert "full for an" in normalized_output
    assert "empty or incomplete backup" in normalized_output
    assert "directory" in normalized_output
