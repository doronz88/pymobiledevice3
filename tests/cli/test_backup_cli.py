import json
import plistlib
import sqlite3
from contextlib import closing

from typer.testing import CliRunner

from pymobiledevice3 import __main__


def create_complete_backup(tmp_path):
    source = "test-source"
    device_directory = tmp_path / source
    device_directory.mkdir()
    (device_directory / "Info.plist").write_bytes(plistlib.dumps({"Product Type": "iPhone1,1"}))
    (device_directory / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False, "Version": "10.0"}))
    (device_directory / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
    with closing(sqlite3.connect(device_directory / "Manifest.db")) as connection:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
        connection.execute(
            "INSERT INTO Files (fileID, domain, relativePath) VALUES (?, ?, ?)",
            ("file-1", "HomeDomain", "Library/SMS/sms.db"),
        )
        connection.commit()
    return source


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


def test_backup_command_has_verify_subcommand():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "verify", "--help"])

    assert result.exit_code == 0
    assert "Validate local backup metadata" in result.output


def test_backup_verify_outputs_validation_summary(tmp_path):
    source = create_complete_backup(tmp_path)
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "verify", "--source", source, str(tmp_path)])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["complete"] is True
    assert output["source"] == source
    assert output["manifest_file_count"] == 1
    assert output["required_file_sizes"]["Manifest.db"] > 0


def test_backup_verify_reports_incomplete_backup_without_traceback(tmp_path):
    source = "test-source"
    device_directory = tmp_path / source
    device_directory.mkdir()
    (device_directory / "Info.plist").write_bytes(plistlib.dumps({}))
    (device_directory / "Manifest.plist").write_bytes(b"")
    (device_directory / "Status.plist").write_bytes(plistlib.dumps({}))
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "verify", "--source", source, str(tmp_path)])

    assert result.exit_code == 1
    assert "Error: Incomplete backup" in result.output
    assert "Manifest.plist is empty" in result.output
    assert "Traceback" not in result.output
