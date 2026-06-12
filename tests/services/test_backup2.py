import plistlib
import sqlite3
import struct
import time
from contextlib import closing
from pathlib import Path
from ssl import SSLEOFError
from unittest.mock import AsyncMock, Mock, call

import pytest

from pymobiledevice3.exceptions import BackupValidationError, ConnectionFailedError, ConnectionTerminatedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.services.mobilebackup2 import (
    BACKUP_OBSERVED_NOTIFICATIONS,
    BACKUP_SELECTIONS,
    NP_LOCAL_AUTH_DISMISSED,
    NP_LOCAL_AUTH_PRESENTED,
    NP_SYNC_CANCEL_REQUEST,
    BackupFile,
    Mobilebackup2Service,
)

PASSWORD = "1234"
BACKUP_SOURCE = "test-source"


def create_test_backup(backup_directory: Path, source: str = BACKUP_SOURCE, encrypted: bool = False) -> Path:
    device_directory = backup_directory / source
    device_directory.mkdir()
    (device_directory / "Info.plist").write_bytes(
        plistlib.dumps({
            "Build Version": "23A000",
            "Product Type": "iPhone1,1",
            "Product Version": "1.0",
            "Target Type": "Device",
            "iTunes Version": "10.0.1",
        })
    )
    (device_directory / "Manifest.plist").write_bytes(
        plistlib.dumps({
            "Date": "2026-01-01T00:00:00Z",
            "IsEncrypted": encrypted,
            "Version": "10.0",
        })
    )
    (device_directory / "Status.plist").write_bytes(
        plistlib.dumps({
            "BackupState": "new",
            "IsFullBackup": True,
            "SnapshotState": "finished",
            "Version": "3.3",
        })
    )
    manifest_db = device_directory / "Manifest.db"
    if encrypted:
        manifest_db.write_bytes(b"encrypted manifest db")
    else:
        with closing(sqlite3.connect(manifest_db)) as connection:
            connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
            connection.executemany(
                "INSERT INTO Files (fileID, domain, relativePath) VALUES (?, ?, ?)",
                [
                    ("file-1", "HomeDomain", "Library/SMS/sms.db"),
                    ("file-2", "HomeDomain", "Library/Safari/Bookmarks.db"),
                ],
            )
            connection.commit()
    return device_directory


def ignore_connection_errors(f):
    """
    The device may become unresponsive for a short while after changing the password settings and reject
    incoming connections at different stages
    """

    async def _wrapper(*args, **kwargs):
        while True:
            try:
                await f(*args, **kwargs)
                break
            except (
                SSLEOFError,
                ConnectionTerminatedError,
                OSError,
                ConnectionFailedError,
            ):
                time.sleep(1)

    return _wrapper


@ignore_connection_errors
async def change_password(lockdown: LockdownClient, old: str = "", new: str = "") -> None:
    async with Mobilebackup2Service(lockdown) as service:
        await service.change_password(old=old, new=new)


@ignore_connection_errors
async def backup(lockdown: LockdownClient, backup_directory: Path) -> None:
    async with Mobilebackup2Service(lockdown) as service:
        await service.backup(full=True, backup_directory=backup_directory)


@pytest.mark.filterwarnings("ignore::UserWarning")
@pytest.mark.asyncio
async def test_backup(lockdown: LockdownClient, tmp_path: Path) -> None:
    await backup(lockdown, tmp_path)


@pytest.mark.filterwarnings("ignore::UserWarning")
@pytest.mark.asyncio
async def test_encrypted_backup(lockdown: LockdownClient, tmp_path: Path) -> None:
    await change_password(lockdown, new=PASSWORD)
    await backup(lockdown, tmp_path)
    await change_password(lockdown, old=PASSWORD)


def test_resolve_backup_selection_sms() -> None:
    rules = Mobilebackup2Service.resolve_backup_selection(["sms"])

    assert len(rules) == 1
    assert rules[0].matches_device_name("HomeDomain/Library/SMS/sms.db")
    assert rules[0].matches_device_name("HomeDomain-Library/SMS/sms.db")
    assert rules[0].matches_device_name("/.b/6/Library/SMS/sms.db")


def test_backup_selection_presets_include_contacts_call_history_and_bookmarks() -> None:
    assert {"contacts", "call_history", "bookmarks"} <= set(BACKUP_SELECTIONS)


def test_regex_filter_callback_matches_upload_and_manifest_forms() -> None:
    callback = Mobilebackup2Service.regex_filter_callback([r"\.(plist|db|db-wal|sqlitedb)$"])

    assert callback(BackupFile(device_name="HomeDomain-Library/Preferences/com.apple.PeoplePicker.plist"))
    assert callback(BackupFile(device_name="HomeDomain-Library/SMS/sms.db"))
    assert callback(BackupFile(domain="HomeDomain", relative_path="Library/Safari/Bookmarks.db-wal"))
    assert callback(BackupFile(domain="HomeDomain", relative_path="Library/AddressBook/AddressBook.sqlitedb"))
    assert not callback(BackupFile(domain="HomeDomain", relative_path="Library/Notes/NotesV7.store"))


def test_combine_filter_callbacks_matches_when_any_callback_matches() -> None:
    preset_callback = Mobilebackup2Service.selection_filter_callback(
        Mobilebackup2Service.resolve_backup_selection(["sms"])
    )
    regex_callback = Mobilebackup2Service.regex_filter_callback([r"\.plist$"])
    callback = Mobilebackup2Service.combine_filter_callbacks(preset_callback, regex_callback)

    assert callback is not None
    assert callback(BackupFile(device_name="HomeDomain-Library/SMS/sms.db"))
    assert callback(BackupFile(device_name="HomeDomain-Library/Preferences/com.apple.Preferences.plist"))
    assert not callback(BackupFile(device_name="HomeDomain-Library/Notes/NotesV7.store"))


def test_selection_filter_callback_matches_upload_and_manifest_forms() -> None:
    callback = Mobilebackup2Service.selection_filter_callback(Mobilebackup2Service.resolve_backup_selection(["sms"]))

    assert callback(BackupFile(device_name="/.b/6/Library/SMS/sms.db"))
    assert callback(BackupFile(domain="HomeDomain", relative_path="Library/SMS/sms.db"))
    assert not callback(BackupFile(domain="HomeDomain", relative_path="Library/Notes/notes.sqlite"))


def test_should_preserve_backup_file_keeps_metadata() -> None:
    assert Mobilebackup2Service.should_preserve_backup_file("Manifest.db", "ignored", None)


def test_resolve_backup_source_uses_single_backup_directory(tmp_path: Path) -> None:
    create_test_backup(tmp_path)

    assert Mobilebackup2Service.resolve_backup_source(tmp_path) == BACKUP_SOURCE


def test_resolve_backup_source_requires_source_for_multiple_backups(tmp_path: Path) -> None:
    create_test_backup(tmp_path)
    create_test_backup(tmp_path, source="second-source")

    with pytest.raises(BackupValidationError, match="Pass --source"):
        Mobilebackup2Service.resolve_backup_source(tmp_path)


def test_resolve_backup_source_reports_missing_backup_directory(tmp_path: Path) -> None:
    with pytest.raises(BackupValidationError, match="does not exist"):
        Mobilebackup2Service.resolve_backup_source(tmp_path / "missing")


def test_validate_backup_accepts_complete_unencrypted_backup(tmp_path: Path) -> None:
    create_test_backup(tmp_path)

    result = Mobilebackup2Service.validate_backup(tmp_path, BACKUP_SOURCE, include_file_summary=True)

    assert result.identifier == BACKUP_SOURCE
    assert result.is_encrypted is False
    assert result.manifest_file_count == 2
    assert result.filesystem_file_count == 4
    assert result.filesystem_size
    assert result.required_file_sizes["Manifest.db"] > 0
    assert result.to_dict()["complete"] is True


def test_validate_backup_accepts_encrypted_manifest_db_without_sqlite_parse(tmp_path: Path) -> None:
    create_test_backup(tmp_path, encrypted=True)

    result = Mobilebackup2Service.validate_backup(tmp_path, BACKUP_SOURCE)

    assert result.is_encrypted is True
    assert result.manifest_file_count is None


def test_validate_backup_reports_missing_metadata(tmp_path: Path) -> None:
    (tmp_path / BACKUP_SOURCE).mkdir()

    with pytest.raises(BackupValidationError, match=r"Info\.plist is missing"):
        Mobilebackup2Service.validate_backup(tmp_path, BACKUP_SOURCE)


def test_validate_backup_reports_empty_manifest_plist(tmp_path: Path) -> None:
    device_directory = create_test_backup(tmp_path)
    (device_directory / "Manifest.plist").write_bytes(b"")

    with pytest.raises(BackupValidationError, match=r"Manifest\.plist is empty"):
        Mobilebackup2Service.validate_backup(tmp_path, BACKUP_SOURCE)


def test_validate_backup_reports_invalid_manifest_db(tmp_path: Path) -> None:
    device_directory = create_test_backup(tmp_path)
    (device_directory / "Manifest.db").write_bytes(b"not sqlite")

    with pytest.raises(BackupValidationError, match=r"Manifest\.db is not a readable"):
        Mobilebackup2Service.validate_backup(tmp_path, BACKUP_SOURCE)


@pytest.mark.asyncio
async def test_observe_backup_notifications_registers_passcode_and_backup_notifications() -> None:
    notification_proxy = Mock()
    notification_proxy.notify_register_dispatch = AsyncMock()

    service = object.__new__(Mobilebackup2Service)
    await service._observe_backup_notifications(notification_proxy)

    notification_proxy.notify_register_dispatch.assert_has_awaits([
        call(notification) for notification in BACKUP_OBSERVED_NOTIFICATIONS
    ])


def test_log_backup_notification_surfaces_passcode_prompt_to_operator() -> None:
    service = object.__new__(Mobilebackup2Service)
    service.logger = Mock()

    service._log_backup_notification({"Name": NP_LOCAL_AUTH_PRESENTED})
    service._log_backup_notification({"Name": NP_LOCAL_AUTH_DISMISSED})
    service._log_backup_notification({"Name": NP_SYNC_CANCEL_REQUEST})

    service.logger.warning.assert_any_call("Please enter the device passcode to continue the backup")
    service.logger.info.assert_called_once_with("Device passcode prompt dismissed")
    service.logger.warning.assert_any_call("User has cancelled the backup process on the device")


def test_unback_with_pyiosbackup_replaces_existing_output(monkeypatch, tmp_path: Path) -> None:
    device_directory = tmp_path / "device"
    output_directory = tmp_path / "device.unback"
    device_directory.mkdir()
    output_directory.mkdir()
    (output_directory / "stale").write_text("old")
    observed = {}

    class FakeBackup:
        def unback(self, path):
            observed["path"] = Path(path)
            (Path(path) / "fresh").write_text("new")

    class FakeBackupFactory:
        @staticmethod
        def from_path(path, password=""):
            observed["backup_path"] = path
            observed["password"] = password
            return FakeBackup()

    monkeypatch.setattr("pymobiledevice3.services.mobilebackup2.Backup", FakeBackupFactory)

    result = Mobilebackup2Service.unback_with_pyiosbackup(device_directory, password=PASSWORD)

    assert result == output_directory
    assert observed == {
        "backup_path": device_directory,
        "password": PASSWORD,
        "path": output_directory,
    }
    assert not (output_directory / "stale").exists()
    assert (output_directory / "fresh").read_text() == "new"


def test_prune_backup_directory_keeps_only_selected_files(tmp_path: Path) -> None:
    device_directory = tmp_path / "device"
    device_directory.mkdir()
    manifest_db = device_directory / "Manifest.db"

    with closing(sqlite3.connect(manifest_db)) as connection:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
        connection.executemany(
            "INSERT INTO Files (fileID, domain, relativePath) VALUES (?, ?, ?)",
            [
                ("keep-sms", "HomeDomain", "Library/SMS/sms.db"),
                ("drop-notes", "HomeDomain", "Library/Notes/notes.sqlite"),
            ],
        )
        connection.commit()

    (device_directory / "Info.plist").write_text("")
    (device_directory / "Manifest.plist").write_text("")
    (device_directory / "Status.plist").write_text("")
    (device_directory / "keep-sms").write_text("sms")
    (device_directory / "drop-notes").write_text("notes")

    Mobilebackup2Service.prune_backup_directory(
        device_directory,
        Mobilebackup2Service.selection_filter_callback(Mobilebackup2Service.resolve_backup_selection(["sms"])),
    )

    with closing(sqlite3.connect(manifest_db)) as connection:
        rows = connection.execute("SELECT fileID, domain, relativePath FROM Files").fetchall()

    assert rows == [("keep-sms", "HomeDomain", "Library/SMS/sms.db")]
    assert (device_directory / "keep-sms").exists()
    assert not (device_directory / "drop-notes").exists()
    assert (device_directory / "Manifest.db").exists()


def test_prune_backup_directory_keeps_hashed_backup_file_layout(tmp_path: Path) -> None:
    device_directory = tmp_path / "device"
    device_directory.mkdir()
    manifest_db = device_directory / "Manifest.db"
    keep_file_id = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"
    drop_file_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    with closing(sqlite3.connect(manifest_db)) as connection:
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)")
        connection.executemany(
            "INSERT INTO Files (fileID, domain, relativePath) VALUES (?, ?, ?)",
            [
                (keep_file_id, "HomeDomain", "Library/SMS/sms.db"),
                (drop_file_id, "HomeDomain", "Library/Notes/notes.sqlite"),
            ],
        )
        connection.commit()

    (device_directory / "Info.plist").write_text("")
    (device_directory / "Manifest.plist").write_text("")
    (device_directory / "Status.plist").write_text("")
    keep_path = device_directory / keep_file_id[:2] / keep_file_id
    keep_path.parent.mkdir()
    keep_path.write_text("sms")
    drop_path = device_directory / drop_file_id[:2] / drop_file_id
    drop_path.parent.mkdir()
    drop_path.write_text("notes")

    Mobilebackup2Service.prune_backup_directory(
        device_directory,
        Mobilebackup2Service.selection_filter_callback(Mobilebackup2Service.resolve_backup_selection(["sms"])),
    )

    assert keep_path.exists()
    assert not drop_path.exists()


@pytest.mark.asyncio
async def test_device_link_move_items_skips_missing_filtered_source(tmp_path: Path) -> None:
    service = AsyncMock()
    device_link = DeviceLink(service, tmp_path, preserve_file=lambda _file_name, _device_name: False)

    await device_link.move_items(["DLMessageMoveItems", {"missing/source": "54/hash"}])

    service.send_plist.assert_awaited_once()


@pytest.mark.asyncio
async def test_device_link_move_items_notifies_post_receive(tmp_path: Path) -> None:
    service = AsyncMock()
    observed = []
    device_link = DeviceLink(
        service, tmp_path, post_file_receive=lambda file_name, device_name: observed.append((file_name, device_name))
    )
    source = tmp_path / "Snapshot" / "Manifest.db"
    source.parent.mkdir(parents=True)
    source.write_text("manifest")

    await device_link.move_items(["DLMessageMoveItems", {"Snapshot/Manifest.db": "Manifest.db"}])

    assert observed == [("Manifest.db", "Snapshot/Manifest.db")]


@pytest.mark.asyncio
async def test_device_link_upload_files_creates_empty_placeholder_for_filtered_file(tmp_path: Path) -> None:
    service = AsyncMock()
    payloads = [
        struct.pack(">I", len("HomeDomain-Library/Notes/notes.sqlite")),
        b"HomeDomain-Library/Notes/notes.sqlite",
        struct.pack(">I", len("ab/cdef")),
        b"ab/cdef",
        struct.pack(">I", 5),
        struct.pack(">B", 0xC),
        b"data",
        struct.pack(">I", 1),
        struct.pack(">B", 0),
        struct.pack(">I", 0),
        b"",
    ]
    service.recvall = AsyncMock(side_effect=payloads)
    device_link = DeviceLink(service, tmp_path, preserve_file=lambda _file_name, _device_name: False)

    await device_link.upload_files(["DLMessageUploadFiles"])

    placeholder = tmp_path / "ab" / "cdef"
    assert placeholder.exists()
    assert placeholder.read_bytes() == b""
