import ctypes
import sqlite3
import struct
import time
from collections.abc import Iterable, Iterator
from contextlib import closing
from pathlib import Path
from ssl import SSLEOFError
from unittest.mock import AsyncMock, Mock, call

import pytest

from pymobiledevice3.exceptions import (
    BackupFilterPasswordRequiredError,
    ConnectionFailedError,
    ConnectionTerminatedError,
)
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.device_link import (
    PURGE_DISK_SPACE_ERROR,
    PURGE_DISK_SPACE_ERROR_STRING,
    DeviceLink,
)
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
    assert {"contacts", "call_history", "bookmarks", "messages"} <= set(BACKUP_SELECTIONS)


def test_messages_selection_includes_database_and_attachment_tree() -> None:
    callback = Mobilebackup2Service.selection_filter_callback(
        Mobilebackup2Service.resolve_backup_selection(["messages"])
    )

    assert callback(BackupFile(device_name="/.ba/mobile/Library/SMS/sms.db"))
    assert callback(BackupFile(device_name="/.ba/mobile/Library/SMS/Attachments/12/02/attachment.mov"))
    assert callback(BackupFile(domain="HomeDomain", relative_path="Library/SMS/sms.db"))
    assert callback(
        BackupFile(
            domain="MediaDomain",
            relative_path="Library/SMS/Attachments/12/02/attachment.mov",
        )
    )
    assert callback(BackupFile(domain="MediaDomain", relative_path="Library/SMS/StickerCache/sticker.heic"))
    assert not callback(BackupFile(domain="HomeDomain", relative_path="Library/Notes/notes.sqlite"))


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


def test_should_do_full_backup_when_incremental_metadata_is_missing(tmp_path: Path) -> None:
    assert Mobilebackup2Service._should_do_full_backup(False, tmp_path) is True


def test_should_do_incremental_backup_when_metadata_exists(tmp_path: Path) -> None:
    for filename in ("Manifest.plist", "Manifest.db", "Status.plist"):
        (tmp_path / filename).write_text("data")

    assert Mobilebackup2Service._should_do_full_backup(False, tmp_path) is False


def test_should_do_full_backup_when_incremental_metadata_is_empty(tmp_path: Path) -> None:
    (tmp_path / "Manifest.plist").write_text("")
    (tmp_path / "Manifest.db").write_text("data")
    (tmp_path / "Status.plist").write_text("data")

    assert Mobilebackup2Service._should_do_full_backup(False, tmp_path) is True


def test_should_do_full_backup_only_when_explicit_if_manifest_exists(tmp_path: Path) -> None:
    for filename in ("Manifest.plist", "Manifest.db", "Status.plist"):
        (tmp_path / filename).write_text("data")

    assert Mobilebackup2Service._should_do_full_backup(True, tmp_path) is True
    assert Mobilebackup2Service._should_do_full_backup(False, tmp_path) is False
    assert Mobilebackup2Service._should_do_full_backup(False, tmp_path, patch_manifest=True) is True


@pytest.mark.asyncio
async def test_patch_encrypted_manifest_requires_password(tmp_path: Path) -> None:
    lockdown = Mock(udid="device")
    service = Mobilebackup2Service(lockdown)
    service.get_will_encrypt = AsyncMock(return_value=True)

    with pytest.raises(BackupFilterPasswordRequiredError):
        await service.backup(
            backup_directory=tmp_path,
            filter_callback=lambda _file: True,
            patch_manifest=True,
        )


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
async def test_device_link_purge_disk_space_answers_instead_of_aborting(tmp_path: Path) -> None:
    """A purge request is answered like Apple's host does, not turned into a fatal error."""
    service = AsyncMock()
    device_link = DeviceLink(service, tmp_path)

    await device_link.purge_disk_space(["DLMessagePurgeDiskSpace", 42 * 1024, 1])

    service.send_plist.assert_awaited_once_with([
        "DLMessageStatusResponse",
        ctypes.c_uint64(PURGE_DISK_SPACE_ERROR).value,
        PURGE_DISK_SPACE_ERROR_STRING,
        0,
    ])


@pytest.mark.asyncio
async def test_device_link_dl_loop_survives_purge_disk_space(tmp_path: Path) -> None:
    """The device gets to report its own outcome after a purge request."""
    service = AsyncMock()
    service.recv_plist = AsyncMock(
        side_effect=[
            ["DLMessagePurgeDiskSpace", 42 * 1024, 1],
            ["DLMessageProcessMessage", {"ErrorCode": 0, "Content": "done"}],
        ]
    )
    device_link = DeviceLink(service, tmp_path)

    assert await device_link.dl_loop() == "done"


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

    device_link.cleanup_discarded_files()

    assert not placeholder.exists()


@pytest.mark.asyncio
async def test_device_link_tracks_filtered_placeholder_across_move(tmp_path: Path) -> None:
    service = AsyncMock()
    device_link = DeviceLink(service, tmp_path, preserve_file=lambda _file_name, _device_name: False)
    source = Path("device/Snapshot/aa/hash")
    destination = Path("device/aa/hash")
    source_path = tmp_path / source
    source_path.parent.mkdir(parents=True)
    source_path.touch()
    device_link._discarded_files.add(source)

    await device_link.move_items(["DLMessageMoveItems", {str(source): str(destination)}])
    device_link.cleanup_discarded_files()

    assert not (tmp_path / source).exists()
    assert not (tmp_path / destination).exists()


def test_device_link_tracks_filtered_placeholders_when_directory_is_copied_or_removed(tmp_path: Path) -> None:
    device_link = DeviceLink(AsyncMock(), tmp_path)
    source = Path("device/Snapshot")
    discarded_file = source / "aa" / "hash"
    copied_file = Path("device/Copy") / "aa" / "hash"
    device_link._discarded_files.add(discarded_file)

    device_link._copy_discarded_files(source, Path("device/Copy"), is_dir=True)
    device_link._forget_discarded_files(source, is_dir=True)

    assert device_link._discarded_files == {copied_file}


class _ScanCountingSet(set[Path]):
    """A path set that counts full iterations, to prove per-file bookkeeping is O(1)."""

    def __init__(self, iterable: Iterable[Path] = ()) -> None:
        super().__init__(iterable)
        self.scans = 0

    def __iter__(self) -> Iterator[Path]:
        self.scans += 1
        return super().__iter__()


def _device_link_with_large_discarded_set(tmp_path: Path, on_disk: Path) -> tuple[DeviceLink, _ScanCountingSet]:
    device_link = DeviceLink(AsyncMock(), tmp_path, preserve_file=lambda _file_name, _device_name: False)
    discarded = _ScanCountingSet(Path("tmp") / f"{index:04x}" for index in range(1000))
    device_link._discarded_files = discarded
    path = tmp_path / on_disk
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    discarded.scans = 0
    return device_link, discarded


@pytest.mark.asyncio
async def test_device_link_move_items_does_not_scan_discarded_set_for_file_moves(tmp_path: Path) -> None:
    device_link, discarded = _device_link_with_large_discarded_set(tmp_path, Path("tmp/0000"))
    preserved = tmp_path / "tmp" / "preserved"
    preserved.touch()

    await device_link.move_items(["DLMessageMoveItems", {"tmp/0000": "aa/hash", "tmp/preserved": "bb/hash"}])

    assert discarded.scans == 0
    assert Path("aa/hash") in discarded
    assert Path("tmp/0000") not in discarded


@pytest.mark.asyncio
async def test_device_link_remove_items_does_not_scan_discarded_set_for_files(tmp_path: Path) -> None:
    device_link, discarded = _device_link_with_large_discarded_set(tmp_path, Path("tmp/0000"))

    await device_link.remove_items(["DLMessageRemoveItems", ["tmp/0000", "tmp/not-tracked"]])

    assert discarded.scans == 0
    assert Path("tmp/0000") not in discarded


@pytest.mark.asyncio
async def test_device_link_copy_item_does_not_scan_discarded_set_for_files(tmp_path: Path) -> None:
    device_link, discarded = _device_link_with_large_discarded_set(tmp_path, Path("tmp/0000"))

    await device_link.copy_item(["DLMessageCopyItem", "tmp/0000", "copy/0000"])

    assert discarded.scans == 0
    assert Path("copy/0000") in discarded
    assert Path("tmp/0000") in discarded


@pytest.mark.asyncio
async def test_device_link_move_items_retargets_placeholders_below_moved_directory(tmp_path: Path) -> None:
    device_link = DeviceLink(AsyncMock(), tmp_path, preserve_file=lambda _file_name, _device_name: False)
    placeholder = tmp_path / "device/Snapshot/aa/hash"
    placeholder.parent.mkdir(parents=True)
    placeholder.touch()
    device_link._discarded_files.add(Path("device/Snapshot/aa/hash"))

    await device_link.move_items(["DLMessageMoveItems", {"device/Snapshot/aa": "device/aa"}])

    assert device_link._discarded_files == {Path("device/aa/hash")}


@pytest.mark.asyncio
async def test_device_link_remove_items_forgets_placeholders_below_removed_directory(tmp_path: Path) -> None:
    device_link = DeviceLink(AsyncMock(), tmp_path, preserve_file=lambda _file_name, _device_name: False)
    placeholder = tmp_path / "device/Snapshot/aa/hash"
    placeholder.parent.mkdir(parents=True)
    placeholder.touch()
    device_link._discarded_files.add(Path("device/Snapshot/aa/hash"))

    await device_link.remove_items(["DLMessageRemoveItems", ["device/Snapshot"]])

    assert device_link._discarded_files == set()


@pytest.mark.asyncio
async def test_device_link_copy_item_duplicates_placeholders_below_copied_directory(tmp_path: Path) -> None:
    device_link = DeviceLink(AsyncMock(), tmp_path, preserve_file=lambda _file_name, _device_name: False)
    placeholder = tmp_path / "device/Snapshot/aa/hash"
    placeholder.parent.mkdir(parents=True)
    placeholder.touch()
    device_link._discarded_files.add(Path("device/Snapshot/aa/hash"))

    await device_link.copy_item(["DLMessageCopyItem", "device/Snapshot", "device/Copy"])

    assert device_link._discarded_files == {
        Path("device/Snapshot/aa/hash"),
        Path("device/Copy/aa/hash"),
    }


def test_device_link_does_not_remove_directory_tracked_as_discarded_file(tmp_path: Path) -> None:
    device_link = DeviceLink(AsyncMock(), tmp_path)
    directory = tmp_path / "kept"
    directory.mkdir()
    kept_file = directory / "data"
    kept_file.write_text("data")
    device_link._discarded_files.add(Path("kept"))

    with pytest.raises(OSError):
        device_link.cleanup_discarded_files()

    assert kept_file.read_text() == "data"
