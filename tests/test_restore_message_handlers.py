import tempfile

import pytest

from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.restore.restore_options import SUPPORTED_MESSAGE_TYPES


def _restore() -> Restore:
    # Bypass __init__ (needs an IPSW and a device); these handlers only touch the logger, whose name
    # comes from the running asyncio task (hence the async tests), and the filesystem.
    return Restore.__new__(Restore)


@pytest.mark.asyncio
async def test_crash_log_is_stored_in_a_temporary_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    await _restore().handle_crash_log_msg({
        "MsgType": "CrashLog",
        "Filename": "restored-2026-09-16-000000.ips",
        "Data": b"crash contents",
    })

    saved = list(tmp_path.glob("pymobiledevice3-restore-crash-*/restored-2026-09-16-000000.ips"))
    assert len(saved) == 1
    assert saved[0].read_bytes() == b"crash contents"


@pytest.mark.asyncio
async def test_crash_log_filename_cannot_escape_the_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    await _restore().handle_crash_log_msg({"Filename": "../../escaped.ips", "Data": b"x"})

    assert len(list(tmp_path.glob("pymobiledevice3-restore-crash-*/escaped.ips"))) == 1
    assert not (tmp_path / "escaped.ips").exists()
    assert not (tmp_path.parent / "escaped.ips").exists()


@pytest.mark.asyncio
async def test_incomplete_crash_log_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    await _restore().handle_crash_log_msg({"Filename": "only-a-name.ips"})

    assert list(tmp_path.iterdir()) == []


def test_fdr_submit_is_not_advertised_because_the_upload_is_not_implemented():
    assert SUPPORTED_MESSAGE_TYPES["FDRSubmit"] is False


@pytest.mark.asyncio
async def test_fdr_submit_is_logged_but_never_acknowledged():
    restore = _restore()
    restore._restored = None  # a stray ack would have to go through this and blow up
    await restore.handle_fdr_submit_msg({"DataClass": "Vinyl", "DataInstance": "1", "DataPayload": b"p"})
