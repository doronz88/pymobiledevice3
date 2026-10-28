import asyncio
import contextlib
import hashlib
import threading
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any, Optional, cast

import pytest
import requests
import typer

from pymobiledevice3.cli import restore as restore_cli

URL = "https://updates.cdn-apple.com/x/iPhone12,1_27.2_24B119_Restore.ipsw"
NAME = "iPhone12,1_27.2_24B119_Restore.ipsw"
PAYLOAD = b"ipsw-bytes"
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture(autouse=True)
def open_ipsw_as_path(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.asynccontextmanager
    async def ipsw_ctx(path: Path) -> AsyncGenerator[Any, None]:
        yield Path(path)

    monkeypatch.setattr(restore_cli, "ipsw_ctx", ipsw_ctx)


@pytest.fixture
def apple_sha256(monkeypatch: pytest.MonkeyPatch) -> list[Optional[str]]:
    """What Apple's CDN publishes for the URL; tests overwrite [0]."""
    published: list[Optional[str]] = [PAYLOAD_SHA256]
    monkeypatch.setattr(restore_cli, "_published_sha256", lambda url: published[0])
    return published


@pytest.fixture
def downloads(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    downloaded: list[Path] = []

    def file_download(url: str, outfile: Path, resume: bool = False, stop: Optional[threading.Event] = None) -> bool:
        downloaded.append(outfile)
        outfile.write_bytes(PAYLOAD)
        return True

    monkeypatch.setattr(restore_cli, "file_download", file_download)
    return downloaded


def _open(ipsw_dir: Optional[Path], sha256: Optional[str] = None) -> Path:
    async def open_ipsw() -> Path:
        async with restore_cli.download_ipsw_ctx(URL, ipsw_dir, sha256) as ipsw:
            # ipsw_ctx is patched to yield the path it was given
            return cast(Path, ipsw)

    return asyncio.run(open_ipsw())


def test_an_ipsw_already_in_the_dir_is_trusted_without_downloading_or_hashing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, apple_sha256: list[Optional[str]], downloads: list[Path]
) -> None:
    (tmp_path / NAME).write_bytes(b"manually downloaded")
    monkeypatch.setattr(restore_cli, "_file_sha256", lambda *args: pytest.fail("a complete IPSW must not be re-hashed"))

    assert _open(tmp_path) == tmp_path / NAME
    assert downloads == []


def test_a_new_download_lands_as_part_and_is_renamed_once_verified(
    tmp_path: Path, apple_sha256: list[Optional[str]], downloads: list[Path]
) -> None:
    ipsw = _open(tmp_path / "ipsw")

    assert downloads == [tmp_path / "ipsw" / f"{NAME}.part"]
    assert ipsw == tmp_path / "ipsw" / NAME
    assert ipsw.read_bytes() == PAYLOAD
    assert not (tmp_path / "ipsw" / f"{NAME}.part").exists()


def test_the_listing_hash_is_used_when_apple_publishes_none(
    tmp_path: Path, apple_sha256: list[Optional[str]], downloads: list[Path]
) -> None:
    apple_sha256[0] = None

    with pytest.raises(typer.Exit):
        _open(tmp_path, sha256=hashlib.sha256(b"something else").hexdigest())
    assert _open(tmp_path, sha256=PAYLOAD_SHA256.upper()).read_bytes() == PAYLOAD


def test_a_download_that_does_not_match_its_sha256_is_discarded(
    tmp_path: Path, apple_sha256: list[Optional[str]], downloads: list[Path]
) -> None:
    apple_sha256[0] = hashlib.sha256(b"something else").hexdigest()

    with pytest.raises(typer.Exit) as exc_info:
        _open(tmp_path)

    assert exc_info.value.exit_code == 1
    assert list(tmp_path.iterdir()) == []


def test_without_any_published_hash_the_download_is_used_unverified(
    tmp_path: Path, apple_sha256: list[Optional[str]], downloads: list[Path]
) -> None:
    apple_sha256[0] = None

    assert _open(tmp_path).read_bytes() == PAYLOAD


def test_a_leftover_part_file_is_resumed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, apple_sha256: list[Optional[str]]
) -> None:
    (tmp_path / f"{NAME}.part").write_bytes(PAYLOAD[:4])

    def file_download(url: str, outfile: Path, resume: bool = False, stop: Optional[threading.Event] = None) -> bool:
        assert resume
        with outfile.open("ab") as f:
            f.write(PAYLOAD[outfile.stat().st_size :])
        return True

    monkeypatch.setattr(restore_cli, "file_download", file_download)

    assert _open(tmp_path).read_bytes() == PAYLOAD


def test_cancelling_stops_the_download_and_keeps_the_part_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, apple_sha256: list[Optional[str]]
) -> None:
    started = threading.Event()
    stopped = threading.Event()

    def file_download(url: str, outfile: Path, resume: bool = False, stop: Optional[threading.Event] = None) -> bool:
        assert stop is not None
        outfile.write_bytes(PAYLOAD[:4])
        started.set()
        if not stop.wait(5):
            pytest.fail("the download was never told to stop")
        stopped.set()
        return False

    monkeypatch.setattr(restore_cli, "file_download", file_download)

    async def cancel_mid_download() -> None:
        task = asyncio.create_task(restore_cli.download_ipsw_ctx(URL, tmp_path).__aenter__())
        await asyncio.to_thread(started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_mid_download())

    assert stopped.is_set()
    assert (tmp_path / f"{NAME}.part").read_bytes() == PAYLOAD[:4]
    assert not (tmp_path / NAME).exists()


def test_without_an_ipsw_dir_the_download_is_temporary(
    apple_sha256: list[Optional[str]], downloads: list[Path]
) -> None:
    ipsw = _open(None)

    assert ipsw.name == NAME
    assert not ipsw.exists()


def test_query_ipswme_marks_builds_already_in_the_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    firmwares = [
        {"version": "27.2", "buildid": "24B119", "url": URL, "signed": True, "sha256sum": "a"},
        {"version": "27.1", "buildid": "24A500", "url": URL.replace("27.2_24B119", "27.1_24A500"), "signed": True},
        {"version": "27.0", "buildid": "24A437", "url": URL.replace("27.2_24B119", "27.0_24A437"), "signed": False},
    ]
    response = type("Response", (), {"json": lambda self: {"firmwares": firmwares}})()
    monkeypatch.setattr(restore_cli.requests, "get", lambda *args, **kwargs: response)
    shown: list[list[str]] = []

    def prompt_selection(choices: list[str], message: str, idx: bool = False) -> int:
        shown.append(choices)
        return 0

    monkeypatch.setattr(restore_cli, "prompt_selection", prompt_selection)
    (tmp_path / NAME).write_bytes(PAYLOAD)

    assert restore_cli.query_ipswme("iPhone12,1", tmp_path) == firmwares[0]
    assert shown == [["27.2: 24B119 (local)", "27.1: 24A500"]]


def test_query_ipswme_reports_an_unreachable_ipswme(monkeypatch: pytest.MonkeyPatch) -> None:
    def get(*args: object, **kwargs: object) -> None:
        raise requests.ConnectionError("no route to host")

    monkeypatch.setattr(restore_cli.requests, "get", get)

    with pytest.raises(typer.Exit) as exc_info:
        restore_cli.query_ipswme("iPhone12,1")

    assert exc_info.value.exit_code == 1
