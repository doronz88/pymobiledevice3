import contextlib
import hashlib
from collections.abc import Generator
from pathlib import Path
from typing import Any, Optional, cast

import pytest
import requests
import typer

from pymobiledevice3.cli import restore as restore_cli

URL = "https://updates.cdn-apple.com/x/iPhone12,1_27.2_24B119_Restore.ipsw"
NAME = "iPhone12,1_27.2_24B119_Restore.ipsw"
PAYLOAD = b"ipsw-bytes"


@pytest.fixture(autouse=True)
def open_ipsw_as_path(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.contextmanager
    def ipsw_ctx(path: Path) -> Generator[Any, None, None]:
        yield Path(path)

    monkeypatch.setattr(restore_cli, "ipsw_ctx", ipsw_ctx)


@pytest.fixture
def downloads(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    downloaded: list[Path] = []

    def file_download(url: str, outfile: Path) -> None:
        downloaded.append(outfile)
        outfile.write_bytes(PAYLOAD)

    monkeypatch.setattr(restore_cli, "file_download", file_download)
    return downloaded


def _open(ipsw_dir: Optional[Path], sha1: Optional[str] = None) -> Path:
    with restore_cli.download_ipsw_ctx(URL, ipsw_dir, sha1) as ipsw:
        # ipsw_ctx is patched to yield the path it was given
        return cast(Path, ipsw)


def test_an_ipsw_already_in_the_dir_is_trusted_without_downloading_or_hashing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, downloads: list[Path]
) -> None:
    (tmp_path / NAME).write_bytes(b"manually downloaded")
    monkeypatch.setattr(restore_cli, "_file_sha1", lambda path: pytest.fail("a complete IPSW must not be re-hashed"))

    assert _open(tmp_path, sha1="does-not-matter") == tmp_path / NAME
    assert downloads == []


def test_a_new_download_lands_as_part_and_is_renamed_once_verified(tmp_path: Path, downloads: list[Path]) -> None:
    ipsw = _open(tmp_path / "ipsw", sha1=hashlib.sha1(PAYLOAD).hexdigest().upper())

    assert downloads == [tmp_path / "ipsw" / f"{NAME}.part"]
    assert ipsw == tmp_path / "ipsw" / NAME
    assert ipsw.read_bytes() == PAYLOAD
    assert not (tmp_path / "ipsw" / f"{NAME}.part").exists()


def test_a_download_that_does_not_match_its_sha1_is_discarded(tmp_path: Path, downloads: list[Path]) -> None:
    with pytest.raises(typer.Exit) as exc_info:
        _open(tmp_path, sha1=hashlib.sha1(b"something else").hexdigest())

    assert exc_info.value.exit_code == 1
    assert list(tmp_path.iterdir()) == []


def test_a_leftover_part_file_is_downloaded_again(tmp_path: Path, downloads: list[Path]) -> None:
    (tmp_path / f"{NAME}.part").write_bytes(b"interrupted")

    assert _open(tmp_path).read_bytes() == PAYLOAD
    assert len(downloads) == 1


def test_without_an_ipsw_dir_the_download_is_temporary(downloads: list[Path]) -> None:
    ipsw = _open(None)

    assert ipsw.name == NAME
    assert not ipsw.exists()


def test_query_ipswme_marks_builds_already_in_the_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    firmwares = [
        {"version": "27.2", "buildid": "24B119", "url": URL, "signed": True, "sha1sum": "a"},
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
