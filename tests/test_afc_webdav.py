"""Device-independent tests for the AFC WebDAV bridge.

The bridge only depends on a small async AFC method surface, so these tests drive
it against a local-filesystem-backed AFC stub instead of a real device.
"""

import os
import shutil
from typing import Any

import httpx
import pytest

pytest.importorskip("asgi_webdav")  # WebDAV support requires Python >= 3.10

from pymobiledevice3.exceptions import AfcFileNotFoundError
from pymobiledevice3.services.webdav import serve_afc_webdav


class LocalAfc:
    """A minimal AFC stand-in backed by a local directory.

    Implements the exact async method surface the WebDAV provider uses, so the same
    provider works unchanged against a real ``AfcService``.
    """

    def __init__(self, root: str) -> None:
        self._root = str(root)
        self._handles: dict[int, Any] = {}
        self._next_handle = 1

    def _local(self, path: str) -> str:
        return os.path.join(self._root, path.lstrip("/"))

    async def os_stat(self, path: str):
        try:
            return os.stat(self._local(path))
        except FileNotFoundError as e:
            raise AfcFileNotFoundError(str(e), None) from e

    async def exists(self, path: str) -> bool:
        return os.path.exists(self._local(path))

    async def isdir(self, path: str) -> bool:
        return os.path.isdir(self._local(path))

    async def listdir(self, path: str) -> list[str]:
        return os.listdir(self._local(path))

    async def makedirs(self, path: str) -> None:
        os.makedirs(self._local(path))

    async def rename(self, source: str, target: str) -> None:
        os.rename(self._local(source), self._local(target))

    async def rm(self, path: str, match=None, force: bool = False) -> list[str]:
        local = self._local(path)
        if os.path.isdir(local):
            shutil.rmtree(local)
        else:
            os.remove(local)
        return []

    async def fopen(self, path: str, mode: str = "r") -> int:
        handle = self._next_handle
        self._next_handle += 1
        self._handles[handle] = open(self._local(path), mode + "b")  # noqa: SIM115 - handle held like AFC fopen
        return handle

    async def fread(self, handle: int, sz: int) -> bytes:
        return self._handles[handle].read(sz)

    async def fwrite(self, handle: int, data: bytes, chunk_size: int = 1 << 30) -> None:
        self._handles[handle].write(data)

    async def fclose(self, handle: int) -> None:
        self._handles.pop(handle).close()


@pytest.mark.asyncio
async def test_get_serves_existing_file(tmp_path) -> None:
    (tmp_path / "hello.txt").write_bytes(b"hi from afc")
    afc = LocalAfc(str(tmp_path))

    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient() as http:
            response = await http.get(f"{server.url}hello.txt")
        assert response.status_code == 200
        assert response.content == b"hi from afc"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_propfind_lists_directory(tmp_path) -> None:
    (tmp_path / "a.txt").write_bytes(b"a")
    (tmp_path / "sub").mkdir()
    afc = LocalAfc(str(tmp_path))

    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient() as http:
            response = await http.request("PROPFIND", server.url, headers={"Depth": "1"})
        assert response.status_code == 207
        assert "a.txt" in response.text
        assert "sub" in response.text
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_put_writes_file(tmp_path) -> None:
    afc = LocalAfc(str(tmp_path))
    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient() as http:
            response = await http.put(f"{server.url}created.txt", content=b"payload")
        assert response.status_code in (200, 201, 204)
    finally:
        await server.stop()

    assert (tmp_path / "created.txt").read_bytes() == b"payload"


@pytest.mark.asyncio
async def test_delete_removes_file(tmp_path) -> None:
    (tmp_path / "doomed.txt").write_bytes(b"bye")
    afc = LocalAfc(str(tmp_path))

    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient() as http:
            response = await http.delete(f"{server.url}doomed.txt")
        assert response.status_code in (200, 204)
    finally:
        await server.stop()

    assert not (tmp_path / "doomed.txt").exists()


@pytest.mark.asyncio
async def test_mkcol_creates_directory(tmp_path) -> None:
    afc = LocalAfc(str(tmp_path))
    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient() as http:
            response = await http.request("MKCOL", f"{server.url}newdir")
        assert response.status_code == 201
    finally:
        await server.stop()

    assert (tmp_path / "newdir").is_dir()


@pytest.mark.asyncio
async def test_move_renames_file(tmp_path) -> None:
    (tmp_path / "before.txt").write_bytes(b"content")
    afc = LocalAfc(str(tmp_path))

    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient() as http:
            response = await http.request(
                "MOVE", f"{server.url}before.txt", headers={"Destination": f"{server.url}after.txt"}
            )
        assert response.status_code in (201, 204)
    finally:
        await server.stop()

    assert not (tmp_path / "before.txt").exists()
    assert (tmp_path / "after.txt").read_bytes() == b"content"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires os.mkfifo (POSIX only)")
@pytest.mark.asyncio
async def test_get_special_file_returns_403(tmp_path) -> None:
    os.mkfifo(str(tmp_path / "afifo"))
    (tmp_path / "after.txt").write_bytes(b"still alive")
    afc = LocalAfc(str(tmp_path))

    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.get(f"{server.url}afifo")
            assert response.status_code == 403
            alive = await http.get(f"{server.url}after.txt")
            assert alive.status_code == 200
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_put_ds_store_is_swallowed(tmp_path) -> None:
    afc = LocalAfc(str(tmp_path))
    server = await serve_afc_webdav(afc, port=0)
    try:
        async with httpx.AsyncClient() as http:
            response = await http.put(f"{server.url}.DS_Store", content=b"\x00\x01mac")
        assert response.status_code in (200, 201, 204)
    finally:
        await server.stop()

    assert not (tmp_path / ".DS_Store").exists()


def test_mount_requires_mount_tool(monkeypatch) -> None:
    import shutil

    import typer

    from pymobiledevice3.cli.cli_common import require_webdav_mount_tool

    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(typer.Exit):
        require_webdav_mount_tool(mount=True)
    require_webdav_mount_tool(mount=False)  # no tool needed when not mounting


@pytest.mark.parametrize(
    "platform, tool, expected",
    [("darwin", "mount_webdav", True), ("win32", "net", True), ("linux", "gio", True)],
)
def test_webdav_mount_supported_per_platform(monkeypatch, platform, tool, expected) -> None:
    import shutil

    from pymobiledevice3.services import webdav_mount

    monkeypatch.setattr(webdav_mount.sys, "platform", platform)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name if name == tool else None)
    assert webdav_mount.webdav_mount_supported() is expected

    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert webdav_mount.webdav_mount_supported() is False


@pytest.mark.parametrize(
    "platform, target, expected_prefix",
    [("darwin", "/mnt", ["open", "/mnt"]), ("win32", "Z:", ["explorer", "Z:"])],
)
def test_opener_command_per_platform(monkeypatch, platform, target, expected_prefix) -> None:
    from pymobiledevice3.services import webdav_mount

    monkeypatch.setattr(webdav_mount.sys, "platform", platform)
    assert webdav_mount._opener_command(target) == expected_prefix


def test_opener_command_linux_uses_xdg_open(monkeypatch) -> None:
    import shutil

    from pymobiledevice3.services import webdav_mount

    monkeypatch.setattr(webdav_mount.sys, "platform", "linux")
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/xdg-open" if name == "xdg-open" else None)
    assert webdav_mount._opener_command("dav://x/") == ["xdg-open", "dav://x/"]


@pytest.mark.asyncio
async def test_mount_returns_none_when_tool_absent(monkeypatch) -> None:
    import shutil

    from pymobiledevice3.services import webdav_mount

    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert await webdav_mount.mount_webdav_volume("http://127.0.0.1:1234/") is None


@pytest.mark.parametrize(
    "label, expected",
    [
        ("pmd-00008030-000-afc", "pmd-00008030-000-afc"),
        ("pmd-UDID-crash", "pmd-UDID-crash"),
        ("pmd-UDID-com.foo.bar", "pmd-UDID-com.foo.bar"),
        ("", "webdav"),
    ],
)
def test_sanitize_label(label, expected) -> None:
    from pymobiledevice3.services import webdav_mount

    assert webdav_mount._sanitize_label(label) == expected


def test_webdav_command_registered_on_afc_groups() -> None:
    from pymobiledevice3.cli import afc, apps, crash

    for group in (afc.cli, apps.cli, crash.cli):
        names = {command.name for command in group.registered_commands if command.name}
        assert "webdav" in names
