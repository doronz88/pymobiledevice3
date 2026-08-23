"""Serve an AFC filesystem over a local WebDAV server.

Runs an async WebDAV server (ASGIWebDAV) in-process; every WebDAV request is
translated into ``AfcService`` calls, so a local WebDAV client (e.g. macOS Finder)
can browse and edit the device's AFC filesystem read-write as a mounted volume.

ASGIWebDAV requires Python >= 3.10, so this module must be imported lazily by
callers that still need to run on older interpreters (they should catch
``ImportError`` and surface a friendly message).
"""

from __future__ import annotations

import asyncio
import logging
import os
import posixpath
from stat import S_ISDIR, S_ISREG
from typing import Any, Optional

import uvicorn
from asgi_webdav.config import Config, generate_config_from_dict, reinit_global_config
from asgi_webdav.constants import (
    RESPONSE_DATA_BLOCK_SIZE,
    DAVDepth,
    DAVPath,
    DAVResponseBodyGenerator,
    DAVResponseContentRange,
    DAVTime,
)
from asgi_webdav.helpers import generate_etag, guess_type
from asgi_webdav.property import DAVProperty, DAVPropertyBasicData
from asgi_webdav.provider.common import DAVProvider, DAVProviderFeature, get_response_content_range
from asgi_webdav.request import DAVRequest
from asgi_webdav.server import DAVApp
from asgi_webdav.web_dav import PrefixProviderInfo

from pymobiledevice3.exceptions import AfcException, ConnectionTerminatedError
from pymobiledevice3.services.webdav_mount import (
    mount_webdav_volume,
    reveal_in_file_manager,
    unmount_webdav_volume,
)

logger = logging.getLogger(__name__)

_APPLE_METADATA_NAMES = frozenset({
    ".DS_Store",
    ".localized",
    ".hidden",
    ".Trashes",
    ".apdisk",
    ".metadata_never_index",
    ".VolumeIcon.icns",
})


def _is_apple_metadata(name: str) -> bool:
    """Whether a basename is macOS Finder metadata (``.DS_Store`` / AppleDouble ``._*`` / friends)."""
    return name.startswith("._") or name in _APPLE_METADATA_NAMES


async def _drain(request: DAVRequest) -> None:
    """Consume and discard a request body."""
    more_body = True
    while more_body:
        event = await request.receive()
        more_body = event.get("more_body")


class AfcDavProvider(DAVProvider):
    """A WebDAV provider whose backing store is a device's AFC filesystem."""

    type = "afc"
    feature = DAVProviderFeature(content_range=True, home_dir=False)

    def __init__(self, afc: Any, root: str, config: Config, prefix: DAVPath, read_only: bool) -> None:
        super().__init__(
            config=config,
            prefix=prefix,
            uri=f"afc://{root}",
            home_dir=False,
            read_only=read_only,
            ignore_property_extra=True,
        )
        self._afc = afc
        self._root = "/" + root.strip("/")

    def __repr__(self) -> str:
        return f"afc://{self._root}"

    def _afc_path(self, path: DAVPath) -> str:
        return posixpath.join(self._root, *path.parts)

    async def _create_dav_property_obj(self, href_path: DAVPath, stat_result: Any) -> DAVProperty:
        is_collection = S_ISDIR(stat_result.st_mode)
        created = getattr(stat_result, "st_birthtime", stat_result.st_mtime)
        if is_collection:
            basic_data = DAVPropertyBasicData(
                is_collection=is_collection,
                display_name=href_path.name,
                creation_date=DAVTime(created),
                last_modified=DAVTime(stat_result.st_mtime),
            )
        else:
            content_type, content_encoding = guess_type(self.config, href_path.name)
            basic_data = DAVPropertyBasicData(
                is_collection=is_collection,
                display_name=href_path.name,
                creation_date=DAVTime(created),
                last_modified=DAVTime(stat_result.st_mtime),
                content_type="" if content_type is None else content_type,
                content_charset=None,
                content_length=stat_result.st_size,
                content_encoding=content_encoding,
            )
        return DAVProperty(href_path=href_path, is_collection=is_collection, basic_data=basic_data)

    async def _get_res_etag(self, request: DAVRequest) -> str:
        stat_result = await self._afc.os_stat(self._afc_path(request.dist_src_path))
        return generate_etag(stat_result.st_size, stat_result.st_mtime)

    async def _do_propfind(self, request: DAVRequest) -> dict[DAVPath, DAVProperty]:
        dav_properties: dict[DAVPath, DAVProperty] = {}
        try:
            base_stat = await self._afc.os_stat(self._afc_path(request.dist_src_path))
        except AfcException:
            return dav_properties

        dav_properties[request.src_path] = await self._create_dav_property_obj(request.src_path, base_stat)
        if request.depth != DAVDepth.ZERO and S_ISDIR(base_stat.st_mode):
            await self._propfind_children(dav_properties, request.src_path, infinity=request.depth == DAVDepth.INFINITY)
        return dav_properties

    async def _propfind_children(
        self, dav_properties: dict[DAVPath, DAVProperty], href_base: DAVPath, infinity: bool, depth_limit: int = 99
    ) -> None:
        sub_dir_names: list[str] = []
        for name in await self._afc.listdir(self._afc_path(href_base)):
            if _is_apple_metadata(name):
                continue
            href_path = href_base.add_child(name)
            try:
                stat_result = await self._afc.os_stat(self._afc_path(href_path))
            except AfcException:
                continue
            dav_properties[href_path] = await self._create_dav_property_obj(href_path, stat_result)
            if S_ISDIR(stat_result.st_mode) and infinity:
                sub_dir_names.append(name)

        if not infinity or depth_limit <= 0:
            return
        for name in sub_dir_names:
            await self._propfind_children(dav_properties, href_base.add_child(name), infinity, depth_limit - 1)

    async def _do_get(
        self, request: DAVRequest
    ) -> tuple[
        int,
        Optional[DAVPropertyBasicData],
        Optional[DAVResponseBodyGenerator],
        Optional[DAVResponseContentRange],
    ]:
        if _is_apple_metadata(request.dist_src_path.name):
            return 404, None, None, None
        afc_path = self._afc_path(request.dist_src_path)
        try:
            stat_result = await self._afc.os_stat(afc_path)
        except AfcException:
            return 404, None, None, None

        if S_ISDIR(stat_result.st_mode):
            dav_property = await self._create_dav_property_obj(request.src_path, stat_result)
            return 200, dav_property.basic_data, None, None
        if not S_ISREG(stat_result.st_mode):
            # refuse fifos / devices / sockets: reading them can block the AFC channel
            return 403, None, None, None

        dav_property = await self._create_dav_property_obj(request.src_path, stat_result)

        if not request.ranges:
            return 200, dav_property.basic_data, self._body_generator(afc_path), None

        # a Range request: macOS Finder / webdavfs reads large files as a series of byte ranges.
        # Answering those with 200 + the whole file makes the client write the full body at the
        # range's offset, corrupting the result. Serve the requested bytes as 206 Partial Content.
        content_range = get_response_content_range(
            request_ranges=request.ranges,
            file_size=dav_property.basic_data.content_length,
        )
        if content_range is None:
            return 200, dav_property.basic_data, self._body_generator(afc_path), None
        if request.if_range and not request.if_range.match(
            etag=dav_property.basic_data.etag,
            last_modified=dav_property.basic_data.last_modified.http_date,
        ):
            return 416, dav_property.basic_data, None, content_range
        return 206, dav_property.basic_data, self._body_generator(afc_path, content_range), content_range

    async def _do_head(self, request: DAVRequest) -> tuple[int, Optional[DAVPropertyBasicData]]:
        if _is_apple_metadata(request.dist_src_path.name):
            return 404, None
        try:
            stat_result = await self._afc.os_stat(self._afc_path(request.dist_src_path))
        except AfcException:
            return 404, None
        if not (S_ISDIR(stat_result.st_mode) or S_ISREG(stat_result.st_mode)):
            return 403, None
        dav_property = await self._create_dav_property_obj(request.src_path, stat_result)
        return 200, dav_property.basic_data

    async def _body_generator(
        self, afc_path: str, content_range: Optional[DAVResponseContentRange] = None
    ) -> DAVResponseBodyGenerator:
        handle = await self._afc.fopen(afc_path, "r")
        try:
            if content_range is None:
                more_body = True
                while more_body:
                    data = await self._afc.fread(handle, RESPONSE_DATA_BLOCK_SIZE)
                    more_body = len(data) == RESPONSE_DATA_BLOCK_SIZE
                    yield data, more_body
                return

            await self._afc.fseek(handle, content_range.content_start, os.SEEK_SET)
            remaining = content_range.content_end - content_range.content_start + 1
            while remaining > 0:
                data = await self._afc.fread(handle, min(remaining, RESPONSE_DATA_BLOCK_SIZE))
                if not data:
                    break
                remaining -= len(data)
                yield data, remaining > 0
        finally:
            await self._afc.fclose(handle)

    async def _do_put(self, request: DAVRequest) -> int:
        if _is_apple_metadata(request.dist_src_path.name):
            # swallow Finder metadata writes: report success without touching the device
            await _drain(request)
            return 201
        afc_path = self._afc_path(request.dist_src_path)
        try:
            stat_result = await self._afc.os_stat(afc_path)
        except AfcException:
            stat_result = None
        if stat_result is not None and not S_ISREG(stat_result.st_mode):
            return 405

        try:
            handle = await self._afc.fopen(afc_path, "w")
            try:
                more_body = True
                while more_body:
                    event = await request.receive()
                    more_body = event.get("more_body")
                    data = event.get("body", b"")
                    if data:
                        await self._afc.fwrite(handle, data)
            finally:
                await self._afc.fclose(handle)
        except AfcException:
            return 403
        return 201

    async def _do_delete(self, request: DAVRequest) -> int:
        if _is_apple_metadata(request.dist_src_path.name):
            return 204
        afc_path = self._afc_path(request.dist_src_path)
        if not await self._afc.exists(afc_path):
            return 404
        try:
            await self._afc.rm(afc_path, force=False)
        except AfcException:
            return 403
        return 204

    async def _do_mkcol(self, request: DAVRequest) -> int:
        afc_path = self._afc_path(request.dist_src_path)
        if await self._afc.exists(afc_path):
            return 405
        parent = posixpath.dirname(afc_path.rstrip("/"))
        if not await self._afc.exists(parent):
            return 409
        try:
            await self._afc.makedirs(afc_path)
        except AfcException:
            return 403
        return 201

    async def _do_move(self, request: DAVRequest) -> int:
        src = self._afc_path(request.dist_src_path)
        dst = self._afc_path(request.dist_dst_path)
        if not await self._afc.exists(src):
            return 403
        if not await self._afc.exists(posixpath.dirname(dst.rstrip("/"))):
            return 409
        dst_exists = await self._afc.exists(dst)
        if not request.overwrite and dst_exists:
            return 412
        try:
            if dst_exists:
                await self._afc.rm(dst, force=True)
            await self._afc.rename(src, dst)
        except AfcException:
            return 403
        return 204 if request.overwrite else 201


class WebDavServer:
    """Handle for a running WebDAV server."""

    def __init__(self, uvicorn_server: Any, task: Any, host: str, port: int) -> None:
        self._server = uvicorn_server
        self._task = task
        self.host = host
        self.port = port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    async def stop(self) -> None:
        self._server.should_exit = True
        await self._task


async def serve_afc_webdav(
    afc: Any, *, path: str = "/", host: str = "127.0.0.1", port: int = 0, readonly: bool = False
) -> WebDavServer:
    """Start a WebDAV server exposing ``afc`` (an :class:`AfcService`).

    :param afc: an open AFC service to bridge.
    :param path: AFC path to serve as the volume root (default: /).
    :param host: local interface to bind (default: loopback).
    :param port: local TCP port; 0 picks a free port.
    :param readonly: expose the filesystem read-only.
    :return: a running-server handle with ``url`` and ``stop()``.
    """
    for name in ("asgi_webdav", "uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).setLevel(logging.WARNING)

    config = generate_config_from_dict({
        "account_mapping": [{"username": "anonymous", "password": "", "permissions": ["+"]}],
        "anonymous": {
            "enable": True,
            "user": {"username": "anonymous", "password": "", "permissions": ["+"]},
            "allow_missing_auth_header": True,
        },
        "provider_mapping": [],
        "logging": {"enable": False},
    })
    reinit_global_config(config)

    app = DAVApp(config)
    provider = AfcDavProvider(afc=afc, root=path, config=config, prefix=DAVPath("/"), read_only=readonly)
    app.web_dav.prefix_provider_mapping = [
        PrefixProviderInfo(
            prefix=DAVPath("/"),
            prefix_weight=1,
            provider=provider,
            home_dir=False,
            read_only=readonly,
            ignore_property_extra=True,
        )
    ]

    uv_config = uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="off")
    server = uvicorn.Server(uv_config)
    task = asyncio.ensure_future(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    bound_port = server.servers[0].sockets[0].getsockname()[1]
    return WebDavServer(server, task, host, bound_port)


async def run_afc_webdav(
    afc: Any,
    *,
    path: str = "/",
    mount: bool = False,
    host: str = "127.0.0.1",
    port: int = 0,
    readonly: bool = False,
    label: str = "pmd-webdav",
) -> None:
    """Serve ``afc`` over WebDAV, optionally mount it locally, and block until interrupted.

    :param afc: an open AFC service to bridge.
    :param path: AFC path to serve (default: /).
    :param mount: mount the volume locally and reveal it in the OS file manager.
    :param host: local interface to bind.
    :param port: local TCP port; 0 picks a free port.
    :param readonly: expose the filesystem read-only.
    :param label: descriptive name for the local mount point, so it is easy to spot in Finder.
    :raises ConnectionTerminatedError: when the device disconnects (after unmounting and
        stopping the local server), so CLI-level reconnect logic can re-serve.
    """
    server = await serve_afc_webdav(afc, path=path, host=host, port=port, readonly=readonly)
    print(f"WebDAV server serving {path!r} at {server.url}")

    mounted = None
    if mount:
        mounted = await mount_webdav_volume(server.url, label=label)
        if mounted is None:
            print("Automatic mount is unavailable on this host; open the URL below in your file manager.")

    if mounted is not None:
        await reveal_in_file_manager(mounted.reveal_target)
        print(f"Mounted; revealed {mounted.reveal_target}")
    else:
        print(f"Open this WebDAV URL in your file manager: {server.url}")
    print("Press Ctrl-C to stop.")

    try:
        await afc.wait_terminated()
        print("Device disconnected; stopping.")
        # Propagate as a connection error (after the finally-cleanup below) so the CLI's
        # global --reconnect machinery can wait for the device and re-serve.
        raise ConnectionTerminatedError()
    finally:
        if mounted is not None:
            await unmount_webdav_volume(mounted)
        await server.stop()
        print("stopped.")
