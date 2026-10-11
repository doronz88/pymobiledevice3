import asyncio
import socket
import struct

import pytest

from pymobiledevice3.remote.remotexpc import HTTP2_MAGIC
from pymobiledevice3.tunneld.api import _create_rsds_from_tunnels


@pytest.mark.asyncio
async def test_create_rsds_skips_a_tunnel_that_resets_the_handshake():
    async def reset_after_preface(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readexactly(len(HTTP2_MAGIC))
        # Linger 0 makes the close send RST instead of FIN
        writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.transport.abort()

    server = await asyncio.start_server(reset_after_preface, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        tunnels = {"dead": [{"tunnel-address": "127.0.0.1", "tunnel-port": port, "interface": "utun-test"}]}
        assert await _create_rsds_from_tunnels(tunnels, ("127.0.0.1", 49151), bridge=False) == []
    finally:
        server.close()
        await server.wait_closed()
