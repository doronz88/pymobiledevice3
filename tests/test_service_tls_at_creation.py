import contextlib
import socket
import ssl
from collections.abc import Generator, Iterator
from typing import Any, Optional, cast

import pytest

from pymobiledevice3 import dtx_service_provider, lockdown
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.service_connection import ServiceConnection


class _Lockdown:
    """Starts every service with SSL on a socket whose peer refuses the handshake."""

    def __init__(self) -> None:
        self.sock, peer = socket.socketpair()
        peer.close()
        self.requested: dict[str, Any] = {}

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
        return {"Port": 1, "EnableServiceSSL": True}

    async def create_service_connection(
        self, port: int, ssl_context: Optional[ssl.SSLContext] = None, strip_ssl: bool = False
    ) -> ServiceConnection:
        self.requested = {"ssl_context": ssl_context, "strip_ssl": strip_ssl}
        return await ServiceConnection.from_socket(self.sock, ssl_context=ssl_context, strip_ssl=strip_ssl)

    @contextlib.contextmanager
    def ssl_file(self) -> Generator[str, None, None]:
        yield "unused-certfile"


def _client_context(certfile: str, **kwargs: Any) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


@pytest.fixture
def fake_lockdown(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Lockdown]:
    monkeypatch.setattr(lockdown, "create_ssl_context", _client_context)
    monkeypatch.setattr(dtx_service_provider, "create_ssl_context", _client_context)
    fake = _Lockdown()
    yield fake
    fake.sock.close()


@pytest.mark.asyncio
async def test_start_lockdown_service_negotiates_tls_at_creation(fake_lockdown: _Lockdown) -> None:
    with pytest.raises(ConnectionTerminatedError):
        await LockdownClient.start_lockdown_service(cast(Any, fake_lockdown), "com.example.service")
    assert fake_lockdown.requested["ssl_context"] is not None
    assert fake_lockdown.requested["strip_ssl"] is False
    assert fake_lockdown.sock.fileno() == -1


@pytest.mark.asyncio
@pytest.mark.parametrize("strip_ssl", [False, True])
async def test_dtx_open_negotiates_tls_at_creation(fake_lockdown: _Lockdown, strip_ssl: bool) -> None:
    provider = cast(Any, type("Provider", (), {"lockdown": fake_lockdown})())
    with pytest.raises(ConnectionTerminatedError):
        await DtxServiceProvider._open_dtx_connection(provider, "com.example.service", strip_ssl=strip_ssl)
    assert fake_lockdown.requested["ssl_context"] is not None
    assert fake_lockdown.requested["strip_ssl"] is strip_ssl
    assert fake_lockdown.sock.fileno() == -1
