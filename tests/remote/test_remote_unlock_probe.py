from typing import Any

import pytest
from bytestruct import UnexpectedConstantError

from pymobiledevice3.exceptions import ProtocolError, PyMobileDevice3Exception
from pymobiledevice3.remote.tunnel_service import RemotePairingProtocol


def _protocol(error: Exception) -> Any:
    async def send_receive_encrypted_request(request: Any) -> Any:
        raise error

    class Probe(RemotePairingProtocol):  # only the remote-unlock probe is exercised
        close = receive_response = send_request = None  # pyright: ignore[reportAssignmentType]

    protocol: Any = object.__new__(Probe)
    protocol._send_receive_encrypted_request = send_receive_encrypted_request
    return protocol


@pytest.mark.asyncio
async def test_remote_unlock_unsupported_leaves_an_empty_host_key() -> None:
    protocol = _protocol(PyMobileDevice3Exception("unsupported"))  # e.g. tvOS
    await protocol._create_remote_unlock()
    assert protocol.remote_unlock_host_key == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [UnexpectedConstantError("bad magic"), ProtocolError("not a dictionary")])
async def test_remote_unlock_malformed_reply_is_not_mistaken_for_unsupported(error: Exception) -> None:
    protocol = _protocol(error)
    with pytest.raises(type(error)):
        await protocol._create_remote_unlock()
