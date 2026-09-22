import inspect
import struct
from unittest.mock import Mock

import pytest

from pymobiledevice3.remote.core_device.vnc_server import VncStreamServer, vnc_auth_response


def test_vnc_auth_response_matches_reference_vector():
    # Password "password" gives the bit-reversed DES key 0e86ceceeef64e26; a zero block under it is
    # ff97502e9422f089 by both OpenSSL 3 (legacy provider) and LibreSSL's `openssl enc -des-ecb`.
    assert vnc_auth_response("password", bytes(16)).hex() == "ff97502e9422f089" * 2


def test_vnc_auth_response_pads_and_truncates_to_eight_bytes():
    challenge = bytes(range(16))
    assert vnc_auth_response("abcdefgh", challenge) == vnc_auth_response("abcdefghijk", challenge)
    assert vnc_auth_response("a", challenge) != vnc_auth_response("b", challenge)


class _Wire:
    """The client's side of a VNC handshake, scripted up front."""

    def __init__(self, version: bytes, password: str) -> None:
        self.sent = bytearray()
        self._version = version
        self._password = password
        self._answered = False

    async def readexactly(self, n: int) -> bytes:
        if self._answered:
            # the read after the challenge response is ClientInit: stop there, security is settled
            raise EOFError
        if n == 12:
            return self._version
        if n == 1:
            return b"\x02"  # 3.7+/3.8: the client picks VNC Auth
        if n == 16:
            self._answered = True
            return vnc_auth_response(self._password, bytes(self.sent[-16:]))
        raise AssertionError(n)

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        pass


def _server(password) -> VncStreamServer:
    server = object.__new__(VncStreamServer)
    server._password = password
    return server


async def _handshake(server: VncStreamServer, wire: _Wire) -> None:
    with pytest.raises(EOFError):
        await server._handshake(Mock(reader=wire, writer=wire))


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [b"RFB 003.003\n", b"RFB 003.008\n"])
async def test_correct_password_is_accepted(version):
    wire = _Wire(version, "s3cret")
    await _handshake(_server("s3cret"), wire)
    assert wire.sent.endswith(b"\x00\x00\x00\x00")  # SecurityResult OK


@pytest.mark.asyncio
async def test_wrong_password_is_refused_with_a_reason_on_3_8():
    wire = _Wire(b"RFB 003.008\n", "wrong")
    with pytest.raises(ConnectionError):
        await _server("s3cret")._handshake(Mock(reader=wire, writer=wire))
    assert wire.sent.endswith(struct.pack(">I", 1) + struct.pack(">I", 21) + b"Authentication failed")


@pytest.mark.asyncio
async def test_wrong_password_is_refused_without_a_reason_on_3_3():
    wire = _Wire(b"RFB 003.003\n", "wrong")
    with pytest.raises(ConnectionError):
        await _server("s3cret")._handshake(Mock(reader=wire, writer=wire))
    assert wire.sent.endswith(struct.pack(">I", 1))


@pytest.mark.asyncio
async def test_without_a_password_any_response_is_accepted():
    # macOS Screen Sharing insists on typing something; the open server keeps accepting it
    wire = _Wire(b"RFB 003.008\n", "whatever")
    await _handshake(_server(None), wire)
    assert wire.sent.endswith(b"\x00\x00\x00\x00")


def test_binds_loopback_by_default():
    parameters = inspect.signature(VncStreamServer.__init__).parameters
    assert parameters["bind"].default == "127.0.0.1"
    assert parameters["password"].default is None
