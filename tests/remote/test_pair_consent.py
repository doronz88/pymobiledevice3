"""Pair-setup M2 handling in RemotePairingProtocol._request_pair_consent."""

from typing import Any

import pytest

from pymobiledevice3.exceptions import PairingError
from pymobiledevice3.remote.tunnel_service import (
    PairConsentResult,
    PairingDataComponentTLVBuf,
    PairingDataComponentType,
    RemotePairingProtocol,
    _describe_pairing_error,
)

# M2 from issue #879, sent by a device in pairing backoff: ERROR=3, RETRY_DELAY=8316 (seconds), STATE=2
BACKOFF_M2 = b"\x07\x01\x03\x08\x02\x7c\x20\x06\x01\x02"

PUBLIC_KEY = bytes(range(256)) + bytes(128)
SALT = bytes(range(16))
VALID_M2 = PairingDataComponentTLVBuf.build([
    {"type": PairingDataComponentType.STATE, "data": b"\x02"},
    {"type": PairingDataComponentType.PUBLIC_KEY, "data": PUBLIC_KEY[:255]},
    {"type": PairingDataComponentType.PUBLIC_KEY, "data": PUBLIC_KEY[255:]},
    {"type": PairingDataComponentType.SALT, "data": SALT},
])


def _pairing_data(data: bytes) -> dict[str, Any]:
    return {"pairingData": {"_0": {"kind": "setupManualPairing", "data": data, "startNewSession": False}}}


class _ScriptedProtocol(RemotePairingProtocol):
    """Answers each receive with the next scripted control-channel event."""

    def __init__(self, model: str, events: list[dict[str, Any]]) -> None:
        super().__init__()
        self.handshake_info = {"peerDeviceInfo": {"identifier": "UDID", "model": model}}
        self.events = events

    async def close(self) -> None: ...

    async def send_request(self, data: dict[str, Any]) -> None: ...

    async def receive_response(self) -> dict[str, Any]:
        return {"message": {"plain": {"_0": {"event": {"_0": self.events.pop(0)}}}}}


@pytest.fixture
def no_input(monkeypatch):
    def fail(prompt: str = "") -> str:
        pytest.fail(f"unexpected PIN prompt: {prompt!r}")

    monkeypatch.setattr("builtins.input", fail)


@pytest.mark.parametrize(
    ("model", "events"),
    [
        ("iPad13,8", [_pairing_data(BACKOFF_M2)]),
        ("iPhone15,2", [{"awaitingUserConsent": {}}, _pairing_data(BACKOFF_M2)]),
        ("AppleTV5,3", [_pairing_data(BACKOFF_M2)]),
    ],
    ids=["immediate", "after-consent", "appletv"],
)
async def test_pair_consent_error_raises_pairing_error(no_input, model, events):
    protocol = _ScriptedProtocol(model, events)

    with pytest.raises(PairingError, match="BACKOFF, retry in 8316 seconds"):
        await protocol._request_pair_consent()

    assert protocol.events == []


async def test_pair_consent_returns_public_key_and_salt(no_input):
    protocol = _ScriptedProtocol("iPhone15,2", [{"awaitingUserConsent": {}}, _pairing_data(VALID_M2)])

    assert await protocol._request_pair_consent() == PairConsentResult(public_key=PUBLIC_KEY, salt=SALT, pin=None)


async def test_pair_consent_asks_apple_tv_for_pin(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "123456")
    protocol = _ScriptedProtocol("AppleTV5,3", [_pairing_data(VALID_M2)])

    assert await protocol._request_pair_consent() == PairConsentResult(public_key=PUBLIC_KEY, salt=SALT, pin="123456")


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (b"\x02", "AUTHENTICATION"),
        (b"\x04", "UNKNOWN_PEER"),
        (b"\x05", "MAX_PEERS"),
        (b"\x06", "MAX_TRIES"),
        (b"\x0a", "UNSUPPORTED"),
        (b"\x7f", "127"),
    ],
)
def test_describe_pairing_error_names_code(error, expected):
    tlv = RemotePairingProtocol.decode_tlv(PairingDataComponentTLVBuf.parse(b"\x07\x01" + error + b"\x06\x01\x02"))

    assert _describe_pairing_error(tlv) == f"device returned pairing error: {expected}"
