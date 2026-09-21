"""browse_service() against a scripted mDNS socket: no network needed."""

import asyncio
import errno
import socket
from types import SimpleNamespace
from typing import Any

import pytest

from pymobiledevice3 import bonjour
from pymobiledevice3.bonjour import (
    QTYPE_PTR,
    QTYPE_SRV,
    QTYPE_TXT,
    MDNSResponder,
    _build_rr,
    _DatagramProtocol,
    _encode_srv,
    _encode_txt,
    browse_service,
    encode_name,
)

SERVICE = "_apple-mobdev2._tcp.local."
INSTANCE = "ca:00:00:00:00:01@fe80::1._apple-mobdev2._tcp.local."


def _response() -> bytes:
    return MDNSResponder._build_message(
        [_build_rr(SERVICE, QTYPE_PTR, encode_name(INSTANCE), 120, False)],
        [
            _build_rr(INSTANCE, QTYPE_SRV, _encode_srv(0, 0, 62078, "device.local."), 120, True),
            _build_rr(INSTANCE, QTYPE_TXT, _encode_txt({"identifier": "X"}), 120, True),
        ],
    )


class _FakeTransport:
    """A datagram transport whose first ``failing_sends`` sends fail the way asyncio reports it."""

    def __init__(self, queue: "asyncio.Queue[tuple[bytes, Any]]", failing_sends: int) -> None:
        self.protocol = _DatagramProtocol(queue)
        self.failing_sends = failing_sends
        self.sent = 0

    def sendto(self, data: bytes, addr: Any) -> None:
        self.sent += 1
        if self.sent <= self.failing_sends:
            # asyncio hands a failed sendto() to the protocol instead of raising it
            self.protocol.error_received(OSError(errno.EHOSTUNREACH, "No route to host"))

    def get_protocol(self) -> _DatagramProtocol:
        return self.protocol

    def close(self) -> None:
        pass


@pytest.fixture
def mdns(monkeypatch):
    """Script what browse_service() receives and how many of its sends fail."""
    state = SimpleNamespace(packets=[], failing_sends=0)

    async def open_mdns_sockets():
        queue: asyncio.Queue[tuple[bytes, Any]] = asyncio.Queue()
        for packet in state.packets:
            queue.put_nowait((packet, ("192.0.2.1", 5353)))
        transport = _FakeTransport(queue, state.failing_sends)
        return [(transport, SimpleNamespace(family=socket.AF_INET))], queue

    monkeypatch.setattr(bonjour, "_open_mdns_sockets", open_mdns_sockets)
    return state


async def test_a_device_answering_more_than_once_is_listed_once(mdns):
    # One answer per interface, plus re-announcements: the same SRV record arrives several times.
    mdns.packets = [_response(), _response(), _response()]

    instances = await browse_service(SERVICE, timeout=0.05)

    assert [(instance.instance, instance.port) for instance in instances] == [(INSTANCE, 62078)]
