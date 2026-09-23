"""A browse aimed at one named device stops when it finds it.

Listing every device on the network has to sit out the whole window, since any of them may still
be announcing. Asking for one specific UDID does not: there is exactly one answer worth waiting
for, so the lookup returns as soon as it arrives and the remaining window is not spent.
"""

import asyncio
import socket
from types import SimpleNamespace
from typing import Any

import pytest

from pymobiledevice3 import bonjour
from pymobiledevice3.bonjour import (
    QTYPE_A,
    QTYPE_PTR,
    QTYPE_SRV,
    QTYPE_TXT,
    MDNSResponder,
    _build_rr,
    _DatagramProtocol,
    _encode_srv,
    _encode_txt,
    encode_name,
)

pytestmark = [pytest.mark.cli]

SERVICE = "_apple-mobdev2._tcp.local."
INSTANCE = "ca:00:00:00:00:01@fe80::1._apple-mobdev2._tcp.local."
# Long enough that sitting out the window is unmistakable next to an early return.
TIMEOUT = 30.0


def _answer() -> bytes:
    return MDNSResponder._build_message(
        [_build_rr(SERVICE, QTYPE_PTR, encode_name(INSTANCE), 120, False)],
        [
            _build_rr(INSTANCE, QTYPE_SRV, _encode_srv(0, 0, 62078, "device.local."), 120, True),
            _build_rr(INSTANCE, QTYPE_TXT, _encode_txt({"identifier": "X"}), 120, True),
            _build_rr("device.local.", QTYPE_A, socket.inet_aton("192.0.2.10"), 120, True),
        ],
    )


class _FakeTransport:
    def __init__(self, queue: "asyncio.Queue[tuple[bytes, Any]]") -> None:
        self.protocol = _DatagramProtocol(queue)

    def sendto(self, data: bytes, addr: Any) -> None:
        pass

    def get_protocol(self) -> _DatagramProtocol:
        return self.protocol

    def close(self) -> None:
        pass


@pytest.fixture
def mdns(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """One answer arrives immediately; nothing else ever does, so the window would run out."""
    state = SimpleNamespace(packets=[_answer()])

    async def open_mdns_sockets():
        queue: asyncio.Queue[tuple[bytes, Any]] = asyncio.Queue()
        for packet in state.packets:
            queue.put_nowait((packet, ("192.0.2.1", 5353)))
        return [(_FakeTransport(queue), SimpleNamespace(family=socket.AF_INET))], queue

    monkeypatch.setattr(bonjour, "_open_mdns_sockets", open_mdns_sockets)
    monkeypatch.setattr(bonjour, "_warned_multicast_blocked", False)
    monkeypatch.setattr(bonjour._Adapters, "pick_iface_for_ip", lambda self, ip, fam, sid: "eth0")
    return state


async def _elapsed(coro) -> tuple[Any, float]:
    loop = asyncio.get_running_loop()
    start = loop.time()
    return await coro, loop.time() - start


async def test_named_device_returns_without_waiting_out_the_window(mdns, monkeypatch):
    from pymobiledevice3.cli import cli_common

    async def one_lockdown(udid=None, **kwargs):
        # get_mobdev2_lockdowns yields per matching advert; drive it off the scripted browse.
        async for instance in bonjour.iter_browse_mobdev2(timeout=TIMEOUT):
            yield instance.addresses[0].full_ip, SimpleNamespace(udid=udid, close=None)

    monkeypatch.setattr(cli_common, "get_mobdev2_lockdowns", one_lockdown)

    devices, elapsed = await _elapsed(cli_common.get_mobdev2_devices(udid="TARGET"))

    assert len(devices) == 1
    assert elapsed < TIMEOUT / 3, f"took {elapsed:.1f}s of a {TIMEOUT}s window"


# Generous enough to survive a coarse clock (Windows rounds to ~16ms and has undershot a 0.2s
# window by 12ms), strict enough that returning at the first answer still fails this.
LISTING_WINDOW = 0.2
LISTING_MIN_FRACTION = 0.5


async def test_listing_every_device_still_uses_the_whole_window(mdns, monkeypatch):
    from pymobiledevice3.cli import cli_common

    async def all_lockdowns(udid=None, **kwargs):
        async for instance in bonjour.iter_browse_mobdev2(timeout=LISTING_WINDOW):
            yield instance.addresses[0].full_ip, SimpleNamespace(udid="ANY", close=None)

    monkeypatch.setattr(cli_common, "get_mobdev2_lockdowns", all_lockdowns)

    # Without a udid the generator is drained, so the browse runs to its timeout rather than
    # stopping at the first answer -- which arrives immediately here.
    devices, elapsed = await _elapsed(cli_common.get_mobdev2_devices())

    assert len(devices) == 1
    assert elapsed >= LISTING_WINDOW * LISTING_MIN_FRACTION, (
        f"returned in {elapsed:.2f}s, expected to sit out most of the {LISTING_WINDOW}s window"
    )


async def test_iter_browse_wrappers_are_closeable():
    # Each wrapper must hand back a real async generator: the targeted lookups aclose() them in a
    # finally, which an AsyncIterable would not support.
    for factory in (bonjour.iter_browse_mobdev2, bonjour.iter_browse_remoted, bonjour.iter_browse_remotepairing):
        generator = factory(timeout=0.01)
        assert hasattr(generator, "aclose"), factory.__name__
        await generator.aclose()
