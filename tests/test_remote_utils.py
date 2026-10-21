import asyncio
import uuid
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.remote import utils


@pytest.fixture(autouse=True)
def no_usb_rsd_addresses(monkeypatch):
    # Keep the IORegistry fast path off real devices; tests that want it patch it back in.
    monkeypatch.setattr(utils.OSUTILS, "usb_rsd_addresses", lambda: None)


@pytest.mark.asyncio
async def test_get_rsds_skips_terminated_endpoint(monkeypatch):
    class TerminatedRsd:
        def __init__(self, address, handshake_uuid=None):
            pass

        async def connect(self):
            raise ConnectionTerminatedError

    def iter_browse_remoted(timeout):
        async def _iter():
            yield SimpleNamespace(addresses=[SimpleNamespace(full_ip="fd00::1")])

        return _iter()

    monkeypatch.setattr(utils, "RemoteServiceDiscoveryService", TerminatedRsd)
    monkeypatch.setattr(utils, "iter_browse_remoted", iter_browse_remoted)
    monkeypatch.setattr(utils, "stop_remoted", nullcontext)
    monkeypatch.setattr(utils, "remoted_handshake_uuid", lambda: None)

    assert await utils.get_rsds() == []


def test_remoted_handshake_uuid_is_resolved_before_remoted_is_suspended(monkeypatch):
    # `remotectl` gets the UUID from remoted itself: asked after the SIGSTOP it hangs until its
    # timeout inside every RSD handshake, and get_rsds ends up skipping the device.
    events = []
    remoted = SimpleNamespace(status=lambda: "running", suspend=lambda: events.append("suspend"))

    monkeypatch.setattr(utils.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(utils, "get_remoted_process", lambda: remoted)
    monkeypatch.setattr(utils, "remoted_handshake_uuid", lambda: events.append("resolve uuid"))

    utils.stop_remoted_if_required()

    assert events == ["resolve uuid", "suspend"]


@pytest.mark.asyncio
async def test_get_rsds_identifies_as_remoted_on_the_ncm_link(monkeypatch):
    # remoted uses the NCM link too, so iOS 27.2+ re-attaches (and resets the tunnel service) unless
    # the handshake there carries remoted's UUID.
    remoted_uuid = uuid.UUID("c9a6e86b-beea-45ea-9332-86f295536960")
    handshake_uuids = []

    class Rsd:
        udid = "UDID"

        def __init__(self, address, handshake_uuid=None):
            handshake_uuids.append(handshake_uuid)

        async def connect(self):
            pass

    def iter_browse_remoted(timeout):
        async def _iter():
            yield SimpleNamespace(addresses=[SimpleNamespace(full_ip="fd00::1")])

        return _iter()

    monkeypatch.setattr(utils, "RemoteServiceDiscoveryService", Rsd)
    monkeypatch.setattr(utils, "iter_browse_remoted", iter_browse_remoted)
    monkeypatch.setattr(utils, "stop_remoted", nullcontext)
    monkeypatch.setattr(utils, "remoted_handshake_uuid", lambda: remoted_uuid)

    assert len(await utils.get_rsds()) == 1
    assert handshake_uuids == [remoted_uuid]


class FakeRsd:
    """An RSD endpoint whose handshake succeeds, fails or never finishes, per address."""

    outcomes: ClassVar[dict[str, Any]] = {}
    closed: ClassVar[list[str]] = []

    def __init__(self, address, handshake_uuid=None):
        self.service = SimpleNamespace(address=address)
        self.udid = None

    async def connect(self):
        outcome = self.outcomes[self.service.address[0]]
        if outcome == "hang":
            await asyncio.Event().wait()
        if isinstance(outcome, BaseException):
            raise outcome
        self.udid = outcome

    async def close(self):
        self.closed.append(self.service.address[0])


@pytest.fixture
def usb(monkeypatch):
    FakeRsd.closed = []
    monkeypatch.setattr(utils, "RemoteServiceDiscoveryService", FakeRsd)
    monkeypatch.setattr(utils, "stop_remoted", nullcontext)
    monkeypatch.setattr(utils, "remoted_handshake_uuid", lambda: None)
    monkeypatch.setattr(utils.OSUTILS, "usb_devices_seen_by_host", list)

    def iter_browse_remoted(timeout):
        raise AssertionError("bonjour should not be browsed")

    monkeypatch.setattr(utils, "iter_browse_remoted", iter_browse_remoted)

    def set_devices(addresses, outcomes):
        monkeypatch.setattr(utils.OSUTILS, "usb_rsd_addresses", lambda: addresses)
        FakeRsd.outcomes = outcomes

    return set_devices


@pytest.mark.asyncio
async def test_get_rsds_finds_usb_devices_on_their_own_links_without_bonjour(usb, monkeypatch):
    # A device whose handshake hangs is given up on (and closed) without holding up the others.
    monkeypatch.setattr(utils, "_USB_HANDSHAKE_TIMEOUT", 0.05)
    usb(
        {"UDID-A": "fe80::1%anri0", "UDID-B": "fe80::2%anri1", "UDID-C": "fe80::9%anri9"},
        {"fe80::1%anri0": "UDID-A", "fe80::9%anri9": "hang", "fe80::2%anri1": "UDID-B"},
    )

    rsds = await utils.get_rsds()

    assert sorted((rsd.service.address[0], rsd.udid) for rsd in rsds) == [
        ("fe80::1%anri0", "UDID-A"),
        ("fe80::2%anri1", "UDID-B"),
    ]
    assert FakeRsd.closed == ["fe80::9%anri9"]


@pytest.mark.asyncio
async def test_get_rsds_only_asks_the_requested_device(usb):
    usb({"UDID-A": "fe80::1%anri0", "UDID-B": "fe80::2%anri1"}, {"fe80::2%anri1": "UDID-B"})

    rsds = await utils.get_rsds(udid="UDID-B")

    assert [rsd.udid for rsd in rsds] == ["UDID-B"]


@pytest.mark.asyncio
async def test_get_rsds_does_not_browse_bonjour_when_the_os_lists_usb_links(usb, monkeypatch):
    # The OS lists every USB device's RSD link: one that does not answer would not answer bonjour's
    # address either, so browsing would only add its window.
    usb({"UDID-A": "fe80::1%anri0"}, {"fe80::1%anri0": ConnectionRefusedError()})

    assert await utils.get_rsds() == []
    assert await utils.get_rsds(udid="NOT-ON-USB") == []


@pytest.mark.asyncio
async def test_get_rsds_leaves_remoted_alone_when_no_usb_device_is_up(usb, monkeypatch):
    # Nothing to handshake with: suspending remoted would only disturb it (and require root).
    usb({}, {})

    def stop_remoted():
        raise AssertionError("remoted should not be suspended")

    monkeypatch.setattr(utils, "stop_remoted", stop_remoted)

    assert await utils.get_rsds() == []


@pytest.mark.asyncio
async def test_get_rsds_waits_for_a_device_whose_link_is_coming_up(usb, monkeypatch):
    # Seen on USB but its RSD link not up yet: wait for it rather than report no device.
    snapshots = iter([{}, {}, {"UDID-A": "fe80::1%anri0"}])
    usb({}, {"fe80::1%anri0": "UDID-A"})
    monkeypatch.setattr(utils.OSUTILS, "usb_rsd_addresses", lambda: next(snapshots))
    monkeypatch.setattr(utils.OSUTILS, "usb_devices_seen_by_host", lambda: [SimpleNamespace(serial="UDID-A")])
    monkeypatch.setattr(utils, "_USB_LINK_POLL_INTERVAL", 0)

    assert [rsd.udid for rsd in await utils.get_rsds()] == ["UDID-A"]


@pytest.mark.asyncio
async def test_get_rsds_gives_up_on_a_link_that_never_comes_up(usb, monkeypatch):
    # e.g. a device without RSD: bounded, and remoted is left alone.
    usb({}, {})
    monkeypatch.setattr(utils.OSUTILS, "usb_devices_seen_by_host", lambda: [SimpleNamespace(serial="UDID-A")])
    monkeypatch.setattr(utils, "_USB_LINK_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(utils, "_USB_LINK_TIMEOUT", 0.05)

    def stop_remoted():
        raise AssertionError("remoted should not be suspended")

    monkeypatch.setattr(utils, "stop_remoted", stop_remoted)

    assert await utils.get_rsds() == []
