from typing import Any

import pytest

from pymobiledevice3.exceptions import TSSError
from pymobiledevice3.restore.recovery import Recovery
from pymobiledevice3.restore.restore import PrefetchedTicket, Restore
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse


def _restore() -> Restore:
    # Bypass __init__ (needs an IPSW and a device); the lookup only touches the prefetch state and the logger.
    restore = Restore.__new__(Restore)
    restore._prefetched_updater_tss = {}
    restore._tss_prefetch_outcomes = []
    return restore


def _prefetched(request: dict[str, Any]) -> PrefetchedTicket:
    return PrefetchedTicket(
        nonce=b"n", response=TSSResponse({"BMU,Ticket": b"ticket"}), ticket_name="BMU,Ticket", request=request
    )


DEVICE_REQUEST = {
    "@BMU,Ticket": True,
    "BMU,BoardID": 13091,
    "BMU,Nonce": b"\x01" * 32,
    "BMU,FirmwareMap": {"Digest": b"\x02" * 32},
}


@pytest.mark.asyncio
async def test_prefetched_ticket_is_served_only_for_the_identical_request():
    restore = _restore()
    # what we signed carries an extra entry (the AP request's @BBTicket); that is fine
    restore._prefetched_updater_tss["T200"] = _prefetched({**DEVICE_REQUEST, "@BBTicket": True})

    served = restore._lookup_prefetched_tss_by_ticket("BMU,Ticket", {"DeviceGeneratedRequest": DEVICE_REQUEST})

    assert served == {"BMU,Ticket": b"ticket"}
    assert restore._tss_prefetch_outcomes == [("T200", "hit")]


@pytest.mark.asyncio
async def test_a_rolled_nonce_or_a_missing_entry_is_a_miss():
    restore = _restore()
    restore._prefetched_updater_tss["T200"] = _prefetched({**DEVICE_REQUEST, "BMU,Nonce": b"\x09" * 32})
    assert restore._lookup_prefetched_tss_by_ticket("BMU,Ticket", {"DeviceGeneratedRequest": DEVICE_REQUEST}) is None

    ours = dict(DEVICE_REQUEST)
    del ours["BMU,BoardID"]
    restore._prefetched_updater_tss["T200"] = _prefetched(ours)
    assert restore._lookup_prefetched_tss_by_ticket("BMU,Ticket", {"DeviceGeneratedRequest": DEVICE_REQUEST}) is None

    assert restore._tss_prefetch_outcomes == [("T200", "miss-drift"), ("T200", "miss-drift")]


@pytest.mark.asyncio
async def test_the_device_can_refuse_the_prefetch_explicitly():
    restore = _restore()
    restore._prefetched_updater_tss["T200"] = _prefetched(dict(DEVICE_REQUEST))

    forced = {"DeviceGeneratedRequest": DEVICE_REQUEST, "MessageForceRepersonalization": True}
    assert restore._lookup_prefetched_tss_by_ticket("BMU,Ticket", forced) is None
    second_loop = {"DeviceGeneratedRequest": DEVICE_REQUEST, "MessageArgUpdaterLoopCount": 1}
    assert restore._lookup_prefetched_tss_by_ticket("BMU,Ticket", second_loop) is None
    first_loop = {"DeviceGeneratedRequest": DEVICE_REQUEST, "MessageArgUpdaterLoopCount": 0}
    assert restore._lookup_prefetched_tss_by_ticket("BMU,Ticket", first_loop) == {"BMU,Ticket": b"ticket"}

    assert restore._tss_prefetch_outcomes == [("T200", "miss-drift"), ("T200", "miss-drift"), ("T200", "hit")]


def test_request_mismatches_compare_bytes_by_content_and_dicts_entry_for_entry():
    assert Restore._request_mismatches(DEVICE_REQUEST, {**DEVICE_REQUEST, "BMU,Nonce": bytearray(b"\x01" * 32)}) == []
    assert Restore._request_mismatches(
        DEVICE_REQUEST, {**DEVICE_REQUEST, "BMU,FirmwareMap": {"Digest": b"\x02" * 32, "Trusted": True}}
    ) == ["BMU,FirmwareMap"]
    assert Restore._request_mismatches(DEVICE_REQUEST, {}) == sorted(DEVICE_REQUEST)


def test_a_ticket_that_was_not_prefetched_is_not_looked_up():
    restore = _restore()
    assert restore._lookup_prefetched_tss_by_ticket("Rap,Ticket", {"DeviceGeneratedRequest": {}}) is None
    assert restore._tss_prefetch_outcomes == []


def _recovery() -> Recovery:
    recovery = Recovery.__new__(Recovery)
    recovery.tss_riders = {}
    recovery.tss_riders_applied = False
    return recovery


@pytest.mark.asyncio
async def test_riders_travel_once_in_the_ap_request_without_overriding_it(monkeypatch):
    posted = []

    async def fake_send_receive(self):
        posted.append(self.tags())
        return TSSResponse({"ApImg4Ticket": b"ap", "BMU,Ticket": b"bmu"})

    monkeypatch.setattr(TSSRequest, "send_receive", fake_send_receive)
    recovery = _recovery()
    recovery.tss_riders = {"@BMU,Ticket": True, "BMU,Nonce": b"n", "ApProductionMode": False}

    tss = TSSRequest()
    tss.add_tags({"@ApImg4Ticket": True, "ApProductionMode": True})
    response = await recovery._send_tss_request(tss)

    assert response["BMU,Ticket"] == b"bmu"
    assert recovery.tss_riders_applied is True
    assert posted[0]["@BMU,Ticket"] is True and posted[0]["ApProductionMode"] is True  # the AP entry won
    assert recovery.tss_riders == {}
    await recovery._send_tss_request(TSSRequest())
    assert "@BMU,Ticket" not in posted[1]  # consumed: the RecoveryVariant re-fetch goes without them
    assert recovery.tss_riders_applied is True  # ... and does not forget that the riders were signed


@pytest.mark.asyncio
async def test_a_rejected_combined_request_is_retried_without_the_riders(monkeypatch):
    posted = []

    async def fake_send_receive(self):
        posted.append(self.tags())
        if "@BMU,Ticket" in self.tags():
            raise TSSError("server replied: This device isn't eligible for the requested build")
        return TSSResponse({"ApImg4Ticket": b"ap"})

    monkeypatch.setattr(TSSRequest, "send_receive", fake_send_receive)
    recovery = _recovery()
    recovery.tss_riders = {"@BMU,Ticket": True, "BMU,Nonce": b"n"}

    tss = TSSRequest()
    tss.add_tags({"@ApImg4Ticket": True})
    response = await recovery._send_tss_request(tss)

    assert response["ApImg4Ticket"] == b"ap"
    assert recovery.tss_riders_applied is False
    assert len(posted) == 2 and "@BMU,Ticket" not in posted[1] and "BMU,Nonce" not in posted[1]
    assert posted[1]["@ApImg4Ticket"] is True
