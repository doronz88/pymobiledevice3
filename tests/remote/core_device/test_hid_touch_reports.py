import pytest
import typer

from pymobiledevice3.cli.developer.core_device import _group_coordinates
from pymobiledevice3.remote.core_device import hid_service
from pymobiledevice3.remote.core_device.hid_service import (
    TOUCHSCREEN_STATE_CONTACT,
    TOUCHSCREEN_STATE_RELEASE,
    TouchscreenContact,
    build_multitouch_report,
    build_touchscreen_report,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

TIMESTAMP = 0x0102030405
TRAILER = b"\x02\x00\x00\x00" + TIMESTAMP.to_bytes(6, "little") + bytes(8)


def test_single_touch_report_layout_is_unchanged():
    report = build_touchscreen_report(TOUCHSCREEN_STATE_CONTACT, 375, 812, TIMESTAMP)
    assert report == bytes([0x09, 0x01, 0x05, 0xC2, 0x77, 0x01, 0x2C, 0x03]) + bytes(32) + TRAILER


def test_single_touch_release_is_identity_two_without_touch_bits():
    report = build_touchscreen_report(TOUCHSCREEN_STATE_RELEASE, 1, 2, TIMESTAMP)
    assert report[:8] == bytes([0x09, 0x01, 0x05, 0x02, 0x01, 0x00, 0x02, 0x00])


def test_single_touch_report_matches_multitouch_identity_two():
    assert build_touchscreen_report(TOUCHSCREEN_STATE_CONTACT, 10, 20, TIMESTAMP) == build_multitouch_report(
        [TouchscreenContact(2, 10, 20)], TIMESTAMP
    )
    assert build_touchscreen_report(TOUCHSCREEN_STATE_RELEASE, 10, 20, TIMESTAMP) == build_multitouch_report(
        [TouchscreenContact(2, 10, 20, touching=False)], TIMESTAMP
    )


def test_multitouch_report_layout():
    report = build_multitouch_report(
        [TouchscreenContact(2, 0x1234, 0x5678), TouchscreenContact(3, 0x9ABC, 0xDEF0, touching=False)], TIMESTAMP
    )
    assert len(report) == 58
    assert report[:3] == bytes([0x09, 0x02, 0x05])
    assert report[3:8] == bytes([0xC2, 0x34, 0x12, 0x78, 0x56])
    assert report[8:13] == bytes([0x03, 0xBC, 0x9A, 0xF0, 0xDE])
    assert report[13:40] == bytes(27)
    assert report[40:] == TRAILER


def test_multitouch_report_five_contacts():
    report = build_multitouch_report([TouchscreenContact(i, i, i) for i in range(5)], 0)
    assert report[:3] == bytes([0x09, 0x05, 0x05])
    assert [report[3 + 5 * i] for i in range(5)] == [0xC0, 0xC1, 0xC2, 0xC3, 0xC4]
    assert report[28:40] == bytes(12)


def test_multitouch_report_empty_frame():
    report = build_multitouch_report([], 0)
    assert report[:3] == bytes([0x09, 0x00, 0x05])
    assert report[3:40] == bytes(37)


def test_timestamp_is_truncated_to_48_bits():
    assert build_multitouch_report([], (1 << 64) - 1)[44:50] == b"\xff" * 6


@pytest.mark.parametrize(
    "contacts",
    [
        [TouchscreenContact(i, 0, 0) for i in range(5)] + [TouchscreenContact(0, 0, 0)],
        [TouchscreenContact(1, 0, 0), TouchscreenContact(1, 5, 5)],
        [TouchscreenContact(5, 0, 0)],
        [TouchscreenContact(-1, 0, 0)],
    ],
)
def test_multitouch_report_rejects_invalid_contacts(contacts):
    with pytest.raises(ValueError):
        build_multitouch_report(contacts)


def _recording_service(monkeypatch):
    sent = []

    async def send_report(service_id, report):
        sent.append((service_id, report))

    async def sleep(delay):
        pass

    monkeypatch.setattr(hid_service.asyncio, "sleep", sleep)
    service = hid_service.UniversalHIDServiceService(RemoteServiceDiscoveryService(("127.0.0.1", 0)))
    monkeypatch.setattr(service, "send_report", send_report)
    return service, sent


def _contacts(report):
    return [
        (
            report[3 + 5 * i],
            int.from_bytes(report[4 + 5 * i : 6 + 5 * i], "little"),
            int.from_bytes(report[6 + 5 * i : 8 + 5 * i], "little"),
        )
        for i in range(report[1])
    ]


@pytest.mark.asyncio
async def test_multi_tap_sends_down_then_up_with_stable_identities(monkeypatch):
    service, sent = _recording_service(monkeypatch)
    await service.multi_tap([(10, 20), (30, 40)])
    assert [service_id for service_id, _ in sent] == [hid_service.DIGITIZER_SURFACE_MAIN_TOUCHSCREEN] * 2
    assert [_contacts(report) for _, report in sent] == [
        [(0xC0, 10, 20), (0xC1, 30, 40)],
        [(0x00, 10, 20), (0x01, 30, 40)],
    ]


@pytest.mark.asyncio
async def test_multi_drag_moves_all_contacts_together(monkeypatch):
    service, sent = _recording_service(monkeypatch)
    await service.multi_drag([(0, 0, 100, 200), (1000, 1000, 900, 800)], steps=2, duration=0)
    assert [_contacts(report) for _, report in sent] == [
        [(0xC0, 0, 0), (0xC1, 1000, 1000)],
        [(0xC0, 50, 100), (0xC1, 950, 900)],
        [(0xC0, 100, 200), (0xC1, 900, 800)],
        [(0x00, 100, 200), (0x01, 900, 800)],
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 6])
async def test_multi_drag_rejects_bad_finger_count_before_sending(monkeypatch, count):
    service, sent = _recording_service(monkeypatch)
    with pytest.raises(ValueError):
        await service.multi_drag([(0, 0, 1, 1)] * count)
    assert sent == []


def test_cli_groups_coordinates_per_finger():
    assert _group_coordinates([1, 2, 3, 4], 2) == [(1, 2), (3, 4)]
    with pytest.raises(typer.BadParameter):
        _group_coordinates([1, 2, 3], 2)
    with pytest.raises(typer.BadParameter):
        _group_coordinates([], 4)
    with pytest.raises(typer.BadParameter):
        _group_coordinates([0] * 12, 2)
