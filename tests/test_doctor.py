"""Host checks: each one must report what was observed, and never guess past it."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from pymobiledevice3 import doctor
from pymobiledevice3.exceptions import MuxException
from pymobiledevice3.osu.os_utils import HostUsbDevice, UsbmuxDaemon

pytestmark = [pytest.mark.cli]

UDID = "00008030-000215140A9A802E"


def _device(connection_type: str) -> Any:
    return SimpleNamespace(
        serial=UDID,
        connection_type=connection_type,
        is_network=connection_type == "Network",
        is_usb=connection_type == "USB",
    )


async def test_a_network_device_proves_wifi_discovery(monkeypatch):
    # Proof beats identity: whatever the daemon is, it plainly found a device over the network.
    monkeypatch.setattr(
        doctor.OSUTILS, "usbmux_daemon", lambda: UsbmuxDaemon(name="whatever", discovers_over_wifi=False)
    )

    check = await doctor._wifi_discovery_check([_device("Network")])

    assert check.status is doctor.Status.OK
    assert "listed over the network" in check.detail


async def test_daemon_without_wifi_support_is_reported_with_the_way_out(monkeypatch):
    monkeypatch.setattr(
        doctor.OSUTILS,
        "usbmux_daemon",
        lambda: UsbmuxDaemon(name="usbmuxd (libimobiledevice)", discovers_over_wifi=False),
    )

    check = await doctor._wifi_discovery_check([_device("USB")])

    assert check.status is doctor.Status.WARNING
    assert "--mobdev2" in (check.hint or "")


async def test_unidentifiable_daemon_is_unknown_not_ok(monkeypatch):
    # Never claim a capability we could neither prove nor attribute.
    monkeypatch.setattr(doctor.OSUTILS, "usbmux_daemon", lambda: None)

    check = await doctor._wifi_discovery_check([])

    assert check.status is doctor.Status.UNKNOWN


async def test_listing_without_connecting_points_at_old_usbmuxd2():
    # usbmuxd2 shipped without `Connect`: listing worked while every service connection failed,
    # which is the failure this check exists to name (pymobiledevice3#1147).
    async def connect(port: int) -> Any:
        raise MuxException("CONNREFUSED")

    device = _device("USB")
    device.connect = connect

    check = await doctor._connect_check([device])

    assert check.status is doctor.Status.PROBLEM
    assert "usbmuxd2" in (check.hint or "")


async def test_connect_probe_closes_what_it_opens():
    closed = []

    async def connect(port: int) -> Any:
        assert port == doctor.LOCKDOWN_PORT
        return SimpleNamespace(close=lambda: closed.append(True))

    device = _device("USB")
    device.connect = connect

    check = await doctor._connect_check([device])

    assert check.status is doctor.Status.OK
    assert closed == [True]


async def test_every_send_failing_is_reported_as_blocked(monkeypatch):
    # The failures arrive through error_received, not from sendto, so a check that only counts
    # sends would call a fully blocked host healthy.
    class FakeProtocol:
        send_errors: ClassVar[list[OSError]] = [OSError("No route to host")]

    class FakeTransport:
        def get_protocol(self) -> Any:
            return FakeProtocol()

        def close(self) -> None:
            pass

    async def open_mdns_sockets() -> Any:
        return [(FakeTransport(), None)], None

    async def send_query_all(transports: Any, pkt: bytes) -> int:
        return 1

    monkeypatch.setattr(doctor, "_open_mdns_sockets", open_mdns_sockets)
    monkeypatch.setattr(doctor, "_send_query_all", send_query_all)
    monkeypatch.setattr(doctor, "MDNS_ERROR_SETTLE_SECONDS", 0)

    check = await doctor._mdns_check()

    assert check.status is doctor.Status.PROBLEM
    assert "refused" in check.detail


async def test_an_unreadable_pair_record_store_is_not_reported_as_empty(monkeypatch, tmp_path: Path):
    # /var/db/lockdown is root-only on macOS; globbing it silently yields nothing, which is not
    # the same as there being no records.
    monkeypatch.setattr(type(doctor.OSUTILS), "pair_record_path", property(lambda self: tmp_path))
    monkeypatch.setattr(doctor.os, "access", lambda path, mode: False)
    monkeypatch.setattr(doctor, "get_home_folder", lambda: tmp_path)
    monkeypatch.setattr(doctor, "iter_remote_pair_records", lambda: iter(()))

    check = doctor._pair_records_check()

    assert "not readable" in check.detail


def test_a_check_shows_the_cost_and_the_fix_on_their_own_lines():
    rendered = repr(
        doctor.Check("Bonjour discovery", doctor.Status.PROBLEM, "blocked", "nothing is found", "allow the terminal")
    )

    lines = rendered.splitlines()
    assert lines[1].strip() == "so: nothing is found"
    assert lines[2].strip() == "fix: allow the terminal"


def test_report_groups_by_what_it_means_for_the_reader():
    report = doctor.Report(
        "env line",
        [
            doctor.Check("works", doctor.Status.OK, "fine"),
            doctor.Check("broken", doctor.Status.PROBLEM, "bad"),
            doctor.Check("absent", doctor.Status.NOT_APPLICABLE, "n/a"),
        ],
    )

    rendered = repr(report)
    assert rendered.startswith("env line")
    assert rendered.index("This works") < rendered.index("This does not") < rendered.index("Not available here")
    assert [check.title for check in report.problems] == ["broken"]


def test_a_clean_report_says_nothing_is_blocking():
    report = doctor.Report("env line", [doctor.Check("works", doctor.Status.OK, "fine")])

    assert "Nothing here is blocking a device connection." in repr(report)


def test_a_device_the_host_sees_but_usbmux_does_not_is_a_problem(monkeypatch):
    # The cable is fine and the OS enumerated the device; usbmux simply is not listing it. That is
    # a different fix from "plug it in", so it must not read the same.
    monkeypatch.setattr(
        type(doctor.OSUTILS),
        "usb_devices_seen_by_host",
        lambda self: [HostUsbDevice(name="iPhone", serial=UDID)],
    )

    check = doctor._host_usb_check([])

    assert check is not None
    assert check.status is doctor.Status.PROBLEM
    assert "usbmux does not" in check.detail


def test_a_host_with_nothing_plugged_in_is_not_an_error(monkeypatch):
    monkeypatch.setattr(type(doctor.OSUTILS), "usb_devices_seen_by_host", lambda self: [])

    check = doctor._host_usb_check([])

    assert check is not None
    assert check.status is doctor.Status.NOT_APPLICABLE


def test_a_platform_that_cannot_be_asked_reports_nothing(monkeypatch):
    monkeypatch.setattr(type(doctor.OSUTILS), "usb_devices_seen_by_host", lambda self: None)

    assert doctor._host_usb_check([]) is None
