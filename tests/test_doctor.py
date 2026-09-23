"""Host checks: each one must report what was observed, and never guess past it."""

import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional, cast

import pytest
from packaging.version import Version
from typer.testing import CliRunner

from pymobiledevice3 import __main__, bonjour, doctor
from pymobiledevice3.cli import doctor as cli_doctor
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, MuxException
from pymobiledevice3.osu import posix_util
from pymobiledevice3.osu.os_utils import HostUsbDevice, UsbmuxDaemon, service_binary
from pymobiledevice3.services import mobile_image_mounter

pytestmark = [pytest.mark.cli]

# Rendering is styled at the source; assertions are about the words, not the escape codes (which
# typer.echo drops anyway whenever the output is not a terminal).
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _ANSI.sub("", text)


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
    # sends would call a fully blocked host healthy. bonjour owns that rule; this pins the report.
    async def probe_multicast(*args: Any, **kwargs: Any) -> tuple[int, list[Exception]]:
        return 3, [OSError("No route to host")] * 3

    monkeypatch.setattr(doctor, "probe_multicast", probe_multicast)

    check = await doctor._mdns_check()

    assert check.status is doctor.Status.PROBLEM
    assert "refused" in check.detail


async def test_a_host_where_some_interfaces_answer_is_fine(monkeypatch):
    async def probe_multicast(*args: Any, **kwargs: Any) -> tuple[int, list[Exception]]:
        return 3, [OSError("loopback refuses")]

    monkeypatch.setattr(doctor, "probe_multicast", probe_multicast)

    check = await doctor._mdns_check()

    assert check.status is doctor.Status.OK
    assert "2 of 3" in check.detail


async def test_an_unreadable_pair_record_store_is_not_reported_as_empty(monkeypatch, tmp_path: Path):
    # /var/db/lockdown is root-only on macOS; globbing it silently yields nothing, which is not
    # the same as there being no records.
    monkeypatch.setattr(type(doctor.OSUTILS), "pair_record_path", property(lambda self: tmp_path))
    monkeypatch.setattr(doctor.os, "access", lambda path, mode: False)
    monkeypatch.setattr(doctor, "get_home_folder", lambda: tmp_path)
    monkeypatch.setattr(doctor, "iter_remote_pair_records", lambda: iter(()))

    check = await doctor._pair_records_check()

    assert "not readable" in check.detail


def test_a_check_shows_the_cost_and_the_fix_on_their_own_lines():
    rendered = _plain(
        repr(
            doctor.Check(
                "Bonjour discovery", doctor.Status.PROBLEM, "blocked", "nothing is found", "allow the terminal"
            )
        )
    )

    lines = rendered.splitlines()
    assert lines[1].strip() == "so:  nothing is found"
    assert lines[2].strip() == "fix: allow the terminal"


def test_report_separates_the_host_from_the_device():
    # The two answer different questions, and someone fixing one should not sift the other.
    report = doctor.Report(
        "env line",
        [doctor.Check("host-ok", doctor.Status.OK, "fine"), doctor.Check("host-bad", doctor.Status.PROBLEM, "bad")],
        [doctor.Check("device-ok", doctor.Status.OK, "ready")],
    )

    rendered = _plain(repr(report))
    assert rendered.startswith("env line")
    assert rendered.index("Host — this works") < rendered.index("Host — this does not")
    assert rendered.index("Host — this does not") < rendered.index("Device — this works")
    assert [check.title for check in report.problems] == ["host-bad"]


def test_a_host_with_no_device_says_only_the_host_was_checked():
    report = doctor.Report("env line", [doctor.Check("host-ok", doctor.Status.OK, "fine")], [])

    assert "No device is attached" in _plain(repr(report))


def test_a_clean_report_says_nothing_is_blocking():
    report = doctor.Report("env line", [doctor.Check("works", doctor.Status.OK, "fine")])

    assert "Nothing here is blocking a device connection." in _plain(repr(report))


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


# --- host USB enumeration, per platform ---------------------------------------


def _sysfs_device(root: Path, node: str, vendor: str, serial: Optional[str], product: Optional[str]) -> None:
    entry = root / node
    entry.mkdir()
    (entry / "idVendor").write_text(vendor + "\n")
    if serial is not None:
        (entry / "serial").write_text(serial + "\n")
    if product is not None:
        (entry / "product").write_text(product + "\n")


def test_linux_reads_apple_devices_out_of_sysfs(monkeypatch, tmp_path: Path):
    # Same data lsusb parses, without depending on usbutils being installed.
    _sysfs_device(tmp_path, "1-1", "05ac", "00008030000215140A9A802E", "iPhone")
    _sysfs_device(tmp_path, "2-1", "8087", "somehub", "Integrated Hub")  # not Apple
    _sysfs_device(tmp_path, "1-1:1.0", "05ac", None, None)  # an interface node, not the device
    monkeypatch.setattr(posix_util, "_LINUX_USB_DEVICES", tmp_path)

    devices = posix_util.Linux().usb_devices_seen_by_host()

    assert devices is not None
    assert [(device.name, device.serial) for device in devices] == [("iPhone", UDID)]


def test_linux_without_sysfs_cannot_answer(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(posix_util, "_LINUX_USB_DEVICES", tmp_path / "absent")

    assert posix_util.Linux().usb_devices_seen_by_host() is None


def test_a_udid_is_spelled_the_way_usbmux_spells_it():
    # Both IOKit and sysfs report a modern UDID without its separator.
    assert posix_util._with_udid_separator("00008030000215140A9A802E") == UDID
    # A 40-character legacy UDID has no separator to restore.
    legacy = "a" * 40
    assert posix_util._with_udid_separator(legacy) == legacy


# --- failures must be reported, never raised ----------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ConnectionFailedToUsbmuxdError("refused"),
        PermissionError("no access to /var/run/usbmuxd"),
        OSError("Name or service not known"),
    ],
    ids=["refused", "no-permission", "unresolvable-address"],
)
async def test_an_unreachable_daemon_is_a_check_not_a_traceback(monkeypatch, error):
    # A host whose usbmux cannot be reached is the main thing doctor exists to explain; crashing
    # would also cost every later check, which is exactly when they matter most.
    async def list_devices():
        raise error

    monkeypatch.setattr(doctor.usbmux, "list_devices", list_devices)

    checks = await doctor._usbmux_checks()

    assert [check.status for check in checks] == [doctor.Status.PROBLEM]
    assert checks[0].title == "usbmux daemon"
    assert checks[0].impact and checks[0].hint


async def test_mdns_sockets_that_cannot_be_opened_are_reported(monkeypatch):
    async def probe_multicast(*args: Any, **kwargs: Any) -> tuple[int, list[Exception]]:
        raise OSError("Address already in use")

    monkeypatch.setattr(doctor, "probe_multicast", probe_multicast)

    check = await doctor._mdns_check()

    assert check.status is doctor.Status.PROBLEM
    assert "no socket could be opened" in check.detail


# --- only iOS devices, and only the link this check is about -------------------


@pytest.mark.parametrize(
    "serial",
    ["F0T1234567890AB", "CPID:8030 CPFM:03 ECID:000215140A9A802E"],
    ids=["magic-keyboard", "recovery-mode"],
)
def test_other_apple_usb_hardware_is_not_a_udid(serial):
    # Apple's vendor id also covers keyboards, trackpads and displays. usbmux never lists those,
    # so counting them would accuse a healthy daemon of being blind.
    assert not posix_util._looks_like_udid(serial)


def test_both_udid_shapes_are_recognized():
    assert posix_util._looks_like_udid("00008030000215140A9A802E")
    assert posix_util._looks_like_udid(UDID)
    assert posix_util._looks_like_udid("a" * 40)


def test_a_device_listed_over_usb_is_matched_however_it_is_spelled(monkeypatch):
    # The host reports the UDID without its separator; usbmux prints it with one.
    monkeypatch.setattr(
        type(doctor.OSUTILS),
        "usb_devices_seen_by_host",
        lambda self: [HostUsbDevice(name="iPhone", serial=UDID)],
    )
    listed = _device("USB")
    listed.serial = UDID.replace("-", "")
    listed.matches_udid = lambda udid: udid.replace("-", "") == UDID.replace("-", "")

    check = doctor._host_usb_check([listed])

    assert check is not None
    assert check.status is doctor.Status.OK


async def test_the_connect_probe_prefers_usb_over_wifi():
    # The daemon's `Connect` support is a USB-side story, and a Wi-Fi entry may be asleep.
    attempted = []

    def _candidate(connection_type: str) -> Any:
        device = _device(connection_type)

        async def connect(port: int) -> Any:
            attempted.append(connection_type)
            return SimpleNamespace(close=lambda: None)

        device.connect = connect
        return device

    await doctor._connect_check([_candidate("Network"), _candidate("USB")])

    assert attempted == ["USB"]


async def test_a_sleeping_device_times_out_instead_of_hanging(monkeypatch):
    async def connect(port: int) -> Any:
        await asyncio.sleep(3600)

    monkeypatch.setattr(doctor, "CONNECT_PROBE_TIMEOUT", 0.01)
    device = _device("Network")
    device.connect = connect

    check = await doctor._connect_check([device])

    assert check.status is doctor.Status.PROBLEM
    assert "timed out" in check.detail


# --- daemon identification, the parse-heavy bits -------------------------------


def test_the_avahi_linkage_is_read_from_whatever_is_readable(tmp_path: Path):
    linked = tmp_path / "usbmuxd2"
    linked.write_bytes(b"\x7fELF...libavahi-client.so.3...")
    plain = tmp_path / "usbmuxd"
    plain.write_bytes(b"\x7fELF...libusb-1.0.so.0...")

    assert posix_util._links_mdns(linked) is True
    assert posix_util._links_mdns(plain) is False
    # The daemon runs as root, so an ordinary user cannot read its /proc entries.
    assert posix_util._links_mdns(tmp_path / "unreadable") is None


@pytest.mark.parametrize(
    ("image_path", "expected"),
    [
        (r'"C:\Apple\AppleMobileDeviceService.exe" -k netsvcs', r"C:\Apple\AppleMobileDeviceService.exe"),
        (r"C:\Program Files\Apple\AMDS.exe", r"C:\Program Files\Apple\AMDS.exe"),
        (r"C:\Program Files\Apple\AMDS.exe -k foo", r"C:\Program Files\Apple\AMDS.exe"),
        (r"C:\Apple\noextension", r"C:\Apple\noextension"),
    ],
    ids=["quoted-with-args", "unquoted-with-spaces", "unquoted-with-args", "no-suffix"],
)
def test_a_service_image_path_yields_just_the_executable(image_path: str, expected: str):
    # An unquoted ImagePath may contain spaces, so arguments cannot be split off on whitespace.
    assert service_binary(image_path) == expected


# --- the command itself --------------------------------------------------------


def _report(*checks: doctor.Check) -> doctor.Report:
    return doctor.Report("env line", list(checks))


def _scoped_report(host: list[doctor.Check], device: list[doctor.Check]) -> doctor.Report:
    return doctor.Report("env line", host, device)


@pytest.mark.parametrize("arguments", [[], ["--json"]], ids=["text", "json"])
def test_a_broken_host_fails_the_command_in_both_output_modes(monkeypatch, arguments: list[str]):
    # A script reading the machine-readable form must not pass on a host the report calls broken.
    async def run_checks() -> doctor.Report:
        return _report(doctor.Check("Bonjour discovery", doctor.Status.PROBLEM, "blocked"))

    monkeypatch.setattr(cli_doctor, "run_checks", run_checks)

    result = CliRunner().invoke(__main__.app, ["doctor", *arguments])

    assert result.exit_code == 1


def test_a_healthy_host_passes_and_json_carries_every_field(monkeypatch):
    async def run_checks() -> doctor.Report:
        return _report(doctor.Check("Wi-Fi devices", doctor.Status.OK, "fine", "no cost", "no fix"))

    monkeypatch.setattr(cli_doctor, "run_checks", run_checks)

    result = CliRunner().invoke(__main__.app, ["doctor", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    # The environment line is the first thing wanted in a pasted bug report.
    assert payload["environment"] == "env line"
    assert payload["checks"][0] == {
        "scope": "Host",
        "title": "Wi-Fi devices",
        "status": "OK",
        "detail": "fine",
        "impact": "no cost",
        "hint": "no fix",
    }


async def test_running_every_check_on_this_host_produces_a_report():
    # The whole point of the guard: whatever this machine's state, a report comes back.
    report = await doctor.run_checks()

    assert report.environment
    assert report.checks


# --- the device, when one is attached ------------------------------------------


class _FakeLockdownClient:
    def __init__(self, paired: bool = True, version: str = "17.4", developer_mode: bool = True) -> None:
        self.paired = paired
        self.product_type = "iPhone15,4"
        self.product_version = version
        self._developer_mode = developer_mode
        self.closed = False

    async def get_developer_mode_status(self) -> bool:
        return self._developer_mode

    async def close(self) -> None:
        self.closed = True


def _attach(monkeypatch, lockdown: _FakeLockdownClient, mounted: bool = True) -> None:
    async def create_using_usbmux(serial=None, **kwargs):
        # Pairing here would pop a trust dialog on someone's device just for running a diagnostic.
        assert kwargs.get("autopair") is False
        return lockdown

    class _Mounter:
        def __init__(self, lockdown=None) -> None:
            pass

        async def __aenter__(self) -> "_Mounter":
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def is_image_mounted(self, image_type: str) -> bool:
            return mounted

    monkeypatch.setattr(doctor, "create_using_usbmux", create_using_usbmux)
    monkeypatch.setattr(doctor, "MobileImageMounterService", _Mounter)


async def test_no_device_means_no_device_section(monkeypatch):
    assert await doctor._device_checks([]) == []


async def test_a_ready_device_reports_its_version_mode_and_image(monkeypatch):
    _attach(monkeypatch, _FakeLockdownClient())

    checks = await doctor._device_checks([_device("USB")])

    assert [check.title for check in checks] == ["Device", "Developer mode", "Developer image"]
    assert all(check.status is doctor.Status.OK for check in checks)
    assert "iPhone15,4 running 17.4" in checks[0].detail


async def test_an_unpaired_device_is_reported_without_pairing_it(monkeypatch):
    lockdown = _FakeLockdownClient(paired=False)
    _attach(monkeypatch, lockdown)

    checks = await doctor._device_checks([_device("USB")])

    # Stops at the identity: everything after it would be refused anyway.
    assert [check.title for check in checks] == ["Device"]
    assert checks[0].status is doctor.Status.WARNING
    assert lockdown.closed


async def test_developer_mode_is_not_a_concept_before_ios_16(monkeypatch):
    _attach(monkeypatch, _FakeLockdownClient(version="15.7", developer_mode=False))

    checks = await doctor._device_checks([_device("USB")])

    mode = next(check for check in checks if check.title == "Developer mode")
    assert mode.status is doctor.Status.NOT_APPLICABLE


async def test_developer_mode_off_says_what_it_costs(monkeypatch):
    _attach(monkeypatch, _FakeLockdownClient(developer_mode=False))

    checks = await doctor._device_checks([_device("USB")])

    mode = next(check for check in checks if check.title == "Developer mode")
    assert mode.status is doctor.Status.WARNING
    assert mode.impact and mode.hint


@pytest.mark.parametrize(
    ("version", "expected"), [("17.4", "Personalized"), ("16.7", "Developer")], ids=["ios17", "ios16"]
)
async def test_the_image_type_follows_the_os_version(monkeypatch, version: str, expected: str):
    _attach(monkeypatch, _FakeLockdownClient(version=version), mounted=False)

    checks = await doctor._device_checks([_device("USB")])

    image = next(check for check in checks if check.title == "Developer image")
    assert expected in image.detail
    assert image.status is doctor.Status.WARNING


async def test_the_lockdown_connection_is_always_closed(monkeypatch):
    lockdown = _FakeLockdownClient()
    _attach(monkeypatch, lockdown)

    await doctor._device_checks([_device("USB")])

    assert lockdown.closed


# --- drift: the doctor must not restate rules that live elsewhere ---------------


@pytest.mark.parametrize("version", ["14.8", "15.7", "16.0", "16.7.1", "17.0", "17.4", "18.0", "26.1", "27.2"])
def test_the_image_type_reported_is_the_one_mounting_would_use(version: str):
    # doctor reports which image is mounted; auto_mount decides which to mount. If those ever
    # disagree, the report is confidently wrong -- so they must come from the same rule.
    lockdown = cast(Any, SimpleNamespace(product_version=version))
    personalized = mobile_image_mounter.uses_personalized_image(lockdown)

    expected = (
        mobile_image_mounter.PersonalizedImageMounter.IMAGE_TYPE
        if personalized
        else mobile_image_mounter.DeveloperDiskImageMounter.IMAGE_TYPE
    )
    assert mobile_image_mounter.image_type_for_device(lockdown) == expected
    # and the cutoff itself is where the mounters say it is
    assert personalized == (Version(version) >= mobile_image_mounter.PERSONALIZED_IMAGE_MIN_VERSION)


@pytest.mark.parametrize(
    ("sent", "errors", "blocked"),
    [
        (0, [], False),
        (3, [], False),
        (3, [OSError("x")], False),
        (3, [OSError("x")] * 2, False),
        (3, [OSError("x")] * 3, True),
        (1, [OSError("x")], True),
    ],
)
def test_the_blocked_verdict_is_bonjours_own(sent: int, errors: list[Exception], blocked: bool):
    # doctor and the browse warning must agree on what "blocked" means; one rule, one answer.
    assert bonjour.is_multicast_blocked(sent, errors) is blocked


def test_doctor_does_not_reach_into_bonjour_internals():
    # Privates drift without warning and carry no compatibility promise. If this needs relaxing,
    # add a public helper to bonjour instead.
    source = (Path(__file__).parent.parent / "pymobiledevice3/doctor.py").read_text()
    assert "_open_mdns_sockets" not in source
    assert "_send_query_all" not in source
    assert "_DatagramProtocol" not in source
