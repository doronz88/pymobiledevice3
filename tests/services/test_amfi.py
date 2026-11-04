from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import AmfiError, ConnectionTerminatedError, DeveloperModeError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services import amfi
from pymobiledevice3.services.amfi import AmfiService

PROFILE_UUID = "11111111-2222-3333-4444-555555555555"
UDID = "00008150-001074523440401C"


class _Connection:
    def __init__(self, reply: dict[str, Any]) -> None:
        self.reply = reply
        self.requests: list[dict[str, Any]] = []
        self.closed = False

    async def __aenter__(self) -> "_Connection":
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        self.closed = True

    async def send_recv_plist(self, data: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(data)
        return self.reply


class _Lockdown:
    def __init__(self, reply: dict[str, Any]) -> None:
        self.connection = _Connection(reply)
        self.service_names: list[str] = []
        self.udid = UDID

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        self.service_names.append(name)
        return cast(ServiceConnection, self.connection)


class _UsbmuxLockdown(_Lockdown):
    def __init__(self, reply: dict[str, Any], usbmux_address: Any = None) -> None:
        super().__init__(reply)
        self.usbmux_address = usbmux_address


@pytest.mark.parametrize(("reply", "expected"), [({"success": True, "status": True}, True), ({"success": True}, None)])
async def test_trust_app_signer_request(reply: dict[str, Any], expected: Any) -> None:
    lockdown = _Lockdown(reply)
    result = await AmfiService(cast(LockdownServiceProvider, lockdown)).trust_app_signer(PROFILE_UUID)
    assert result is expected
    assert lockdown.service_names == ["com.apple.amfi.lockdown"]
    assert lockdown.connection.requests == [{"action": 4, "input_profile_uuid": PROFILE_UUID}]
    assert lockdown.connection.closed


# {"success": False} is what an iOS 27.0 device replies for an unknown profile UUID
@pytest.mark.parametrize("reply", [{"success": False}, {"Error": "some error"}, {}])
async def test_trust_app_signer_failure_raises(reply: dict[str, Any]) -> None:
    lockdown = _Lockdown(reply)
    with pytest.raises(AmfiError):
        await AmfiService(cast(LockdownServiceProvider, lockdown)).trust_app_signer(PROFILE_UUID)
    assert lockdown.connection.closed


def _fake_restart(monkeypatch: pytest.MonkeyPatch, reconnected: Any, listed: bool = True) -> list[tuple[str, Any]]:
    """Simulate the reboot: the heartbeat ends in a disconnect and the usbmux reconnect yields ``reconnected``."""
    events: list[tuple[str, Any]] = []

    class _Heartbeat:
        def __init__(self, lockdown: Any) -> None:
            pass

        async def start(self) -> None:
            events.append(("heartbeat", None))
            raise ConnectionTerminatedError()

    async def fake_retry_create_using_usbmux(retry_timeout: Any = None, **kwargs: Any) -> Any:
        events.append(("reconnect", (retry_timeout, kwargs)))
        return reconnected

    async def fake_select_device(udid: Any = None, connection_type: Any = None, usbmux_address: Any = None) -> Any:
        events.append(("select_device", udid))
        return object() if listed else None

    monkeypatch.setattr(amfi, "HeartbeatService", _Heartbeat)
    monkeypatch.setattr(amfi, "retry_create_using_usbmux", fake_retry_create_using_usbmux)
    monkeypatch.setattr(amfi, "select_device", fake_select_device)
    monkeypatch.setattr(amfi, "UsbmuxLockdownClient", _UsbmuxLockdown)
    return events


async def test_enable_developer_mode_reconnects_to_the_same_device(monkeypatch: pytest.MonkeyPatch) -> None:
    after_restart = _UsbmuxLockdown({"success": True})
    events = _fake_restart(monkeypatch, after_restart)
    lockdown = _UsbmuxLockdown({"success": True}, usbmux_address="/tmp/usbmuxd")

    await AmfiService(cast(LockdownServiceProvider, lockdown)).enable_developer_mode(reconnect_timeout=42)

    assert events == [
        ("heartbeat", None),
        ("reconnect", (42, {"serial": UDID, "usbmux_address": "/tmp/usbmuxd"})),
    ]
    assert lockdown.connection.requests == [{"action": AmfiService.DEVELOPER_MODE_ENABLE}]
    assert after_restart.connection.requests == [{"action": AmfiService.DEVELOPER_MODE_ACCEPT}]


async def test_enable_developer_mode_gives_up_when_the_device_does_not_come_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_restart(monkeypatch, reconnected=None)
    lockdown = _UsbmuxLockdown({"success": True})

    with pytest.raises(DeveloperModeError, match="did not reconnect over usbmux within 42 seconds"):
        await AmfiService(cast(LockdownServiceProvider, lockdown)).enable_developer_mode(reconnect_timeout=42)


async def test_enable_developer_mode_over_rsd_reconnects_through_usbmux(monkeypatch: pytest.MonkeyPatch) -> None:
    # e.g. --rsd to a device that is also plugged in: usbmuxd still knows it by its UDID
    after_restart = _UsbmuxLockdown({"success": True})
    events = _fake_restart(monkeypatch, after_restart, listed=True)
    provider = _Lockdown({"success": True})

    await AmfiService(cast(LockdownServiceProvider, provider)).enable_developer_mode(reconnect_timeout=42)

    assert events == [
        ("select_device", UDID),
        ("heartbeat", None),
        ("reconnect", (42, {"serial": UDID, "usbmux_address": None})),
    ]
    assert after_restart.connection.requests == [{"action": AmfiService.DEVELOPER_MODE_ACCEPT}]


async def test_enable_developer_mode_without_usbmux_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    # --rsd/--tunnel to a device usbmuxd does not list: the reboot leaves nothing to reconnect through
    events = _fake_restart(monkeypatch, reconnected=None, listed=False)
    provider = _Lockdown({"success": True})

    with pytest.raises(DeveloperModeError, match="not connected through usbmux"):
        await AmfiService(cast(LockdownServiceProvider, provider)).enable_developer_mode()

    assert provider.connection.requests == [{"action": AmfiService.DEVELOPER_MODE_ENABLE}]
    assert events == [("select_device", UDID)]
