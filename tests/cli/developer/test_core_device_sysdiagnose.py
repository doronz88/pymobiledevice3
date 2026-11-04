from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.cli.developer import core_device
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

pytestmark = [pytest.mark.cli]

UDID = "00008150-001074523440401C"
FILENAME = "sysdiagnose_2026.11.05_12-00-00+0200_iPhone-OS_iPhone_23A000.tar.gz"


class _AsyncContext:
    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None


class _UsbmuxLockdown(_AsyncContext):
    pass


@pytest.fixture
def pulled_through(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Fake the capture and record which provider the sysdiagnose is pulled through."""
    providers: list[Any] = []

    class FakeDiagnosticsService(_AsyncContext):
        def __init__(self, rsd: object) -> None:
            pass

        async def capture_sysdiagnose(self, is_dry_run: bool) -> Any:
            return SimpleNamespace(preferred_filename=FILENAME)

    class FakeCrashReportsManager(_AsyncContext):
        def __init__(self, lockdown: object) -> None:
            providers.append(lockdown)
            self.afc = self

        async def pull(self, relative_src: str, dst: str) -> None:
            assert relative_src == f"/DiagnosticLogs/sysdiagnose/{FILENAME}"
            Path(dst).write_bytes(b"sysdiagnose")

    monkeypatch.setattr(core_device, "DiagnosticsServiceService", FakeDiagnosticsService)
    monkeypatch.setattr(core_device, "CrashReportsManager", FakeCrashReportsManager)
    return providers


def _usbmux(monkeypatch: pytest.MonkeyPatch, listed: Optional[bool]) -> _UsbmuxLockdown:
    """Make usbmuxd list the device (``True``), not list it (``False``), or not be running (``None``)."""
    lockdown = _UsbmuxLockdown()

    async def fake_select_device(udid: Any = None, connection_type: Any = None, usbmux_address: Any = None) -> Any:
        assert udid == UDID
        if listed is None:
            raise ConnectionFailedToUsbmuxdError()
        return object() if listed else None

    async def fake_create_using_usbmux(serial: Any = None, **kwargs: Any) -> _UsbmuxLockdown:
        assert listed and serial == UDID
        return lockdown

    monkeypatch.setattr(core_device, "select_device", fake_select_device)
    monkeypatch.setattr(core_device, "create_using_usbmux", fake_create_using_usbmux)
    return lockdown


def _sysdiagnose(tmp_path: Path) -> Any:
    rsd = cast(RemoteServiceDiscoveryService, SimpleNamespace(udid=UDID))
    core_device.core_device_sysdiagnose(rsd, tmp_path)
    return rsd


def test_sysdiagnose_downloads_over_usbmux_when_listed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pulled_through: list[Any]
) -> None:
    lockdown = _usbmux(monkeypatch, listed=True)

    _sysdiagnose(tmp_path)

    assert pulled_through == [lockdown]
    assert (tmp_path / FILENAME).read_bytes() == b"sysdiagnose"


@pytest.mark.parametrize("listed", [False, None], ids=["not-listed", "no-usbmuxd"])
def test_sysdiagnose_downloads_through_rsd_without_usbmux(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pulled_through: list[Any], listed: Optional[bool]
) -> None:
    # --rsd to a device usbmuxd does not know: pull through the tunnel instead of failing
    _usbmux(monkeypatch, listed=listed)

    rsd = _sysdiagnose(tmp_path)

    assert pulled_through == [rsd]
    assert (tmp_path / FILENAME).read_bytes() == b"sysdiagnose"
