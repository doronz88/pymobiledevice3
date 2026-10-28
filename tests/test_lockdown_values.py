from typing import Any, Optional

import pytest

from pymobiledevice3.exceptions import MissingValueError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


class _Provider(LockdownServiceProvider):
    def __init__(self, values: dict[tuple[Optional[str], Optional[str]], Any]) -> None:
        super().__init__()
        self._values = values

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        if (domain, key) not in self._values:
            raise MissingValueError("MissingValue", None, "27.2")
        return self._values[(domain, key)]


_WIFI = ("com.apple.mobile.wireless_lockdown", "EnableWifiConnections")


@pytest.mark.asyncio
async def test_wifi_connections_are_off_when_never_set() -> None:
    # lockdownd answers MissingValue for the key until it is first set
    assert await _Provider({}).get_enable_wifi_connections() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [True, False])
async def test_wifi_connections_reports_the_stored_value(value: bool) -> None:
    assert await _Provider({_WIFI: value}).get_enable_wifi_connections() is value


class _RecordingProvider(LockdownServiceProvider):
    def __init__(self) -> None:
        super().__init__()
        self.sets: list[tuple[Any, Optional[str], Optional[str]]] = []

    async def set_value(self, value: Any, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        self.sets.append((value, domain, key))
        return {}


@pytest.mark.asyncio
@pytest.mark.parametrize(("value", "stored"), [(True, 1), (False, 0)])
async def test_auto_answer_calls_sets_the_accessibility_preference(value: bool, stored: int) -> None:
    provider = _RecordingProvider()
    await provider.set_auto_answer_calls(value)
    assert provider.sets == [(stored, "com.apple.Accessibility", "CallAudioRoutingAutoAnswerEnabledPreference")]
