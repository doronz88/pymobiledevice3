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
