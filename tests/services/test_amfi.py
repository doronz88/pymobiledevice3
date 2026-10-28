from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import AmfiError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.amfi import AmfiService

PROFILE_UUID = "11111111-2222-3333-4444-555555555555"


class _Connection:
    def __init__(self, reply: dict[str, Any]) -> None:
        self.reply = reply
        self.requests: list[dict[str, Any]] = []

    async def send_recv_plist(self, data: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(data)
        return self.reply


class _Lockdown:
    def __init__(self, reply: dict[str, Any]) -> None:
        self.connection = _Connection(reply)
        self.service_names: list[str] = []

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        self.service_names.append(name)
        return cast(ServiceConnection, self.connection)


@pytest.mark.parametrize(("reply", "expected"), [({"success": True, "status": True}, True), ({"success": True}, None)])
async def test_trust_app_signer_request(reply: dict[str, Any], expected: Any) -> None:
    lockdown = _Lockdown(reply)
    result = await AmfiService(cast(LockdownServiceProvider, lockdown)).trust_app_signer(PROFILE_UUID)
    assert result is expected
    assert lockdown.service_names == ["com.apple.amfi.lockdown"]
    assert lockdown.connection.requests == [{"action": 4, "input_profile_uuid": PROFILE_UUID}]


# {"success": False} is what an iOS 27.0 device replies for an unknown profile UUID
@pytest.mark.parametrize("reply", [{"success": False}, {"Error": "some error"}, {}])
async def test_trust_app_signer_failure_raises(reply: dict[str, Any]) -> None:
    lockdown = _Lockdown(reply)
    with pytest.raises(AmfiError):
        await AmfiService(cast(LockdownServiceProvider, lockdown)).trust_app_signer(PROFILE_UUID)
