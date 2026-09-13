import asyncio

import pytest

from pymobiledevice3.exceptions import LockdownError, MCProtectedError, PasscodeRequiredError, SessionActiveError
from pymobiledevice3.lockdown import LockdownClient, UsbmuxLockdownClient

LOCKDOWND_SOCKET_SELECT_TIMEOUT = 60


@pytest.mark.parametrize(
    ("error", "exception_type"),
    [
        ("MCProtected", MCProtectedError),
        ("PasscodeRequired", PasscodeRequiredError),
        ("SessionActive", SessionActiveError),
    ],
)
def test_lockdown_error_mapping(error: str, exception_type: type[LockdownError]) -> None:
    lockdown = object.__new__(UsbmuxLockdownClient)
    lockdown.identifier = "test-device"
    lockdown.all_values = {"ProductVersion": "18.0"}

    with pytest.raises(exception_type) as exc_info:
        lockdown._verify_request_response("Test", {"Request": "Test", "Error": error})

    assert str(exc_info.value) == error
    assert exc_info.value.identifier == "test-device"
    assert exc_info.value.product_version == "18.0"


@pytest.mark.asyncio
async def test_lockdown_reconnect(lockdown: LockdownClient) -> None:
    d1 = await lockdown.get_date()

    # add some threshold to make sure lockdownd closed the connection on its end
    await asyncio.sleep(LOCKDOWND_SOCKET_SELECT_TIMEOUT + 5)

    d2 = await lockdown.get_date()

    assert d1 < d2
