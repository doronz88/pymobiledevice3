import asyncio

import pytest

from pymobiledevice3.exceptions import (
    LockdownError,
    MCProtectedError,
    PairingDialogResponsePendingError,
    PairingError,
    PasscodeRequiredError,
    PasswordRequiredError,
    SessionActiveError,
    UserDeniedPairingError,
)
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

    # lockdownd's code is kept apart from the message, which explains it
    assert exc_info.value.error == error
    assert str(exc_info.value) == exception_type.describe()
    assert exc_info.value.identifier == "test-device"
    assert exc_info.value.product_version == "18.0"


@pytest.mark.parametrize(
    ("error", "exception_type"),
    [
        ("PasswordProtected", PasswordRequiredError),
        ("UserDeniedPairing", UserDeniedPairingError),
        ("PairingDialogResponsePending", PairingDialogResponsePendingError),
    ],
)
def test_lockdown_pairing_errors_read_as_a_message(error: str, exception_type: type[PairingError]) -> None:
    # these were built with (code, identifier, version), so their message read as a tuple
    lockdown = object.__new__(UsbmuxLockdownClient)
    lockdown.identifier = "test-device"
    lockdown.all_values = {"ProductVersion": "18.0"}

    with pytest.raises(exception_type) as exc_info:
        lockdown._verify_request_response("Pair", {"Request": "Pair", "Error": error})

    assert str(exc_info.value) == exception_type.describe()


def test_lockdown_unmapped_error_names_the_request_and_code() -> None:
    lockdown = object.__new__(UsbmuxLockdownClient)
    lockdown.identifier = "test-device"
    lockdown.all_values = {"ProductVersion": "18.0"}

    with pytest.raises(LockdownError) as exc_info:
        lockdown._verify_request_response("StartSession", {"Request": "StartSession", "Error": "SessionInactive"})

    assert exc_info.value.error == "SessionInactive"
    assert str(exc_info.value) == "lockdownd failed StartSession: SessionInactive"


@pytest.mark.asyncio
async def test_lockdown_reconnect(lockdown: LockdownClient) -> None:
    d1 = await lockdown.get_date()

    # add some threshold to make sure lockdownd closed the connection on its end
    await asyncio.sleep(LOCKDOWND_SOCKET_SELECT_TIMEOUT + 5)

    d2 = await lockdown.get_date()

    assert d1 < d2
