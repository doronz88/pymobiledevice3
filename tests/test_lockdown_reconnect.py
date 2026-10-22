import ssl
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError, InvalidConnectionError, LockdownError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.service_connection import ServiceConnection

DROP = "drop"


class FakeService:
    """A lockdownd connection that answers every request, drops it, or replies with a lockdownd error."""

    def __init__(self, failure: Optional[str] = None) -> None:
        self.failure = failure
        self.requests: list[str] = []

    async def send_recv_plist(self, message: dict[str, Any]) -> dict[str, Any]:
        request = message["Request"]
        self.requests.append(request)
        if self.failure == DROP:
            raise ConnectionTerminatedError()
        if self.failure is not None:
            return {"Request": request, "Error": self.failure}
        if request == "StartSession":
            return {"Request": request, "SessionID": "session"}
        return {"Request": request, "Value": {"ProductVersion": "16.4.1"}}

    async def close(self) -> None:
        pass


class FakeLockdownClient(LockdownClient):
    def __init__(self, connections: list[FakeService], product_version: Optional[str]) -> None:
        super().__init__(cast(ServiceConnection, connections[0]), host_id="host", pair_record={"HostID": "host"})
        if product_version is not None:
            self.all_values = {"ProductVersion": product_version}
        self.connections = connections
        self.opened = 0

    async def create_service_connection(
        self, port: int, ssl_context: Optional[ssl.SSLContext] = None, strip_ssl: bool = False
    ) -> ServiceConnection:
        self.opened += 1
        return cast(ServiceConnection, self.connections[min(self.opened, len(self.connections) - 1)])


@pytest.mark.asyncio
@pytest.mark.parametrize("product_version", ["16.4.1", None])
@pytest.mark.parametrize(
    ("failure", "error"),
    [
        (DROP, ConnectionTerminatedError),
        ("InvalidConnection", InvalidConnectionError),
        ("SessionInactive", LockdownError),
    ],
)
async def test_request_gives_up_when_the_reconnected_session_fails_too(
    failure: str, error: type[Exception], product_version: Optional[str]
) -> None:
    # The pairing check that runs after a reconnect must not reconnect again, or a device that
    # fails every request recurses until RecursionError.
    client = FakeLockdownClient([FakeService(failure)], product_version)

    with pytest.raises(error):
        await client._request("GetValue")

    assert client.opened == 1


@pytest.mark.asyncio
async def test_request_retries_on_a_fresh_connection_after_a_drop() -> None:
    dropped = FakeService(DROP)
    fresh = FakeService()
    client = FakeLockdownClient([dropped, fresh], "16.4.1")

    response = await client._request("GetValue")

    assert response == {"Request": "GetValue", "Value": {"ProductVersion": "16.4.1"}}
    assert client.opened == 1
    assert client.paired
    assert dropped.requests == ["GetValue"]
    assert fresh.requests == ["StartSession", "GetValue", "GetValue"]
