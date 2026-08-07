import plistlib
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import InstallCoordinationError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.services.install_coordination_proxy import (
    CFURL_MAGIC,
    REQUEST_TYPE_QUERY,
    InstallCoordinationProxyService,
    decode_url,
    encode_url,
)

INSTALL_PATH = "file:///Applications/Preferences.app/"


def _service(response: dict[str, Any]) -> tuple[InstallCoordinationProxyService, list[dict[str, Any]]]:
    sent: list[dict[str, Any]] = []

    class FakeConnection:
        async def send_request(self, request: dict[str, Any]) -> None:
            sent.append(request)

        async def receive_response(self) -> dict[str, Any]:
            return response

    service = InstallCoordinationProxyService(cast(RemoteServiceDiscoveryService, object()))
    service._service = cast(RemoteXPCConnection, FakeConnection())
    return service, sent


def test_url_round_trip() -> None:
    encoded = encode_url(INSTALL_PATH)
    assert encoded["com.apple.CFURL.magic"] == CFURL_MAGIC
    assert decode_url(encoded) == INSTALL_PATH


def test_decode_url_returns_none_for_non_url() -> None:
    assert decode_url("not a url dict") is None


@pytest.mark.asyncio
async def test_query_sends_both_version_gates() -> None:
    # Omitting either version makes the daemon drop the connection without replying.
    service, sent = _service({
        "Success": True,
        "DBUUID": "D1D20BD4-9669-47A6-B577-F6D62ED45B43",
        "DBSequence": 276,
        "InstallPath": encode_url(INSTALL_PATH),
        "PersistentIdentifier": b"\x00\x01",
    })

    await service.query("com.apple.Preferences")

    (request,) = sent
    assert int(request["RequestVersion"]) == 1
    assert int(request["ProtocolVersion"]) == 1
    assert int(request["RequestType"]) == REQUEST_TYPE_QUERY
    assert request["BundleID"] == "com.apple.Preferences"


@pytest.mark.asyncio
async def test_query_parses_install_record() -> None:
    service, _ = _service({
        "Success": True,
        "DBUUID": "D1D20BD4-9669-47A6-B577-F6D62ED45B43",
        "DBSequence": 276,
        "InstallPath": encode_url(INSTALL_PATH),
        "PersistentIdentifier": b"\x00\x01",
    })

    record = await service.query("com.apple.Preferences")

    assert record.db_uuid == "D1D20BD4-9669-47A6-B577-F6D62ED45B43"
    assert record.db_sequence == 276
    assert record.install_path == INSTALL_PATH
    assert record.persistent_identifier == b"\x00\x01"


@pytest.mark.asyncio
async def test_query_raises_and_surfaces_archived_error_text() -> None:
    error_data = plistlib.dumps({"$objects": ["$null", "The operation could not be completed"]})
    service, _ = _service({"Success": False, "ErrorData": error_data})

    with pytest.raises(InstallCoordinationError, match="could not be completed"):
        await service.query("com.example.missing")


@pytest.mark.asyncio
async def test_query_raises_without_error_data() -> None:
    service, _ = _service({"Success": False})

    with pytest.raises(InstallCoordinationError, match="no error detail"):
        await service.query("com.example.missing")


@pytest.mark.asyncio
async def test_query_from_device(service_provider) -> None:
    """Query a stock application against a connected device."""
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("installcoordination_proxy requires an RSD tunnel")

    async with InstallCoordinationProxyService(service_provider) as service:
        record = await service.query("com.apple.Preferences")

    assert record.install_path is not None
    assert record.install_path.endswith(".app/")
    assert record.db_sequence > 0
