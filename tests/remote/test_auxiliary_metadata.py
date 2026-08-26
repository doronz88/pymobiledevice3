import base64
import plistlib
from typing import Any, cast

from pymobiledevice3.remote.remote_service_discovery import (
    WEBINSPECTOR_ENABLE_REMOTE_INSPECTION_KEY,
    WEBINSPECTOR_METADATA_DOMAIN,
    RemoteServiceDiscoveryService,
    parse_device_kvs_data,
)
from pymobiledevice3.remote.tunnel_service import (
    RemotePairingProtocol,
    RemotePairingTunnel,
    TunnelProtocol,
    TunnelResult,
)


def _kvs(payload: dict[str, Any]) -> bytes:
    return plistlib.dumps(payload, fmt=plistlib.FMT_BINARY)


SAMPLE = {
    "com.apple.WebInspector": {"EnableRemoteInspection": False},
    "com.apple.mobile.wireless_lockdown": {"EnableWifiDebugging": True},
    "NULL": {"ProductVersion": "26.6.1"},
}


def test_parse_device_kvs_data_from_bytes() -> None:
    parsed = parse_device_kvs_data(_kvs(SAMPLE))
    assert parsed[WEBINSPECTOR_METADATA_DOMAIN][WEBINSPECTOR_ENABLE_REMOTE_INSPECTION_KEY] is False
    assert parsed["NULL"]["ProductVersion"] == "26.6.1"


def test_parse_device_kvs_data_from_base64_str() -> None:
    # The userspace/tunneld handshake carries deviceKVSData as a base64 string.
    parsed = parse_device_kvs_data(base64.b64encode(_kvs(SAMPLE)).decode())
    assert parsed[WEBINSPECTOR_METADATA_DOMAIN][WEBINSPECTOR_ENABLE_REMOTE_INSPECTION_KEY] is False


def test_parse_device_kvs_data_none_and_garbage_return_empty() -> None:
    assert parse_device_kvs_data(None) == {}
    assert parse_device_kvs_data(b"not a plist") == {}
    assert parse_device_kvs_data("!!!not base64 or plist!!!") == {}
    # A plist that isn't a top-level dict is rejected.
    assert parse_device_kvs_data(plistlib.dumps([1, 2, 3], fmt=plistlib.FMT_BINARY)) == {}


def _rsd(auxiliary_metadata: dict[str, Any]) -> RemoteServiceDiscoveryService:
    return RemoteServiceDiscoveryService(("127.0.0.1", 0), auxiliary_metadata=auxiliary_metadata)


def test_auxiliary_metadata_defaults_empty() -> None:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    assert rsd.auxiliary_metadata == {}
    assert rsd.get_auxiliary_metadata("com.apple.WebInspector") == {}


def test_get_auxiliary_metadata_returns_domain_dict() -> None:
    rsd = _rsd({"com.apple.WebInspector": {"EnableRemoteInspection": True}})
    assert rsd.get_auxiliary_metadata("com.apple.WebInspector") == {"EnableRemoteInspection": True}
    assert rsd.get_auxiliary_metadata("com.apple.absent") == {}


def test_is_remote_web_inspector_enabled_true() -> None:
    rsd = _rsd({"com.apple.WebInspector": {"EnableRemoteInspection": True}})
    assert rsd.is_remote_web_inspector_enabled() is True


def test_is_remote_web_inspector_enabled_false() -> None:
    rsd = _rsd({"com.apple.WebInspector": {"EnableRemoteInspection": False}})
    assert rsd.is_remote_web_inspector_enabled() is False


def test_is_remote_web_inspector_enabled_none_when_domain_absent() -> None:
    # Off-native the device omits the WebInspector domain from the handshake KVS -> unknown.
    rsd = _rsd({"NULL": {"ProductVersion": "26.6.1"}})
    assert rsd.is_remote_web_inspector_enabled() is None


class _FakeProtocol(RemotePairingProtocol):
    async def close(self) -> None: ...

    async def receive_response(self) -> dict[str, Any]:
        return {}

    async def send_request(self, data: dict[str, Any]) -> None: ...


def test_remote_pairing_protocol_auxiliary_metadata_decodes_handshake() -> None:
    proto = _FakeProtocol()
    # The handshake carries deviceKVSData as a base64 string inside peerDeviceInfo.
    proto.handshake_info = {"peerDeviceInfo": {"deviceKVSData": base64.b64encode(_kvs(SAMPLE)).decode()}}
    assert proto.auxiliary_metadata["com.apple.WebInspector"]["EnableRemoteInspection"] is False


def test_remote_pairing_protocol_auxiliary_metadata_empty_before_handshake() -> None:
    assert _FakeProtocol().auxiliary_metadata == {}


def test_tunnel_result_auxiliary_metadata_default_and_populated() -> None:
    client = cast(RemotePairingTunnel, None)
    default = TunnelResult("utun0", "fd::1", 1, TunnelProtocol.TCP, client)
    assert default.auxiliary_metadata == {}

    populated = TunnelResult(
        "utun0", "fd::1", 1, TunnelProtocol.TCP, client, {"com.apple.WebInspector": {"EnableRemoteInspection": True}}
    )
    assert populated.auxiliary_metadata["com.apple.WebInspector"]["EnableRemoteInspection"] is True
