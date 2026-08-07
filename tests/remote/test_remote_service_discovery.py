from typing import Any, Optional

import pytest

from pymobiledevice3.exceptions import DeviceFeatureNotSupportedError, InvalidServiceError, NotConnectedError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

APP_SERVICE = "com.apple.coredevice.appservice"
APP_FEATURES = [
    "com.apple.coredevice.feature.listapps",
    "com.apple.coredevice.feature.launchapplication",
]


def make_rsd(services: dict[str, Any], udid: Optional[str] = "udid") -> RemoteServiceDiscoveryService:
    """An RSD wired with a handshake response, without any I/O."""
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {"Properties": {"OSVersion": "26.0"}, "Services": services}
    rsd.udid = udid
    return rsd


def test_get_service_features_returns_advertised_features() -> None:
    rsd = make_rsd({APP_SERVICE: {"Port": "1024", "Properties": {"Features": APP_FEATURES}}})
    assert rsd.get_service_features(APP_SERVICE) == frozenset(APP_FEATURES)


def test_get_service_features_empty_when_service_advertises_none() -> None:
    rsd = make_rsd({APP_SERVICE: {"Port": "1024", "Properties": {"UsesRemoteXPC": True}}})
    assert rsd.get_service_features(APP_SERVICE) == frozenset()


def test_get_service_features_missing_service_raises() -> None:
    rsd = make_rsd({})
    with pytest.raises(InvalidServiceError):
        rsd.get_service_features(APP_SERVICE)


def test_get_service_features_not_connected_raises() -> None:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    with pytest.raises(NotConnectedError):
        rsd.get_service_features(APP_SERVICE)


def test_require_feature_passes_when_advertised() -> None:
    rsd = make_rsd({APP_SERVICE: {"Port": "1024", "Properties": {"Features": APP_FEATURES}}})
    rsd.require_feature(APP_SERVICE, "com.apple.coredevice.feature.listapps")


def test_require_feature_raises_when_not_advertised() -> None:
    rsd = make_rsd({APP_SERVICE: {"Port": "1024", "Properties": {"Features": APP_FEATURES}}})
    with pytest.raises(DeviceFeatureNotSupportedError) as exc_info:
        rsd.require_feature(APP_SERVICE, "com.apple.coredevice.feature.streamapplist")
    error = exc_info.value
    assert error.service_name == APP_SERVICE
    assert error.feature == "com.apple.coredevice.feature.streamapplist"
    assert error.identifier == "udid"
    assert error.product_version == "26.0"
    assert "streamapplist" in str(error)


def test_require_feature_noop_when_service_advertises_no_features() -> None:
    # A handshake without a Features list cannot be used to deny an operation.
    rsd = make_rsd({APP_SERVICE: {"Port": "1024", "Properties": {"UsesRemoteXPC": True}}})
    rsd.require_feature(APP_SERVICE, "com.apple.coredevice.feature.streamapplist")


def test_require_feature_noop_when_features_list_is_empty() -> None:
    # An empty list is treated like an absent one: deny-all is never inferred from it.
    rsd = make_rsd({APP_SERVICE: {"Port": "1024", "Properties": {"Features": []}}})
    rsd.require_feature(APP_SERVICE, "com.apple.coredevice.feature.streamapplist")


def test_require_feature_missing_service_raises_invalid_service() -> None:
    rsd = make_rsd({})
    with pytest.raises(InvalidServiceError):
        rsd.require_feature(APP_SERVICE, "com.apple.coredevice.feature.listapps")
