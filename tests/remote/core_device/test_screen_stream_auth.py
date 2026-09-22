import base64

import pytest

from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


def _server(password=None) -> ScreenStreamServer:
    return ScreenStreamServer(RemoteServiceDiscoveryService(("127.0.0.1", 0)), password=password)


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def test_binds_loopback_by_default():
    assert _server()._bind == "127.0.0.1"


def test_open_server_serves_same_origin_and_no_origin_requests():
    server = _server()
    assert server._refuse_request({"host": "127.0.0.1:8080"}) is None
    assert server._refuse_request({"host": "127.0.0.1:8080", "origin": "http://127.0.0.1:8080"}) is None
    assert server._refuse_request({"host": "Phone.local:8080", "origin": "http://phone.local:8080"}) is None


@pytest.mark.parametrize("origin", ["http://evil.example", "http://127.0.0.1:9999", "http://localhost:8080"])
def test_cross_origin_requests_are_forbidden(origin):
    # a page on another site (or a rebound name) cannot drive the device through the viewer's port
    refusal = _server()._refuse_request({"host": "127.0.0.1:8080", "origin": origin})
    assert refusal is not None and refusal.startswith(b"HTTP/1.1 403 ")


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic", "Bearer x", _basic("me", "wrong"), _basic("me", ""), "Basic not-base64!"],
)
def test_password_required_from_every_request(authorization):
    headers = {"host": "127.0.0.1:8080"}
    if authorization is not None:
        headers["authorization"] = authorization
    refusal = _server("s3cret")._refuse_request(headers)
    assert refusal is not None and refusal.startswith(b"HTTP/1.1 401 ")
    assert b'WWW-Authenticate: Basic realm="pymobiledevice3"' in refusal


@pytest.mark.parametrize("user", ["", "anyone"])
@pytest.mark.parametrize("password", ["s3cret", "with:colon", "pässwörd"])
def test_password_accepted_with_any_user_name(user, password):
    headers = {"host": "127.0.0.1:8080", "authorization": _basic(user, password)}
    assert _server(password)._refuse_request(headers) is None
