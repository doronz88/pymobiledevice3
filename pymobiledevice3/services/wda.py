# pyright: reportMissingParameterType=error
"""Minimal WebDriverAgent (WDA) client.

This module provides:
- A simple HTTP-based client for direct WDA usage.
- An async client that routes requests through a LockdownServiceProvider
  connection (usbmux, TCP, or RSD-backed) without requiring a local forwarder.
"""

import base64
import json
from dataclasses import dataclass
from typing import Any, Optional

import requests

from pymobiledevice3.exceptions import WdaError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.service_connection import ServiceConnection

DEFAULT_WDA_PORT = 8100
DEFAULT_WDA_URL = "http://127.0.0.1:8100"


@dataclass
class WdaClient:
    """Synchronous HTTP client for a running WebDriverAgent (WDA) server.

    Talks to WDA over plain HTTP (default `http://127.0.0.1:8100`), expecting WDA to already be
    reachable at `base_url` (e.g. via a local port forward). Provides session management and the
    common WebDriver actions: element lookup, click, text input, button presses, swipes,
    screenshots and source dumps. Once `start_session` is called the returned session id is cached
    on `session_id` and used as the default for subsequent calls.
    """

    base_url: str = DEFAULT_WDA_URL
    timeout: float = 10.0
    session_id: Optional[str] = None

    def _url(self, path: str) -> str:
        """Build a full URL for a WDA path."""
        return f"{self.base_url.rstrip('/')}{path}"

    def _request_json(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Send an HTTP request and parse the WDA JSON response."""
        resp = requests.request(method, self._url(path), json=payload, timeout=self.timeout)
        data = resp.json()
        status = data.get("status")
        if status not in (None, 0, "0"):
            raise WdaError(self._format_error(data, resp.status_code), status_code=resp.status_code)

        return data

    @staticmethod
    def _format_error(data: dict[str, Any], status_code: int) -> str:
        """Format WDA error payloads."""
        message = data.get("value")
        if isinstance(message, dict):
            message = message.get("message") or message.get("error") or message
        return f"WDA error (status={status_code}): {message}"

    def start_session(self, bundle_id: Optional[str] = None) -> str:
        """Start a WDA session, optionally launching a specific application.

        :param bundle_id: Bundle identifier of the app to attach the session to; if omitted no
            specific app capability is requested.
        :returns: The created session id, also cached on `session_id`.
        :raises WdaError: WDA did not return a session id.
        """
        caps: dict[str, Any] = {}
        if bundle_id:
            caps["bundleId"] = bundle_id
        payload = {
            "capabilities": {"alwaysMatch": caps},
            "desiredCapabilities": caps,
        }
        data = self._request_json("POST", "/session", payload)
        session_id = data.get("sessionId")
        if not session_id:
            value = data.get("value")
            if isinstance(value, dict):
                session_id = value.get("sessionId")
        if not session_id:
            raise WdaError("WDA did not return a session id")
        self.session_id = session_id
        return session_id

    def find_element(self, using: str, value: str, session_id: Optional[str] = None) -> str:
        """Locate a single UI element and return its element id.

        :param using: The locator strategy (e.g. `accessibility id`, `class name`, `xpath`).
        :param value: The locator value matched against `using`.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :returns: The resolved element id.
        :raises WdaError: No session id is available, or WDA did not return an element id.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("session_id is required")
        data = self._request_json(
            "POST",
            f"/session/{session_id}/element",
            {"using": using, "value": value},
        )
        element = data.get("value")
        if not isinstance(element, dict):
            raise WdaError("WDA did not return an element")
        element_id = (
            element.get("ELEMENT") or element.get("element-6066-11e4-a52e-4f735466cecf") or element.get("element")
        )
        if not element_id:
            raise WdaError("WDA did not return an element id")
        return element_id

    def click(self, element_id: str, session_id: Optional[str] = None) -> None:
        """Tap an element by its element id.

        :param element_id: The element id to click.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: No session id is available.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("session_id is required")
        self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})

    def press_button(self, name: str, session_id: Optional[str] = None) -> None:
        """Press a hardware/device button by name.

        The name is normalized to a WDA button name. When a session is given the session-scoped
        `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last
        resort, `home` is delivered via the global home-screen endpoint.

        :param name: Button name or alias (e.g. `home`, `volumeUp`, `lock`).
        :param session_id: Session to use; if omitted only the global `home` fallback applies.
        :raises WdaError: WDA supports neither the pressButton nor keys endpoints for this button.
        """
        normalized = normalize_wda_button_name(name)
        payload = {"name": normalized}
        if session_id:
            try:
                self._request_json("POST", f"/session/{session_id}/wda/pressButton", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
            if self._try_keys_endpoint(session_id, normalized):
                return
        if normalized == "home":
            self._request_json("POST", "/wda/homescreen", {})
            return
        raise WdaError("WDA does not support pressButton or keys endpoints", status_code=404)

    def unlock(self, session_id: Optional[str] = None) -> None:
        """Unlock the device, trying the session-scoped endpoint then the global one.

        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: WDA does not support the unlock endpoint.
        """
        session_id = session_id or self.session_id
        if session_id:
            try:
                self._request_json("POST", f"/session/{session_id}/wda/unlock", {})
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
        try:
            self._request_json("POST", "/wda/unlock", {})
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            raise WdaError("WDA does not support unlock endpoint", status_code=404) from exc

    def get_source(self, session_id: Optional[str] = None) -> str:
        """Fetch the current UI hierarchy as an XML source tree.

        :param session_id: Session to query; if omitted the global source endpoint is used.
        :returns: The XML source string.
        :raises WdaError: WDA did not return a source string.
        """
        if session_id:
            data = self._request_json("GET", f"/session/{session_id}/source", None)
        else:
            data = self._request_json("GET", "/source", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a source string")
        return value

    def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
        """Capture a screenshot and return the decoded PNG bytes.

        :param session_id: Session to query; if omitted the global screenshot endpoint is used.
        :returns: The raw PNG image bytes (base64-decoded from the WDA response).
        :raises WdaError: WDA did not return a screenshot.
        """
        if session_id:
            data = self._request_json("GET", f"/session/{session_id}/screenshot", None)
        else:
            data = self._request_json("GET", "/screenshot", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a screenshot")
        return base64.b64decode(value)

    def get_status(self) -> dict[str, Any]:
        """Return the WDA `/status` payload describing the server and device state.

        :returns: The parsed status response.
        """
        return self._request_json("GET", "/status", None)

    def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """Return the current window size.

        :param session_id: Session to query; required.
        :returns: A mapping with the window dimensions (e.g. `width`, `height`).
        :raises WdaError: No session id is available, or WDA did not return a window size.
        """
        if not session_id:
            raise WdaError("session_id is required")
        data = self._request_json("GET", f"/session/{session_id}/window/size", None)
        value = data.get("value")
        if not isinstance(value, dict):
            raise WdaError("WDA did not return window size")
        return value

    def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
        """Type text into the currently focused element.

        Sends the text as individual characters, trying the `wda/keys` endpoint first and falling
        back to the plain `keys` endpoint if the former is unavailable.

        :param text: The text to type.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("session_id is required")
        payload = {"value": list(text)}
        try:
            self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            self._request_json("POST", f"/session/{session_id}/keys", payload)

    def swipe(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration: float = 0.2,
        session_id: Optional[str] = None,
    ) -> None:
        """Drag from a start coordinate to an end coordinate over a duration.

        :param start_x: Starting x coordinate.
        :param start_y: Starting y coordinate.
        :param end_x: Ending x coordinate.
        :param end_y: Ending y coordinate.
        :param duration: Gesture duration in seconds.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("session_id is required")
        payload = {
            "fromX": start_x,
            "fromY": start_y,
            "toX": end_x,
            "toY": end_y,
            "duration": duration,
        }
        self._request_json("POST", f"/session/{session_id}/wda/dragfromtoforduration", payload)

    def _try_keys_endpoint(self, session_id: Optional[str], normalized: str) -> bool:
        """Try the session keys endpoint for button presses."""
        key = normalize_wda_key_name(normalized)
        payload = {"keys": [key]}
        if session_id:
            try:
                self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return True
        return False


@dataclass
class WdaServiceClient:
    """Async WDA client that reaches the WDA server through a LockdownServiceProvider connection.

    Instead of relying on a pre-existing local HTTP forwarder, this client opens a service
    connection to the WDA port on the device for each request (via usbmux for an RSD-backed
    provider, otherwise through the provider directly), writes a raw HTTP/1.1 request, and parses
    the response. It exposes the same WebDriver actions as `WdaClient` as coroutines. The session
    id returned by `start_session` is cached on `session_id` and used as the default for later calls.
    """

    service_provider: LockdownServiceProvider
    port: int = DEFAULT_WDA_PORT
    timeout: float = 10.0
    session_id: Optional[str] = None

    async def _request_json(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Send a WDA request over a service connection and parse JSON."""
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        headers = [
            f"{method} {path} HTTP/1.1",
            "Host: localhost",
            "Connection: close",
        ]
        if payload is not None:
            headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(body)}")
        request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body

        if isinstance(self.service_provider, RemoteServiceDiscoveryService):
            conn = await ServiceConnection.create_using_usbmux(
                self.service_provider.udid,
                self.port,
                usbmux_address=getattr(self.service_provider.lockdown, "usbmux_address", None),
            )
        else:
            conn = await self.service_provider.create_service_connection(self.port)
        async with conn:
            await conn.sendall(request_bytes)

            header_bytes, body_prefix = await self._read_until(conn, b"\r\n\r\n")
            header_text = header_bytes.decode("iso-8859-1")
            lines = header_text.split("\r\n")
            status_line = lines[0]
            status_code = int(status_line.split(" ", 2)[1])

            response_headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    continue
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                response_headers[k.strip().lower()] = v.strip()

            content_length = response_headers.get("content-length")
            if content_length is not None:
                try:
                    length = int(content_length)
                except ValueError:
                    length = 0
                if length <= len(body_prefix):
                    body_bytes = body_prefix[:length]
                else:
                    remainder = length - len(body_prefix)
                    body_bytes = body_prefix + await conn.recvall(remainder)
            else:
                chunks = [body_prefix] if body_prefix else []
                while True:
                    chunk = await conn.recv_any(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                body_bytes = b"".join(chunks)

        try:
            data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except ValueError as exc:
            raise WdaError(f"WDA returned non-JSON response (status={status_code})", status_code=status_code) from exc

        if status_code >= 400:
            raise WdaError(WdaClient._format_error(data, status_code), status_code=status_code)

        status = data.get("status")
        if status not in (None, 0, "0"):
            raise WdaError(WdaClient._format_error(data, status_code), status_code=status_code)

        return data

    async def _read_until(self, conn: ServiceConnection, marker: bytes) -> tuple[bytes, bytes]:
        """Read from a connection until a marker is found."""
        buf = b""
        while marker not in buf:
            chunk = await conn.recv_any(65536)
            if not chunk:
                break
            buf += chunk
        if marker not in buf:
            raise WdaError("WDA response did not contain headers terminator")
        header_bytes, body_prefix = buf.split(marker, 1)
        return header_bytes, body_prefix

    async def start_session(self, bundle_id: Optional[str] = None) -> str:
        """Start a WDA session, optionally launching a specific application.

        :param bundle_id: Bundle identifier of the app to attach the session to; if omitted no
            specific app capability is requested.
        :returns: The created session id, also cached on `session_id`.
        :raises WdaError: WDA did not return a session id.
        """
        caps: dict[str, Any] = {}
        if bundle_id:
            caps["bundleId"] = bundle_id
        payload = {
            "capabilities": {"alwaysMatch": caps},
            "desiredCapabilities": caps,
        }
        data = await self._request_json("POST", "/session", payload)
        session_id = data.get("sessionId")
        if not session_id:
            value = data.get("value")
            if isinstance(value, dict):
                session_id = value.get("sessionId")
        if not session_id:
            raise WdaError("WDA did not return a session id")
        self.session_id = session_id
        return session_id

    async def find_element(self, using: str, value: str, session_id: Optional[str] = None) -> str:
        """Locate a single UI element and return its element id.

        :param using: The locator strategy (e.g. `accessibility id`, `class name`, `xpath`).
        :param value: The locator value matched against `using`.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :returns: The resolved element id.
        :raises WdaError: No session id is available, or WDA did not return an element id.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("session_id is required")
        data = await self._request_json(
            "POST",
            f"/session/{session_id}/element",
            {"using": using, "value": value},
        )
        element = data.get("value")
        if not isinstance(element, dict):
            raise WdaError("WDA did not return an element")
        element_id = (
            element.get("ELEMENT") or element.get("element-6066-11e4-a52e-4f735466cecf") or element.get("element")
        )
        if not element_id:
            raise WdaError("WDA did not return an element id")
        return element_id

    async def click(self, element_id: str, session_id: Optional[str] = None) -> None:
        """Tap an element by its element id.

        :param element_id: The element id to click.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: No session id is available.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("session_id is required")
        await self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})

    async def press_button(self, name: str, session_id: Optional[str] = None) -> None:
        """Press a hardware/device button by name.

        The name is normalized to a WDA button name. When a session is given the session-scoped
        `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last
        resort, `home` is delivered via the global home-screen endpoint.

        :param name: Button name or alias (e.g. `home`, `volumeUp`, `lock`).
        :param session_id: Session to use; if omitted only the global `home` fallback applies.
        :raises WdaError: WDA supports neither the pressButton nor keys endpoints for this button.
        """
        normalized = normalize_wda_button_name(name)
        payload = {"name": normalized}
        if session_id:
            try:
                await self._request_json("POST", f"/session/{session_id}/wda/pressButton", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
            if await self._try_keys_endpoint(session_id, normalized):
                return
        if normalized == "home":
            await self._request_json("POST", "/wda/homescreen", {})
            return
        raise WdaError("WDA does not support pressButton or keys endpoints", status_code=404)

    async def unlock(self, session_id: Optional[str] = None) -> None:
        """Unlock the device, trying the session-scoped endpoint then the global one.

        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: WDA does not support the unlock endpoint.
        """
        session_id = session_id or self.session_id
        if session_id:
            try:
                await self._request_json("POST", f"/session/{session_id}/wda/unlock", {})
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
        try:
            await self._request_json("POST", "/wda/unlock", {})
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            raise WdaError("WDA does not support unlock endpoint", status_code=404) from exc

    async def get_source(self, session_id: Optional[str] = None) -> str:
        """Fetch the current UI hierarchy as an XML source tree.

        :param session_id: Session to query; if omitted the global source endpoint is used.
        :returns: The XML source string.
        :raises WdaError: WDA did not return a source string.
        """
        if session_id:
            data = await self._request_json("GET", f"/session/{session_id}/source", None)
        else:
            data = await self._request_json("GET", "/source", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a source string")
        return value

    async def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
        """Capture a screenshot and return the decoded PNG bytes.

        :param session_id: Session to query; if omitted the global screenshot endpoint is used.
        :returns: The raw PNG image bytes (base64-decoded from the WDA response).
        :raises WdaError: WDA did not return a screenshot.
        """
        if session_id:
            data = await self._request_json("GET", f"/session/{session_id}/screenshot", None)
        else:
            data = await self._request_json("GET", "/screenshot", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a screenshot")
        return base64.b64decode(value)

    async def get_status(self) -> dict[str, Any]:
        """Return the WDA `/status` payload describing the server and device state.

        :returns: The parsed status response.
        """
        return await self._request_json("GET", "/status", None)

    async def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """Return the current window size.

        :param session_id: Session to query; required.
        :returns: A mapping with the window dimensions (e.g. `width`, `height`).
        :raises WdaError: No session id is available, or WDA did not return a window size.
        """
        if not session_id:
            raise WdaError("session_id is required")
        data = await self._request_json("GET", f"/session/{session_id}/window/size", None)
        value = data.get("value")
        if not isinstance(value, dict):
            raise WdaError("WDA did not return window size")
        return value

    async def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
        """Type text into the currently focused element.

        Sends the text as individual characters, trying the `wda/keys` endpoint first and falling
        back to the plain `keys` endpoint if the former is unavailable.

        :param text: The text to type.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("session_id is required")
        payload = {"value": list(text)}
        try:
            await self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            await self._request_json("POST", f"/session/{session_id}/keys", payload)

    async def swipe(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration: float = 0.2,
        session_id: Optional[str] = None,
    ) -> None:
        """Drag from a start coordinate to an end coordinate over a duration.

        :param start_x: Starting x coordinate.
        :param start_y: Starting y coordinate.
        :param end_x: Ending x coordinate.
        :param end_y: Ending y coordinate.
        :param duration: Gesture duration in seconds.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("session_id is required")
        payload = {
            "fromX": start_x,
            "fromY": start_y,
            "toX": end_x,
            "toY": end_y,
            "duration": duration,
        }
        await self._request_json("POST", f"/session/{session_id}/wda/dragfromtoforduration", payload)

    async def _try_keys_endpoint(self, session_id: Optional[str], normalized: str) -> bool:
        """Try the session keys endpoint for button presses."""
        key = normalize_wda_key_name(normalized)
        payload = {"keys": [key]}
        if session_id:
            try:
                await self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return True
        return False


def normalize_wda_button_name(name: str) -> str:
    """Normalize common button aliases to WDA names."""
    key = name.strip().lower().replace("-", "").replace("_", "")
    aliases = {
        "home": "home",
        "volumeup": "volumeUp",
        "volup": "volumeUp",
        "volumeupbutton": "volumeUp",
        "volumedown": "volumeDown",
        "voldown": "volumeDown",
        "volumedownbutton": "volumeDown",
        "lock": "lock",
        "lockscreen": "lock",
        "sleep": "lock",
        "power": "lock",
    }
    return aliases.get(key, name)


def normalize_wda_key_name(name: str) -> str:
    """Normalize common button aliases to WDA key names."""
    key = name.strip().lower().replace("-", "").replace("_", "")
    aliases = {
        "home": "HOME",
        "volumeup": "VOLUME_UP",
        "volup": "VOLUME_UP",
        "volumedown": "VOLUME_DOWN",
        "voldown": "VOLUME_DOWN",
        "lock": "LOCK",
        "lockscreen": "LOCK",
        "sleep": "LOCK",
        "power": "LOCK",
    }
    return aliases.get(key, name)
