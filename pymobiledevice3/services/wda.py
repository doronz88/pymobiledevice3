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
    """Simple HTTP-based WDA client."""

    base_url: str = DEFAULT_WDA_URL
    timeout: float = 10.0
    session_id: Optional[str] = None

    def _url(self, path: str) -> str:
        """Build a full URL for a WDA path."""
        return f"{self.base_url.rstrip('/')}{path}"

    def _request_json(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Send an HTTP request and parse the WDA JSON response."""
        try:
            resp = requests.request(method, self._url(path), json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            raise WdaError(f"WDA request failed: {exc}") from exc

        try:
            data = resp.json()
        except ValueError as exc:
            raise WdaError(
                f"WDA returned non-JSON response (status={resp.status_code})", status_code=resp.status_code
            ) from exc

        if resp.status_code >= 400:
            raise WdaError(self._format_error(data, resp.status_code), status_code=resp.status_code)

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
        """Start a WDA session (optionally for a bundle id)."""
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
        """Find an element and return its element id."""
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
        """Click an element by id."""
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("session_id is required")
        self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})

    def press_button(self, name: str, session_id: Optional[str] = None) -> None:
        """Press a device button via WDA."""
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

    def get_source(self, session_id: Optional[str] = None) -> str:
        """Return the WDA XML source tree."""
        if session_id:
            data = self._request_json("GET", f"/session/{session_id}/source", None)
        else:
            data = self._request_json("GET", "/source", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a source string")
        return value

    def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
        """Return a PNG screenshot as bytes."""
        if session_id:
            data = self._request_json("GET", f"/session/{session_id}/screenshot", None)
        else:
            data = self._request_json("GET", "/screenshot", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a screenshot")
        return base64.b64decode(value)

    def get_status(self) -> dict[str, Any]:
        """Return WDA status payload."""
        return self._request_json("GET", "/status", None)

    def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """Return the current window size."""
        if not session_id:
            raise WdaError("session_id is required")
        data = self._request_json("GET", f"/session/{session_id}/window/size", None)
        value = data.get("value")
        if not isinstance(value, dict):
            raise WdaError("WDA did not return window size")
        return value

    def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
        """Send text input to the focused element."""
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
        """Swipe from one coordinate to another."""
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
    """WDA client that uses a LockdownServiceProvider connection."""

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

            try:
                header_bytes, body_prefix = await self._read_until(conn, b"\r\n\r\n")
            except Exception as exc:
                raise WdaError(f"WDA response read failed: {exc}") from exc

            header_text = header_bytes.decode("iso-8859-1")
            lines = header_text.split("\r\n")
            status_line = lines[0]
            try:
                status_code = int(status_line.split(" ", 2)[1])
            except Exception:
                status_code = 0

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

    async def _read_until(self, conn, marker: bytes) -> tuple[bytes, bytes]:
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
        """Start a WDA session (optionally for a bundle id)."""
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
        """Find an element and return its element id."""
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
        """Click an element by id."""
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("session_id is required")
        await self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})

    async def press_button(self, name: str, session_id: Optional[str] = None) -> None:
        """Press a device button via WDA."""
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

    async def get_source(self, session_id: Optional[str] = None) -> str:
        """Return the WDA XML source tree."""
        if session_id:
            data = await self._request_json("GET", f"/session/{session_id}/source", None)
        else:
            data = await self._request_json("GET", "/source", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a source string")
        return value

    async def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
        """Return a PNG screenshot as bytes."""
        if session_id:
            data = await self._request_json("GET", f"/session/{session_id}/screenshot", None)
        else:
            data = await self._request_json("GET", "/screenshot", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a screenshot")
        return base64.b64decode(value)

    async def get_status(self) -> dict[str, Any]:
        """Return WDA status payload."""
        return await self._request_json("GET", "/status", None)

    async def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """Return the current window size."""
        if not session_id:
            raise WdaError("session_id is required")
        data = await self._request_json("GET", f"/session/{session_id}/window/size", None)
        value = data.get("value")
        if not isinstance(value, dict):
            raise WdaError("WDA did not return window size")
        return value

    async def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
        """Send text input to the focused element."""
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
        """Swipe from one coordinate to another."""
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
