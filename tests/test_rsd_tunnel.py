from typing import Optional

import pytest

from pymobiledevice3.exceptions import UserspaceTunnelUnavailableError
from pymobiledevice3.remote import native_tunnel, rsd_tunnel, userspace_tunnel


def _fake_tunnels(
    monkeypatch: pytest.MonkeyPatch,
    darwin: bool,
    native_exc: Optional[Exception] = None,
    userspace_exc: Optional[Exception] = None,
) -> list[str]:
    calls: list[str] = []

    def fake_tunnel(name: str, exc: Optional[Exception]) -> type:
        class FakeTunnel:
            def __init__(self, serial: Optional[str] = None, autopair: bool = True) -> None:
                pass

            async def aopen(self) -> str:
                calls.append(name)
                if exc is not None:
                    raise exc
                return name.upper()

            async def aclose(self) -> None:
                calls.append(f"close {name}")

        return FakeTunnel

    monkeypatch.setattr(rsd_tunnel, "_IS_DARWIN", darwin)
    monkeypatch.setattr(native_tunnel, "NativeRemotedTunnel", fake_tunnel("native", native_exc))
    monkeypatch.setattr(userspace_tunnel, "UserspaceRsdTunnel", fake_tunnel("userspace", userspace_exc))
    return calls


@pytest.mark.asyncio
@pytest.mark.parametrize("darwin", [True, False])
async def test_defaults_to_the_userspace_tunnel(monkeypatch: pytest.MonkeyPatch, darwin: bool) -> None:
    # The native tunnel's RSD connection and remoted's evict each other (#1994), so it is not the
    # default on macOS either.
    calls = _fake_tunnels(monkeypatch, darwin=darwin)

    assert await rsd_tunnel.PreferredRsdTunnel().aopen() == "USERSPACE"
    assert calls == ["userspace"]


@pytest.mark.asyncio
async def test_falls_back_to_native_when_userspace_cannot_serve_the_device(monkeypatch: pytest.MonkeyPatch) -> None:
    # iOS 17.0-17.3 has no CoreDeviceProxy; remoted still reaches it with no root.
    calls = _fake_tunnels(monkeypatch, darwin=True, userspace_exc=UserspaceTunnelUnavailableError("no 17.4"))

    assert await rsd_tunnel.PreferredRsdTunnel().aopen() == "NATIVE"
    assert calls == ["userspace", "native"]


@pytest.mark.asyncio
async def test_no_native_fallback_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_tunnels(monkeypatch, darwin=False, userspace_exc=UserspaceTunnelUnavailableError("no 17.4"))

    with pytest.raises(UserspaceTunnelUnavailableError):
        await rsd_tunnel.PreferredRsdTunnel().aopen()
    assert calls == ["userspace"]


@pytest.mark.asyncio
async def test_prefer_native_tries_native_first(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_tunnels(monkeypatch, darwin=True)

    assert await rsd_tunnel.PreferredRsdTunnel(prefer_native=True).aopen() == "NATIVE"
    assert calls == ["native"]


@pytest.mark.asyncio
async def test_prefer_native_falls_back_to_userspace(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_tunnels(monkeypatch, darwin=True, native_exc=RuntimeError("no remotepairingd"))

    assert await rsd_tunnel.PreferredRsdTunnel(prefer_native=True).aopen() == "USERSPACE"
    assert calls == ["native", "close native", "userspace"]
