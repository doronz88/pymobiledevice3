"""A no-root iOS 17+ RSD tunnel that automatically picks the best transport for the host.

On macOS this prefers the :class:`~pymobiledevice3.remote.native_tunnel.NativeRemotedTunnel`
(piggybacks Apple's own ``remoted`` — faster host->device and lower latency, and it coexists with
Xcode), falling back to the in-process
:class:`~pymobiledevice3.remote.userspace_tunnel.UserspaceRsdTunnel` when the native path is not
available. On every other platform (where ``remoted`` does not exist) it uses the userspace tunnel.
Both are no-root.

Prefer this over picking a concrete tunnel class when you just want "a working no-root RSD on iOS
17+" and don't care which mechanism provides it.
"""

import platform
from typing import TYPE_CHECKING, Any, Optional, Union

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

if TYPE_CHECKING:
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel

_IS_DARWIN = platform.system() == "Darwin"


class PreferredRsdTunnel:
    """A no-root iOS 17+ RSD tunnel that selects the best available transport for the host.

    Async context manager (closes automatically)::

        async with PreferredRsdTunnel(serial=udid) as rsd:
            ...  # rsd is a connected RemoteServiceDiscoveryService

    Or open/close explicitly with :meth:`aopen` / :meth:`aclose`. ``serial`` selects the device
    (``None`` => first/only device). ``prefer_native=False`` forces the userspace tunnel even on
    macOS. On macOS the native tunnel is tried first and, if it is unavailable, the userspace tunnel
    is used instead; elsewhere the userspace tunnel is used directly.
    """

    def __init__(self, serial: Optional[str] = None, autopair: bool = True, prefer_native: bool = True) -> None:
        self.serial = serial
        self.autopair = autopair
        self.prefer_native = prefer_native
        self.rsd: Optional[RemoteServiceDiscoveryService] = None
        self._handle: Optional[Union[NativeRemotedTunnel, UserspaceRsdTunnel]] = None

    async def aopen(self) -> RemoteServiceDiscoveryService:
        if self.rsd is not None:
            return self.rsd
        if _IS_DARWIN and self.prefer_native:
            # Imported here so non-macOS callers never touch the ctypes/libxpc layer.
            from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel

            native = NativeRemotedTunnel(serial=self.serial)
            try:
                rsd = await native.aopen()
            except Exception:
                # Any native-path failure (unavailable, or an unexpected ctypes/libxpc error) falls
                # back to the userspace tunnel rather than propagating.
                await native.aclose()  # release anything half-acquired before falling back
            else:
                self.rsd = rsd
                self._handle = native
                return rsd

        # Imported lazily: the userspace stack (pmd-pytcp) import is expensive.
        from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel

        userspace = UserspaceRsdTunnel(serial=self.serial, autopair=self.autopair)
        rsd = await userspace.aopen()
        self.rsd = rsd
        self._handle = userspace
        return rsd

    async def aclose(self) -> None:
        if self._handle is not None:
            await self._handle.aclose()
            self._handle = None
            self.rsd = None

    async def __aenter__(self) -> RemoteServiceDiscoveryService:
        return await self.aopen()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()
