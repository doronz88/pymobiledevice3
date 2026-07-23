#!/usr/bin/env python3
from typing import Any, Optional

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class CompanionProxyService(LockdownService):
    """
    Query and interact with companion devices (e.g. a paired Apple Watch) via the companion proxy
    lockdown service.

    Provides access to the paired-device registry, live notifications of companion devices coming
    and going, registry value lookups, and TCP port forwarding to a companion device. This is a
    lockdown service and is used as an async context manager; the RSD/tunnel variant is selected
    automatically for non-`LockdownClient` providers.
    """

    SERVICE_NAME = "com.apple.companion_proxy"
    RSD_SERVICE_NAME = "com.apple.companion_proxy.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def list(self):
        """
        List the companion devices currently paired with the device.

        Sends a ``GetDeviceRegistry`` command and returns the paired-device registry.

        :returns: the list of paired devices (the ``PairedDevicesArray`` entry), or an empty list
            if none are present.
        """
        service = await self.lockdown.start_lockdown_service(self.service_name)
        return (await service.send_recv_plist({"Command": "GetDeviceRegistry"})).get("PairedDevicesArray", [])

    async def listen_for_devices(self):
        """
        Yield events as companion devices appear and disappear.

        Sends ``StartListeningForDevices`` and then continuously yields each event message the
        device emits.

        :returns: an async generator of device registry change events.
        """
        service = await self.lockdown.start_lockdown_service(self.service_name)
        await service.send_plist({"Command": "StartListeningForDevices"})
        while True:
            yield await service.recv_plist()

    async def get_value(self, udid: str, key: str):
        """
        Read a single value from the registry of a specific companion device.

        Sends a ``GetValueFromRegistry`` command for the given device and key.

        :param udid: UDID of the companion device to query.
        :param key: registry key whose value should be retrieved.
        :returns: the retrieved value dictionary.
        :raises PyMobileDevice3Exception: if the device returns an error instead of a value.
        """
        service = await self.lockdown.start_lockdown_service(self.service_name)
        response = await service.send_recv_plist({
            "Command": "GetValueFromRegistry",
            "GetValueGizmoUDIDKey": udid,
            "GetValueKeyKey": key,
        })

        value = response.get("RetrievedValueDictionary")
        if value is not None:
            return value

        error = response.get("Error")
        raise PyMobileDevice3Exception(error)

    async def start_forwarding_service_port(
        self, remote_port: int, service_name: Optional[str] = None, options: Optional[dict[str, Any]] = None
    ):
        """
        Start forwarding a port on the companion device through the proxy.

        Sends a ``StartForwardingServicePort`` command for the given remote port. The request
        defaults the forwarded service to non-low-priority and does not prefer Wi-Fi; these and any
        other fields may be overridden via ``options``.

        :param remote_port: port number on the companion device to forward.
        :param service_name: optional name of the forwarded service, sent as ``ForwardedServiceName``.
        :param options: optional dictionary merged into the request to override default fields.
        :returns: the local proxy port assigned for the forwarded connection
            (the ``CompanionProxyServicePort`` value).
        """
        service = await self.lockdown.start_lockdown_service(self.service_name)

        request: dict[str, Any] = {
            "Command": "StartForwardingServicePort",
            "GizmoRemotePortNumber": remote_port,
            "IsServiceLowPriority": False,
            "PreferWifi": False,
        }

        if service_name is not None:
            request["ForwardedServiceName"] = service_name

        if options is not None:
            request.update(options)

        return (await service.send_recv_plist(request)).get("CompanionProxyServicePort")

    async def stop_forwarding_service_port(self, remote_port: int):
        """
        Stop a port forward previously started with `start_forwarding_service_port`.

        Sends a ``StopForwardingServicePort`` command for the given remote port.

        :param remote_port: port number on the companion device whose forwarding should be stopped.
        :returns: the device's response to the stop command.
        """
        service = await self.lockdown.start_lockdown_service(self.service_name)

        request: dict[str, Any] = {"Command": "StopForwardingServicePort", "GizmoRemotePortNumber": remote_port}

        return await service.send_recv_plist(request)
