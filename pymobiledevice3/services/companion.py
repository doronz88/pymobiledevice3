#!/usr/bin/env python3
from typing import Optional

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class CompanionProxyService(LockdownService):
    SERVICE_NAME = "com.apple.companion_proxy"
    RSD_SERVICE_NAME = "com.apple.companion_proxy.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def list(self):
        service = self.lockdown.start_lockdown_service(self.service_name)
        return service.send_recv_plist({"Command": "GetDeviceRegistry"}).get("PairedDevicesArray", [])

    def listen_for_devices(self):
        service = self.lockdown.start_lockdown_service(self.service_name)
        service.send_plist({"Command": "StartListeningForDevices"})
        while True:
            yield service.recv_plist()

    def get_value(self, udid: str, key: str):
        service = self.lockdown.start_lockdown_service(self.service_name)
        response = service.send_recv_plist({
            "Command": "GetValueFromRegistry",
            "GetValueGizmoUDIDKey": udid,
            "GetValueKeyKey": key,
        })

        value = response.get("RetrievedValueDictionary")
        if value is not None:
            return value

        error = response.get("Error")
        raise PyMobileDevice3Exception(error)

    def start_forwarding_service_port(
        self, remote_port: int, service_name: Optional[str] = None, options: Optional[dict] = None
    ):
        service = self.lockdown.start_lockdown_service(self.service_name)

        request = {
            "Command": "StartForwardingServicePort",
            "GizmoRemotePortNumber": remote_port,
            "IsServiceLowPriority": False,
            "PreferWifi": False,
        }

        if service_name is not None:
            request["ForwardedServiceName"] = service_name

        if options is not None:
            request.update(options)

        return service.send_recv_plist(request).get("CompanionProxyServicePort")

    def stop_forwarding_service_port(self, remote_port: int):
        service = self.lockdown.start_lockdown_service(self.service_name)

        request = {"Command": "StopForwardingServicePort", "GizmoRemotePortNumber": remote_port}

        return service.send_recv_plist(request)
