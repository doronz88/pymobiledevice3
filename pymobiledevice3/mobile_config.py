#!/usr/bin/env python
import plistlib
import logging

from pymobiledevice3.lockdown import LockdownClient


class MobileConfigService(object):
    def __init__(self, lockdown, udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        self.service = lockdown.start_service("com.apple.mobile.MCInstall")

    def get_profile_list(self):
        self.service.send_plist({"RequestType": "GetProfileList"})
        response = self.service.recv_plist()
        if response.get("Status", None) != "Acknowledged":
            raise Exception(f'invalid response {response}')
        return response

    def install_profile(self, payload):
        self.service.send_plist({"RequestType": "InstallProfile", "Payload": plistlib.Data(payload)})
        return self.service.recv_plist()

    def remove_profile(self, ident):
        profiles = self.get_profile_list()
        if not profiles:
            return
        if ident not in profiles["ProfileMetadata"]:
            self.logger.info("Trying to remove not installed profile %s", ident)
            return
        meta = profiles["ProfileMetadata"][ident]
        data = plistlib.dumps({"PayloadType": "Configuration",
                               "PayloadIdentifier": ident,
                               "PayloadUUID": meta["PayloadUUID"],
                               "PayloadVersion": meta["PayloadVersion"]
                               })
        self.service.send_plist({"RequestType": "RemoveProfile", "ProfileIdentifier": plistlib.Data(data)})
        return self.service.recv_plist()
