import logging

from pymobiledevice3.lockdown import LockdownClient

SRCFILES = """Baseband
CrashReporter
MobileAsset
VARFS
HFSMeta
Lockdown
MobileBackup
MobileDelete
MobileInstallation
MobileNotes
Network
UserDatabases
WiFi
WirelessAutomation
NANDDebugInfo
SystemConfiguration
Ubiquity
tmp
WirelessAutomation"""


class DeviceVersionNotSupported(Exception):
    pass


class FileRelayService(object):
    SERVICE_NAME = 'com.apple.mobile.file_relay'

    def __init__(self, lockdown: LockdownClient, ):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)
        self.packet_num = 0

    def stop_session(self):
        self.logger.info("Disconecting...")
        self.service.close()

    def request_sources(self, sources=["UserDatabases"]):
        self.service.send_plist({"Sources": sources})
        while 1:
            res = self.service.recv_plist()
            if res:
                s = res.get("Status")
                if s == "Acknowledged":
                    z = ""
                    while True:
                        x = self.service.recv()
                        if not x:
                            break
                        z += x
                    return z
                else:
                    print(res.get("Error"))
                    break
        return None
