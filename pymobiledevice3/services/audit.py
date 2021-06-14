from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.remote_server import RemoteServer


class Audit(RemoteServer):
    SERVICE_NAME = 'com.apple.accessibility.axAuditDaemon.remoteserver'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, remove_ssl_context=True)

    def recv_plist(self, **kwargs):
        plist = super().recv_plist()

        while isinstance(plist[0], str) and plist[0].startswith('_notify'):
            # skip notifications
            plist = super().recv_plist()
        return plist

    def device_capabilities(self):
        self.broadcast.deviceCapabilities()
        return self.recv_plist()[0]
