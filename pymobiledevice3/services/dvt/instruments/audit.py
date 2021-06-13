from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.structs import MessageAux


class Audit:
    SERVICE_NAME = 'com.apple.accessibility.axAuditDaemon.remoteserver'

    def __init__(self, lockdown: LockdownClient):
        self._dvt = DvtSecureSocketProxyService(lockdown, self.SERVICE_NAME, False)
        self._capabilities = {'_notifyOfPublishedCapabilities:'}

    def recv_plist(self):
        plist = self._dvt.recv_plist()

        while isinstance(plist[0], str) and plist[0].startswith('_notify'):
            # skip notifications
            plist = self._dvt.recv_plist()
        return plist

    def device_capabilities(self):
        self._dvt.send_message(0, 'deviceCapabilities', MessageAux(), True)
        return self.recv_plist()[0]
