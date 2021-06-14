from distutils.version import LooseVersion

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.remote_server import RemoteServer


class DvtSecureSocketProxyService(RemoteServer):
    SERVICE_NAME = 'com.apple.instruments.remoteserver.DVTSecureSocketProxy'
    OLD_SERVICE_NAME = 'com.apple.instruments.remoteserver'

    def __init__(self, lockdown: LockdownClient):
        if LooseVersion(lockdown.ios_version) >= LooseVersion('14.0'):
            service_name = self.SERVICE_NAME
            remove_ssl_context = False
        else:
            service_name = self.OLD_SERVICE_NAME
            remove_ssl_context = True

        super().__init__(lockdown, service_name, remove_ssl_context=remove_ssl_context)
