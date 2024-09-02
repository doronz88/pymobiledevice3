from packaging.version import Version

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.remote_server import RemoteServer


class DvtTestmanagedProxyService(RemoteServer):
    SERVICE_NAME = 'com.apple.testmanagerd.lockdown.secure'
    OLD_SERVICE_NAME = 'com.apple.testmanagerd.lockdown'
    RSD_SERVICE_NAME = 'com.apple.dt.testmanagerd.remote'

    # TODO: there is also service named 'com.apple.dt.testmanagerd.remote.automation', but not used

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, RemoteServiceDiscoveryService):  # only happends when >=17.0
            service_name = self.RSD_SERVICE_NAME
            remove_ssl_context = False
        elif Version(lockdown.product_version) >= Version('14.0'):
            service_name = self.SERVICE_NAME
            remove_ssl_context = False
        else:
            service_name = self.OLD_SERVICE_NAME
            remove_ssl_context = True

        super().__init__(lockdown, service_name, remove_ssl_context=remove_ssl_context)
