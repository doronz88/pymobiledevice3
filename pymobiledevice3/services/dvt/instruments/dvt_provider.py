from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class DvtProvider(DtxServiceProvider):
    SERVICE_NAME = "com.apple.instruments.remoteserver.DVTSecureSocketProxy"
    RSD_SERVICE_NAME = "com.apple.instruments.dtservicehub"
    OLD_SERVICE_NAME = "com.apple.instruments.remoteserver"

    def __init__(self, lockdown, strip_ssl=None, dtx=None):
        super().__init__(lockdown, strip_ssl, dtx)
        self.sent_capabilities["com.apple.instruments.client.processcontrol.capability.terminationCallback"] = 1
