from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class DvtProvider(DtxServiceProvider):
    SERVICE_NAME = "com.apple.instruments.remoteserver.DVTSecureSocketProxy"
    RSD_SERVICE_NAME = "com.apple.instruments.dtservicehub"
    OLD_SERVICE_NAME = "com.apple.instruments.remoteserver"
