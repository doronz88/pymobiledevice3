from typing import Optional

from pymobiledevice3.dtx import DTXConnection
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


class DvtProvider(DtxServiceProvider):
    """
    Provides access to the DVT (DTX Instruments) services exposed by Apple's
    ``instruments`` daemon.

    The provider opens a `DTXConnection` on top of a
    given service provider and is the entry point used by the individual DVT
    `DTXService` subclasses (process control, device
    info, screenshot, etc.).

    The underlying service is reached differently depending on the transport:

    - over lockdown (``SERVICE_NAME`` /``OLD_SERVICE_NAME`` ) on older iOS versions
    - over an RSD tunnel (``RSD_SERVICE_NAME`` ) on iOS 17 and later

    The provider is meant to be used as an async context manager, which connects
    the DTX transport on entry and closes it on exit::

        async with DvtProvider(lockdown) as provider:
            ...

    It additionally advertises the process-control ``terminationCallback``
    capability so that the device reports process termination events.
    """

    SERVICE_NAME = "com.apple.instruments.remoteserver.DVTSecureSocketProxy"
    RSD_SERVICE_NAME = "com.apple.instruments.dtservicehub"
    OLD_SERVICE_NAME = "com.apple.instruments.remoteserver"

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        strip_ssl: Optional[bool] = None,
        dtx: Optional[DTXConnection] = None,
    ) -> None:
        """
        :param lockdown: Lockdown or RSD service provider used to reach the DVT service.
        :param strip_ssl: Override the SSL-stripping behaviour. ``None`` (default) lets
            the base provider decide based on the transport.
        :param dtx: Pre-built `DTXConnection` to reuse instead
            of opening a new one (shares a single transport across callers).
        """
        super().__init__(lockdown, strip_ssl, dtx)
        # the base provider always initializes sent_capabilities to a dict
        assert self.sent_capabilities is not None
        self.sent_capabilities["com.apple.instruments.client.processcontrol.capability.terminationCallback"] = 1
