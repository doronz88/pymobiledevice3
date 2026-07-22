from collections.abc import AsyncGenerator
from typing import Union

from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import try_decode

CHUNK_SIZE = 4096
TIME_FORMAT = "%H:%M:%S"
SYSLOG_LINE_SPLITTER = b"\n\x00"


class SyslogService(LockdownService):
    """
    Stream the device's live system log via the ``com.apple.syslog_relay`` service.

    The service name used depends on the lockdown type (legacy ``com.apple.syslog_relay`` for
    `LockdownClient`, RSD shim otherwise).
    """

    SERVICE_NAME = "com.apple.syslog_relay"
    RSD_SERVICE_NAME = "com.apple.syslog_relay.shim.remote"

    def __init__(self, service_provider: LockdownServiceProvider):
        if isinstance(service_provider, LockdownClient):
            super().__init__(service_provider, self.SERVICE_NAME)
        else:
            super().__init__(service_provider, self.RSD_SERVICE_NAME)

    async def watch(self) -> AsyncGenerator[Union[str, bytes], None]:
        """
        Stream syslog lines from the device as they are emitted.

        Reads the relay in chunks, splits on the syslog line delimiter, buffers any partial trailing
        line until the rest arrives, and decodes each complete line. Empty lines are skipped.

        :yields: A single decoded syslog line (without the trailing delimiter), or the raw bytes
            when the line is not valid UTF-8.
        :raises ConnectionTerminatedError: If the device closes the connection.
        """
        buf = b""
        while True:
            # read in chunks till we have at least one syslog line
            chunk = await self.service.recv_any(CHUNK_SIZE)

            if len(chunk) == 0:
                raise ConnectionTerminatedError()

            buf += chunk

            # SYSLOG_LINE_SPLITTER is used to split each syslog line
            if SYSLOG_LINE_SPLITTER in buf:
                lines = buf.split(SYSLOG_LINE_SPLITTER)

                # handle partial last lines
                if not buf.endswith(SYSLOG_LINE_SPLITTER):
                    buf = lines[-1]
                    lines = lines[:-1]

                for line in lines:
                    if len(line) == 0:
                        continue

                    yield try_decode(line)
