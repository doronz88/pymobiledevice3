from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import try_decode

CHUNK_SIZE = 4096
TIME_FORMAT = '%H:%M:%S'
SYSLOG_LINE_SPLITTER = b'\n\x00'


class SyslogService(LockdownService):
    """
    View system logs
    """

    SERVICE_NAME = 'com.apple.syslog_relay'
    RSD_SERVICE_NAME = 'com.apple.syslog_relay.shim.remote'

    def __init__(self, service_provider: LockdownServiceProvider):
        if isinstance(service_provider, LockdownClient):
            super().__init__(service_provider, self.SERVICE_NAME)
        else:
            super().__init__(service_provider, self.RSD_SERVICE_NAME)

    def watch(self):
        buf = b''
        while True:
            # read in chunks till we have at least one syslog line
            chunk = self.service.recv(CHUNK_SIZE)

            if len(chunk) == 0:
                raise ConnectionAbortedError()

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
