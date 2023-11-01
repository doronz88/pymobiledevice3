import logging
import sys

logger = logging.getLogger(__name__)

try:
    from pymobiledevice3.remote.core_device_tunnel_service import RemotePairingTunnel, start_quic_tunnel

    MAX_IDLE_TIMEOUT = RemotePairingTunnel.MAX_IDLE_TIMEOUT
except ImportError:
    start_quic_tunnel = None
    MAX_IDLE_TIMEOUT = None

WIN32_IMPORT_ERROR = """Windows platforms are not yet supported for this command. For more info:
https://github.com/doronz88/pymobiledevice3/issues/569
"""

GENERAL_IMPORT_ERROR = """Failed to import `start_quic_tunnel`. Possible reasons are:
Please file an issue at:
https://github.com/doronz88/pymobiledevice3/issues/new?assignees=&labels=&projects=&template=bug_report.md&title=

Also, please supply with a traceback of the following python line:

from pymobiledevice3.remote.core_device_tunnel_service import start_quic_tunnel
"""


def verify_tunnel_imports() -> bool:
    if start_quic_tunnel is not None:
        return True
    if sys.platform == 'win32':
        logger.error(WIN32_IMPORT_ERROR)
        return False
    logger.error(GENERAL_IMPORT_ERROR)
    return False
