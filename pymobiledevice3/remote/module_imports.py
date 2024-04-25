import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

try:
    from pymobiledevice3.remote.tunnel_service import RemotePairingQuicTunnel, start_tunnel

    MAX_IDLE_TIMEOUT = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT
except ImportError:
    start_tunnel: Optional[Callable] = None
    MAX_IDLE_TIMEOUT = None

GENERAL_IMPORT_ERROR = """Failed to import `start_tunnel`.
Please file an issue at:
https://github.com/doronz88/pymobiledevice3/issues/new?assignees=&labels=&projects=&template=bug_report.md&title=

Also, please supply with a traceback of the following python line:

from pymobiledevice3.remote.tunnel_service import start_tunnel
"""


def verify_tunnel_imports() -> bool:
    if start_tunnel is not None:
        return True
    logger.error(GENERAL_IMPORT_ERROR)
    return False
