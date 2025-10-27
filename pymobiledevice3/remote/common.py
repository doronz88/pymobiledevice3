import sys
from enum import Enum


class ConnectionType(Enum):
    USB = "usb"
    WIFI = "wifi"


class TunnelProtocol(Enum):
    TCP = "tcp"
    QUIC = "quic"

    # TODO: make only TCP the default once 3.12 becomes deprecated
    DEFAULT = TCP if sys.version_info >= (3, 13) else QUIC
