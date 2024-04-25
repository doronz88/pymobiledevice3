from enum import Enum


class ConnectionType(Enum):
    USB = 'usb'
    WIFI = 'wifi'


class TunnelProtocol(Enum):
    TCP = 'tcp'
    QUIC = 'quic'
