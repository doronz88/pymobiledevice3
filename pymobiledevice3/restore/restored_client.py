import logging

from pymobiledevice3.exceptions import NoDeviceConnectedError, DeviceNonConnectedError
from pymobiledevice3.lockdown import list_devices
from pymobiledevice3.service_connection import ServiceConnection


class RestoredClient(object):
    DEFAULT_CLIENT_NAME = 'pyMobileDevice'
    SERVICE_PORT = 62078

    def __init__(self, udid=None, client_name=DEFAULT_CLIENT_NAME):
        available_udids = list_devices()
        if udid is None:
            if len(available_udids) == 0:
                raise NoDeviceConnectedError()
            udid = available_udids[0]
        else:
            if udid not in available_udids:
                raise DeviceNonConnectedError()

        self.logger = logging.getLogger(__name__)
        self.service = ServiceConnection.create(udid, self.SERVICE_PORT)
        self.label = client_name
        self.query_type = self.service.send_recv_plist({'Request': 'QueryType'})
        self.version = self.query_type.get('RestoreProtocolVersion')

        assert self.query_type.get('Type') == 'com.apple.mobile.restored', f'wrong query type: {self.query_type}'

    def query_value(self, key=None):
        req = {'Request': 'QueryValue', 'Label': self.label}

        if key:
            req['QueryKey'] = key

        return self.service.send_recv_plist(req)

    def start_restore(self, opts=None):
        req = {'Request': 'StartRestore', 'Label': self.label, 'RestoreProtocolVersion': self.version}

        if opts is not None:
            req['RestoreOptions'] = opts

        logging.debug(f'start_restore request: {req}')

        return self.service.send_plist(req)

    def reboot(self):
        return self.service.send_recv_plist({'Request': 'Reboot', 'Label': self.label})

    def send(self, message):
        self.service.send_plist(message)

    def recv(self):
        return self.service.recv_plist()
