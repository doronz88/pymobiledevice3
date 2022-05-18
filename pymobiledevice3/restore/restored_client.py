import logging

from cached_property import cached_property

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import NoDeviceConnectedError, ConnectionFailedError
from pymobiledevice3.restore.restore_options import RestoreOptions
from pymobiledevice3.service_connection import ServiceConnection


class RestoredClient(object):
    DEFAULT_CLIENT_NAME = 'pyMobileDevice'
    SERVICE_PORT = 62078

    def __init__(self, udid=None, client_name=DEFAULT_CLIENT_NAME):
        self.logger = logging.getLogger(__name__)
        self.udid = self._get_or_verify_udid(udid)
        self.service = ServiceConnection.create(self.udid, self.SERVICE_PORT)
        self.label = client_name
        self.query_type = self.service.send_recv_plist({'Request': 'QueryType'})
        self.version = self.query_type.get('RestoreProtocolVersion')

        assert self.query_type.get('Type') == 'com.apple.mobile.restored', f'wrong query type: {self.query_type}'

    @staticmethod
    def _get_or_verify_udid(udid=None):
        device = usbmux.select_device(udid)
        if device is None:
            if udid:
                raise ConnectionFailedError()
            else:
                raise NoDeviceConnectedError()
        return device.serial

    def query_value(self, key=None):
        req = {'Request': 'QueryValue', 'Label': self.label}

        if key:
            req['QueryKey'] = key

        return self.service.send_recv_plist(req)

    def start_restore(self, opts: RestoreOptions = None):
        req = {'Request': 'StartRestore', 'Label': self.label, 'RestoreProtocolVersion': self.version}

        if opts is not None:
            req['RestoreOptions'] = opts.to_dict()

        self.logger.debug(f'start_restore request: {req}')

        return self.service.send_plist(req)

    def reboot(self):
        return self.service.send_recv_plist({'Request': 'Reboot', 'Label': self.label})

    def send(self, message):
        self.service.send_plist(message)

    def recv(self):
        return self.service.recv_plist()

    @cached_property
    def hardware_info(self):
        return self.query_value('HardwareInfo')['HardwareInfo']

    @property
    def saved_debug_info(self):
        return self.query_value('SavedDebugInfo')['SavedDebugInfo']
