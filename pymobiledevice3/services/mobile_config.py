import plistlib
import logging

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient


class MobileConfigService(object):
    SERVICE_NAME = 'com.apple.mobile.MCInstall'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = lockdown.start_service(self.SERVICE_NAME)

    def get_profile_list(self):
        self.service.send_plist({'RequestType': 'GetProfileList'})
        response = self.service.recv_plist()
        if response.get('Status', None) != 'Acknowledged':
            raise PyMobileDevice3Exception(f'invalid response {response}')
        return response

    def install_profile(self, payload):
        self.service.send_plist({'RequestType': 'InstallProfile', 'Payload': payload})
        response = self.service.recv_plist()
        if response.get('Status') != 'Acknowledged':
            raise PyMobileDevice3Exception(f'Failed to install given profile: {response}')

    def remove_profile(self, ident):
        profiles = self.get_profile_list()
        if not profiles:
            return
        if ident not in profiles['ProfileMetadata']:
            self.logger.info('Trying to remove not installed profile %s', ident)
            return
        meta = profiles['ProfileMetadata'][ident]
        data = plistlib.dumps({'PayloadType': 'Configuration',
                               'PayloadIdentifier': ident,
                               'PayloadUUID': meta['PayloadUUID'],
                               'PayloadVersion': meta['PayloadVersion']
                               })
        self.service.send_plist({'RequestType': 'RemoveProfile', 'ProfileIdentifier': data})
        return self.service.recv_plist()
