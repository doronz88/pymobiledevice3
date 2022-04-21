import plistlib
from io import BytesIO
from typing import List

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class ProvisioningProfile:
    def __init__(self, buf: bytes):
        self.buf = buf

        xml = b'<?xml' + buf.split(b'<?xml', 1)[1]
        xml = xml.split(b'</plist>')[0] + b'</plist>'
        self.plist = plistlib.loads(xml)

    def __str__(self):
        return str(self.plist)


class MisagentService(BaseService):
    SERVICE_NAME = 'com.apple.misagent'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME)

    def install(self, plist: BytesIO):
        response = self.service.send_recv_plist({'MessageType': 'Install',
                                                 'Profile': plist.read(),
                                                 'ProfileType': 'Provisioning'})
        if response['Status']:
            raise PyMobileDevice3Exception(f'invalid status: {response}')

        return response

    def remove(self, profile_id):
        response = self.service.send_recv_plist({'MessageType': 'Remove',
                                                 'ProfileID': profile_id,
                                                 'ProfileType': 'Provisioning'})
        if response['Status']:
            raise PyMobileDevice3Exception(f'invalid status: {response}')

        return response

    def copy_all(self) -> List[ProvisioningProfile]:
        response = self.service.send_recv_plist({'MessageType': 'CopyAll',
                                                 'ProfileType': 'Provisioning'})
        if response['Status']:
            raise PyMobileDevice3Exception(f'invalid status: {response}')

        return [ProvisioningProfile(p) for p in response['Payload']]
