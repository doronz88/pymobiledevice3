from io import BytesIO

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient


class MisagentService(object):
    SERVICE_NAME = 'com.apple.misagent'

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)

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

    def copy_all(self):
        response = self.service.send_recv_plist({'MessageType': 'CopyAll',
                                                 'ProfileType': 'Provisioning'})
        if response['Status']:
            raise PyMobileDevice3Exception(f'invalid status: {response}')

        return response['Payload']
