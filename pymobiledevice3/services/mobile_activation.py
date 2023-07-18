#!/usr/bin/env python3
import plistlib
from contextlib import closing
from pathlib import Path

import requests

from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux

ACTIVATION_USER_AGENT_IOS = 'iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28)'
ACTIVATION_DEFAULT_URL = 'https://albert.apple.com/deviceservices/deviceActivation'
ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = 'https://albert.apple.com/deviceservices/drmHandshake'
DEFAULT_HEADERS = {
    'Accept': 'application/xml',
    'User-Agent': ACTIVATION_USER_AGENT_IOS,
    'Expect': '100-continue',
}

ACTIVATION_REQUESTS_SUBDIR = Path('offline_requests')
NONCE_CYCLE_INTERVAL = 60 * 5


class MobileActivationService:
    """
    Perform device activation

    There is no point in inheriting from BaseService since we'll need a new lockdown connection
    for each request.
    """
    SERVICE_NAME = 'com.apple.mobileactivationd'

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    @property
    def state(self):
        return self.send_command('GetActivationStateRequest')['Value']

    def wait_for_activation_session(self):
        blob = self.create_activation_session_info()
        handshake_request_message = blob['HandshakeRequestMessage']
        while handshake_request_message == blob['HandshakeRequestMessage']:
            blob = self.create_activation_session_info()

    def activate(self):
        blob = self.create_activation_session_info()

        # create drmHandshake request with blob from device
        headers = {'Content-Type': 'application/x-apple-plist'}
        headers.update(DEFAULT_HEADERS)
        content, headers = self.post(ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL, data=plistlib.dumps(blob), headers=headers)

        activation_info = self.create_activation_info_with_session(content)

        content, headers = self.post(ACTIVATION_DEFAULT_URL, data={'activation-info': plistlib.dumps(activation_info)})
        assert headers['Content-Type'] == 'text/xml'
        self.activate_with_session(content, headers)

    def deactivate(self):
        return self.send_command('DeactivateRequest')

    def create_activation_session_info(self):
        return self.send_command('CreateTunnel1SessionInfoRequest')['Value']

    def create_activation_info_with_session(self, handshake_response):
        return self.send_command('CreateTunnel1ActivationInfoRequest', handshake_response)['Value']

    def activate_with_session(self, activation_record, headers):
        data = {
            'Command': 'HandleActivationInfoWithSessionRequest',
            'Value': activation_record,
        }
        if headers:
            data['ActivationResponseHeaders'] = dict(headers)
        with closing(create_using_usbmux(self.lockdown.udid).start_lockdown_service(self.SERVICE_NAME)) as service:
            return service.send_recv_plist(data)

    def send_command(self, command, value=''):
        data = {'Command': command}
        if value:
            data['Value'] = value
        with closing(create_using_usbmux(self.lockdown.udid).start_lockdown_service(self.SERVICE_NAME)) as service:
            return service.send_recv_plist(data)

    def post(self, url, data, headers=None):
        if headers is None:
            headers = DEFAULT_HEADERS

        resp = requests.post(url, data=data, headers=headers)
        return resp.content, resp.headers
