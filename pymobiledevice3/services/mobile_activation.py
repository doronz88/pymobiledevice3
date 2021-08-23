#!/usr/bin/env python3
import logging
import plistlib
import shlex
from contextlib import closing
from pathlib import Path
import time

import requests

from pymobiledevice3.lockdown import LockdownClient

ACTIVATION_USER_AGENT_IOS = 'iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28)'
ACTIVATION_DEFAULT_URL = 'https://albert.apple.com/deviceservices/deviceActivation'
ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = 'https://albert.apple.com/deviceservices/drmHandshake'
DEFAULT_HEADERS = {
    'Accept': 'application/xml',
    'User-Agent': ACTIVATION_USER_AGENT_IOS,
    'Expect': '100-continue',
}

ACTIVATION_REQUESTS_SUBDIR = Path('activation')


class MobileActivationService:
    SERVICE_NAME = 'com.apple.mobileactivationd'

    def __init__(self, lockdown: LockdownClient, offline=True):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.offline = offline

    @property
    def state(self):
        return self.send_command('GetActivationStateRequest')['Value']

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
        with closing(self.lockdown.start_service(self.SERVICE_NAME)) as service:
            return service.send_recv_plist(data)

    def send_command(self, command, value=''):
        data = {'Command': command}
        if value:
            data['Value'] = value
        with closing(self.lockdown.start_service(self.SERVICE_NAME)) as service:
            return service.send_recv_plist(data)

    def post(self, url, data, headers=None):
        if headers is None:
            headers = DEFAULT_HEADERS
        if not self.offline:
            resp = requests.post(url, data=data, headers=headers)
            return resp.content, resp.headers
        for file in ACTIVATION_REQUESTS_SUBDIR.iterdir():
            file.unlink()
        ACTIVATION_REQUESTS_SUBDIR.mkdir(parents=True, exist_ok=True)
        curl_arguments = ['curl', '-X', 'POST', '-D', 'headers.txt']

        if isinstance(data, bytes):
            request_data = ACTIVATION_REQUESTS_SUBDIR / f'request_data_{hash(data)}.plist'
            request_data.write_bytes(data)
            curl_arguments.extend(['--data-binary', f'@{request_data.name}'])
        elif isinstance(data, dict):
            for key, value, in data.items():
                request_data = ACTIVATION_REQUESTS_SUBDIR / f'request_data_{hash(value)}.plist'
                request_data.write_bytes(value)
                curl_arguments.extend(['-F', f'{key}=@{request_data.name}'])

        for header, value in headers.items():
            curl_arguments.extend(['-H', f'{header}: {value}'])

        headers = ACTIVATION_REQUESTS_SUBDIR / 'headers.txt'
        curl_arguments.extend(['-D', headers.name])
        curl_arguments.append(url)

        response = ACTIVATION_REQUESTS_SUBDIR / f'request_data_{time.time()}.txt'
        request = ACTIVATION_REQUESTS_SUBDIR / f'request_script.sh'
        request.write_text(f'#!/bin/sh\n{shlex.join(curl_arguments)} | tee {response.name}\n')
        request.chmod(0o755)

        self.logger.info(f'Run the following shell script ({request.name})')
        # Check for plist response.
        while not response.exists() or b'</plist>' not in response.read_bytes():
            time.sleep(1)

        # Check for headers.
        while not headers.exists() or ': ' not in headers.read_text():
            time.sleep(1)

        raw_headers = headers.read_text()
        parsed_headers = {}
        for line in raw_headers.splitlines():
            if ': ' not in line:
                continue
            key, value = line.split(': ', 1)
            parsed_headers[key] = value

        return response.read_bytes(), parsed_headers
