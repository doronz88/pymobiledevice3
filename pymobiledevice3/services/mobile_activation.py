#!/usr/bin/env python3
import dataclasses
import plistlib
import xml.etree.ElementTree as ET
from contextlib import closing
from pathlib import Path
from typing import List, Mapping

import click
import inquirer3
import requests

from pymobiledevice3.exceptions import MobileActivationException
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


@dataclasses.dataclass
class Field:
    id: str
    label: str
    placeholder: str
    secure: bool


@dataclasses.dataclass
class ActivationForm:
    title: str
    description: str
    fields: List[Field]
    server_info: Mapping[str, str]


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

    @staticmethod
    def _get_activation_form_from_response(content: str) -> ActivationForm:
        root = ET.fromstring(content)
        title = root.find('page/navigationBar').get('title')
        description = root.find('page/tableView/section/footer').text
        fields = []
        for editable in root.findall('page//editableTextRow'):
            fields.append(
                Field(id=editable.get('id'), label=editable.get('label'), placeholder=editable.get('placeholder'),
                      secure=bool(editable.get('secure', False))))
        server_info = {}
        for k, v in root.find('serverInfo').items():
            server_info[k] = v
        return ActivationForm(title=title, description=description, fields=fields, server_info=server_info)

    def activate(self, skip_apple_id_query: bool = False) -> None:
        blob = self.create_activation_session_info()

        # create drmHandshake request with blob from device
        headers = {'Content-Type': 'application/x-apple-plist'}
        headers.update(DEFAULT_HEADERS)
        content, headers = self.post(ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL, data=plistlib.dumps(blob), headers=headers)

        activation_info = self.create_activation_info_with_session(content)

        content, headers = self.post(ACTIVATION_DEFAULT_URL, data={'activation-info': plistlib.dumps(activation_info)})
        content_type = headers['Content-Type']

        if content_type == 'application/x-buddyml':
            if skip_apple_id_query:
                raise MobileActivationException('Device is iCloud locked')
            activation_form = self._get_activation_form_from_response(content.decode())
            click.secho(activation_form.title, bold=True)
            click.secho(activation_form.description)
            fields = []
            for field in activation_form.fields:
                if field.secure:
                    fields.append(inquirer3.Password(name=field.id, message=f'{field.label}'))
                else:
                    fields.append(inquirer3.Text(name=field.id, message=f'{field.label}'))
            data = inquirer3.prompt(fields)
            data.update(activation_form.server_info)
            content, headers = self.post(ACTIVATION_DEFAULT_URL, data=data)
            content_type = headers['Content-Type']

        assert content_type == 'text/xml'
        self.activate_with_session(content, headers)

    def deactivate(self):
        return self.send_command('DeactivateRequest')

    def create_activation_session_info(self):
        response = self.send_command('CreateTunnel1SessionInfoRequest')
        error = response.get('Error')
        if error is not None:
            raise MobileActivationException(f'Mobile activation can not be done due to: {response}')
        return response['Value']

    def create_activation_info_with_session(self, handshake_response):
        response = self.send_command('CreateTunnel1ActivationInfoRequest', handshake_response)
        error = response.get('Error')
        if error is not None:
            raise MobileActivationException(f'Mobile activation can not be done due to: {response}')
        return response['Value']

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
