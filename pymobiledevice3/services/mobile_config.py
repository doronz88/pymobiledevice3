import plistlib
from enum import Enum
from typing import Mapping

from pymobiledevice3.exceptions import ProfileError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class Purpose(Enum):
    PostSetupInstallation = 'PostSetupInstallation'


class MobileConfigService(BaseService):
    SERVICE_NAME = 'com.apple.mobile.MCInstall'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME)

    def hello(self) -> None:
        self._send_recv({'RequestType': 'HelloHostIdentifier'})

    def flush(self) -> None:
        self._send_recv({'RequestType': 'Flush'})

    def get_stored_profile(self, purpose: Purpose = Purpose.PostSetupInstallation) -> Mapping:
        return self._send_recv({'RequestType': 'GetStoredProfile', 'Purpose': purpose.value})

    def store_profile(self, profile_data: bytes, purpose: Purpose = Purpose.PostSetupInstallation) -> None:
        self._send_recv({'RequestType': 'StoreProfile', 'ProfileData': profile_data, 'Purpose': purpose.value})

    def get_cloud_configuration(self) -> Mapping:
        return self._send_recv({'RequestType': 'GetCloudConfiguration'}).get('CloudConfiguration')

    def set_cloud_configuration(self, cloud_configuration: Mapping) -> None:
        self._send_recv({'RequestType': 'SetCloudConfiguration', 'CloudConfiguration': cloud_configuration})

    def establish_provisional_enrollment(self, nonce: bytes) -> None:
        self._send_recv({'RequestType': 'EstablishProvisionalEnrollment', 'Nonce': nonce})

    def set_wifi_power_state(self, state: bool) -> None:
        self._send_recv({'RequestType': 'SetWiFiPowerState', 'PowerState': state})

    def erase_device(self, preserve_data_plan: bool, disallow_proximity_setup: bool) -> None:
        try:
            self._send_recv({'RequestType': 'EraseDevice', 'PreserveDataPlan': preserve_data_plan,
                             'DisallowProximitySetup': disallow_proximity_setup})
        except ConnectionAbortedError:
            pass

    def get_profile_list(self) -> Mapping:
        return self._send_recv({'RequestType': 'GetProfileList'})

    def install_profile(self, payload: bytes) -> None:
        self._send_recv({'RequestType': 'InstallProfile', 'Payload': payload})

    def remove_profile(self, identifier: str) -> None:
        profiles = self.get_profile_list()
        if not profiles:
            return
        if identifier not in profiles['ProfileMetadata']:
            self.logger.info(f'Trying to remove not installed profile: {identifier}')
            return
        meta = profiles['ProfileMetadata'][identifier]
        data = plistlib.dumps({'PayloadType': 'Configuration',
                               'PayloadIdentifier': identifier,
                               'PayloadUUID': meta['PayloadUUID'],
                               'PayloadVersion': meta['PayloadVersion']
                               })
        self._send_recv({'RequestType': 'RemoveProfile', 'ProfileIdentifier': data})

    def _send_recv(self, request: Mapping) -> Mapping:
        response = self.service.send_recv_plist(request)
        if response.get('Status', None) != 'Acknowledged':
            raise ProfileError(f'invalid response {response}')
        return response
