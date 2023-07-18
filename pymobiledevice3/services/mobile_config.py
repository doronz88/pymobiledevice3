import plistlib
from enum import Enum
from typing import Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder
from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

from pymobiledevice3.exceptions import ProfileError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService


class Purpose(Enum):
    PostSetupInstallation = 'PostSetupInstallation'


class MobileConfigService(LockdownService):
    SERVICE_NAME = 'com.apple.mobile.MCInstall'
    RSD_SERVICE_NAME = 'com.apple.mobile.MCInstall.shim.remote'

    def __init__(self, lockdown: LockdownClient):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def hello(self) -> None:
        self._send_recv({'RequestType': 'HelloHostIdentifier'})

    def flush(self) -> None:
        self._send_recv({'RequestType': 'Flush'})

    def escalate(self, pkcs12: bytes, password: str) -> None:
        decrypted_p12 = load_pkcs12(pkcs12, password.encode('utf-8'))

        escalate_response = self._send_recv({
            'RequestType': 'Escalate',
            'SupervisorCertificate': decrypted_p12.cert.certificate.public_bytes(Encoding.DER)
        })
        signed_challenge = PKCS7SignatureBuilder().set_data(escalate_response['Challenge']).add_signer(
            decrypted_p12.cert.certificate, decrypted_p12.key, hashes.SHA256()).sign(Encoding.DER, [])
        self._send_recv({'RequestType': 'EscalateResponse', 'SignedRequest': signed_challenge})
        self._send_recv({'RequestType': 'ProceedWithKeybagMigration'})

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

    def install_profile_silent(self, profile: bytes, pkcs12: bytes, password: str) -> None:
        self.escalate(pkcs12, password)
        self._send_recv({'RequestType': 'InstallProfileSilent', 'Payload': profile})

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
