import plistlib
from enum import Enum
from pathlib import Path
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder

from pymobiledevice3.exceptions import CloudConfigurationAlreadyPresentError, ProfileError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT = 14002


class Purpose(Enum):
    PostSetupInstallation = 'PostSetupInstallation'


class MobileConfigService(LockdownService):
    SERVICE_NAME = 'com.apple.mobile.MCInstall'
    RSD_SERVICE_NAME = 'com.apple.mobile.MCInstall.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def hello(self) -> None:
        self._send_recv({'RequestType': 'HelloHostIdentifier'})

    def flush(self) -> None:
        self._send_recv({'RequestType': 'Flush'})

    def escalate(self, certificate_file: str) -> None:
        """
        Authenticate with the device.

        :param certificate_file: Certificate file in PEM format, containing certificate and private key.
        :return: None
        """
        with open(certificate_file, 'rb') as certificate_file:
            certificate_file = certificate_file.read()
        private_key = serialization.load_pem_private_key(certificate_file, password=None)
        cer = x509.load_pem_x509_certificate(certificate_file)
        public_key = cer.public_bytes(Encoding.DER)
        escalate_response = self._send_recv({
            'RequestType': 'Escalate',
            'SupervisorCertificate': public_key
        })
        signed_challenge = PKCS7SignatureBuilder().set_data(escalate_response['Challenge']).add_signer(
            cer, private_key, hashes.SHA256()).sign(Encoding.DER, [])
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

    def install_profile_silent(self, certificate_file: str, profile: bytes) -> None:
        self.escalate(certificate_file)
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
            error_chain = response.get('ErrorChain')
            if error_chain is not None:
                error_code = error_chain[0]['ErrorCode']
                if error_code == ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT:
                    raise CloudConfigurationAlreadyPresentError()
            raise ProfileError(f'invalid response {response}')
        return response

    def supervise(self, organization: str, keybag: Path) -> None:
        cer = x509.load_pem_x509_certificate(keybag.read_bytes())
        public_key = cer.public_bytes(Encoding.DER)
        self.set_cloud_configuration({
            'AllowPairing': True,
            'CloudConfigurationUIComplete': True,
            'ConfigurationSource': 2,
            'ConfigurationWasApplied': True,
            'IsMDMUnremovable': False,
            'IsMandatory': True,
            'IsMultiUser': False,
            'IsSupervised': True,
            'OrganizationMagic': '5A750C81-5B7E-4F7B-B070-B5E565236C04',
            'OrganizationName': organization,
            'PostSetupProfileWasInstalled': True,
            'SkipSetup': [
                'Location',
                'Restore',
                'SIMSetup',
                'Android',
                'AppleID',
                'IntendedUser',
                'TOS',
                'Siri',
                'ScreenTime',
                'Diagnostics',
                'SoftwareUpdate',
                'Passcode',
                'Biometric',
                'Payment',
                'Zoom',
                'DisplayTone',
                'MessagingActivationUsingPhoneNumber',
                'HomeButtonSensitivity',
                'CloudStorage',
                'ScreenSaver',
                'TapToSetup',
                'Keyboard',
                'PreferredLanguage',
                'SpokenLanguage',
                'WatchMigration',
                'OnBoarding',
                'TVProviderSignIn',
                'TVHomeScreenSync',
                'Privacy',
                'TVRoom',
                'iMessageAndFaceTime',
                'AppStore',
                'Safety',
                'Multitasking',
                'ActionButton',
                'TermsOfAddress',
                'AccessibilityAppearance',
                'Welcome',
                'Appearance',
                'RestoreCompleted',
                'UpdateCompleted'
            ],
            'SupervisorHostCertificates': [
                public_key
            ]
        })
