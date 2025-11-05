import contextlib
import plistlib
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder

from pymobiledevice3.exceptions import CloudConfigurationAlreadyPresentError, ProfileError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT = 14002
GLOBAL_HTTP_PROXY_UUID = "86a52338-52f7-4c09-b005-52baf3dc4882"
GLOBAL_RESTRICTIONS_UUID = "e22a0a66-08a8-43f5-9bbc-5279af35bb2b"


class Purpose(Enum):
    PostSetupInstallation = "PostSetupInstallation"


class MobileConfigService(LockdownService):
    SERVICE_NAME = "com.apple.mobile.MCInstall"
    RSD_SERVICE_NAME = "com.apple.mobile.MCInstall.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def hello(self) -> None:
        self._send_recv({"RequestType": "HelloHostIdentifier"})

    def flush(self) -> None:
        self._send_recv({"RequestType": "Flush"})

    def escalate(self, keybag_file: Path) -> None:
        """
        Authenticate with the device.

        :param keybag_file: Certificate file in PEM format, containing certificate and private key.
        :return: None
        """
        with open(keybag_file, "rb") as keybag_file:
            keybag_file = keybag_file.read()
        private_key = serialization.load_pem_private_key(keybag_file, password=None)
        cer = x509.load_pem_x509_certificate(keybag_file)
        public_key = cer.public_bytes(Encoding.DER)
        escalate_response = self._send_recv({"RequestType": "Escalate", "SupervisorCertificate": public_key})
        signed_challenge = (
            PKCS7SignatureBuilder()
            .set_data(escalate_response["Challenge"])
            .add_signer(cer, private_key, hashes.SHA256())
            .sign(Encoding.DER, [])
        )
        self._send_recv({"RequestType": "EscalateResponse", "SignedRequest": signed_challenge})
        self._send_recv({"RequestType": "ProceedWithKeybagMigration"})

    def get_stored_profile(self, purpose: Purpose = Purpose.PostSetupInstallation) -> dict:
        return self._send_recv({"RequestType": "GetStoredProfile", "Purpose": purpose.value})

    def store_profile(self, profile_data: bytes, purpose: Purpose = Purpose.PostSetupInstallation) -> None:
        self._send_recv({"RequestType": "StoreProfile", "ProfileData": profile_data, "Purpose": purpose.value})

    def get_cloud_configuration(self) -> dict:
        return self._send_recv({"RequestType": "GetCloudConfiguration"}).get("CloudConfiguration")

    def set_cloud_configuration(self, cloud_configuration: dict) -> None:
        self._send_recv({"RequestType": "SetCloudConfiguration", "CloudConfiguration": cloud_configuration})

    def establish_provisional_enrollment(self, nonce: bytes) -> None:
        self._send_recv({"RequestType": "EstablishProvisionalEnrollment", "Nonce": nonce})

    def set_wifi_power_state(self, state: bool) -> None:
        self._send_recv({"RequestType": "SetWiFiPowerState", "PowerState": state})

    def erase_device(self, preserve_data_plan: bool, disallow_proximity_setup: bool) -> None:
        with contextlib.suppress(ConnectionAbortedError):
            self._send_recv({
                "RequestType": "EraseDevice",
                "PreserveDataPlan": preserve_data_plan,
                "DisallowProximitySetup": disallow_proximity_setup,
            })

    def get_profile_list(self) -> dict:
        return self._send_recv({"RequestType": "GetProfileList"})

    def install_profile(self, payload: bytes) -> None:
        self._send_recv({"RequestType": "InstallProfile", "Payload": payload})

    def install_profile_silent(self, keybag_file: Path, profile: bytes) -> None:
        self.escalate(keybag_file)
        self._send_recv({"RequestType": "InstallProfileSilent", "Payload": profile})

    def remove_profile(self, identifier: str) -> None:
        profiles = self.get_profile_list()
        if not profiles:
            return
        if identifier not in profiles["ProfileMetadata"]:
            self.logger.info(f"Trying to remove not installed profile: {identifier}")
            return
        meta = profiles["ProfileMetadata"][identifier]
        data = plistlib.dumps({
            "PayloadType": "Configuration",
            "PayloadIdentifier": identifier,
            "PayloadUUID": meta["PayloadUUID"],
            "PayloadVersion": meta["PayloadVersion"],
        })
        self._send_recv({"RequestType": "RemoveProfile", "ProfileIdentifier": data})

    def _send_recv(self, request: dict) -> dict:
        response = self.service.send_recv_plist(request)
        if response.get("Status", None) != "Acknowledged":
            error_chain = response.get("ErrorChain")
            if error_chain is not None:
                error_code = error_chain[0]["ErrorCode"]
                if error_code == ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT:
                    raise CloudConfigurationAlreadyPresentError()
            raise ProfileError(f"invalid response {response}")
        return response

    def install_wifi_profile(
        self,
        encryption_type: str,
        ssid: str,
        password: str,
        auto_join: bool = True,
        captive_bypass: bool = False,
        disable_association_mac_randomization: bool = False,
        hidden_network: bool = False,
        is_hotspot: bool = False,
        keybag_file: Optional[Path] = None,
    ) -> None:
        payload_uuid = str(uuid4())
        self.install_managed_profile(
            f"WiFi Profile For {ssid}",
            {
                "AutoJoin": auto_join,
                "CaptiveBypass": captive_bypass,
                "DisableAssociationMACRandomization": disable_association_mac_randomization,
                "EncryptionType": encryption_type,
                "HIDDEN_NETWORK": hidden_network,
                "IsHotspot": is_hotspot,
                "Password": password,
                "PayloadDescription": "Configures Wi-Fi settings",
                "PayloadDisplayName": "Wi-Fi",
                "PayloadIdentifier": f"com.apple.wifi.managed.{payload_uuid}",
                "PayloadType": "com.apple.wifi.managed",
                "PayloadUUID": payload_uuid,
                "PayloadVersion": 1,
                "ProxyType": "None",
                "SSID_STR": ssid,
            },
            keybag_file=keybag_file,
        )

    def install_http_proxy(self, server: str, server_port: int, keybag_file: Optional[Path] = None) -> None:
        payload_uuid = str(uuid4())
        self.install_managed_profile(
            f"HTTP Proxy for {server}:{server_port}",
            {
                "PayloadDescription": "Global HTTP Proxy",
                "PayloadDisplayName": "Global HTTP Proxy",
                "PayloadIdentifier": f"com.apple.proxy.http.global.{payload_uuid}",
                "PayloadType": "com.apple.proxy.http.global",
                "PayloadUUID": payload_uuid,
                "PayloadVersion": 1,
                "ProxyCaptiveLoginAllowed": False,
                "ProxyServer": server,
                "ProxyServerPort": server_port,
                "ProxyType": "Manual",
            },
            payload_uuid=GLOBAL_HTTP_PROXY_UUID,
            keybag_file=keybag_file,
        )

    def remove_http_proxy(self) -> None:
        self.remove_profile(GLOBAL_HTTP_PROXY_UUID)

    def supervise(self, organization: str, keybag_file: Path) -> None:
        cer = x509.load_pem_x509_certificate(keybag_file.read_bytes())
        public_key = cer.public_bytes(Encoding.DER)
        self.set_cloud_configuration({
            "AllowPairing": True,
            "CloudConfigurationUIComplete": True,
            "ConfigurationSource": 2,
            "ConfigurationWasApplied": True,
            "IsMDMUnremovable": False,
            "IsMandatory": True,
            "IsMultiUser": False,
            "IsSupervised": True,
            "OrganizationMagic": str(uuid4()),
            "OrganizationName": organization,
            "PostSetupProfileWasInstalled": True,
            "SkipSetup": [
                "Location",
                "Restore",
                "SIMSetup",
                "Android",
                "AppleID",
                "IntendedUser",
                "TOS",
                "Siri",
                "ScreenTime",
                "Diagnostics",
                "SoftwareUpdate",
                "Passcode",
                "Biometric",
                "Payment",
                "Zoom",
                "DisplayTone",
                "MessagingActivationUsingPhoneNumber",
                "HomeButtonSensitivity",
                "CloudStorage",
                "ScreenSaver",
                "TapToSetup",
                "Keyboard",
                "PreferredLanguage",
                "SpokenLanguage",
                "WatchMigration",
                "OnBoarding",
                "TVProviderSignIn",
                "TVHomeScreenSync",
                "Privacy",
                "TVRoom",
                "iMessageAndFaceTime",
                "AppStore",
                "Safety",
                "Multitasking",
                "ActionButton",
                "TermsOfAddress",
                "AccessibilityAppearance",
                "Welcome",
                "Appearance",
                "RestoreCompleted",
                "UpdateCompleted",
                "WiFi",
                "Display",
                "Tone",
                "LanguageAndLocale",
                "TouchID",
                "TrueToneDisplay",
                "FileVault",
                "iCloudStorage",
                "iCloudDiagnostics",
                "Registration",
                "DeviceToDeviceMigration",
                "UnlockWithWatch",
                "Accessibility",
                "All",
                "ExpressLanguage",
                "Language",
                "N/A",
                "Region",
                "Avatar",
                "DeviceProtection",
                "Key",
                "LockdownMode",
                "Wallpaper",
                "PrivacySubtitle",
                "SecuritySubtitle",
                "DataSubtitle",
                "AppleIDSubtitle",
                "AppearanceSubtitle",
                "PreferredLang",
                "OnboardingSubtitle",
                "AppleTVSubtitle",
                "Intelligence",
                "WebContentFiltering",
                "CameraButton",
                "AdditionalPrivacySettings",
                "EnableLockdownMode",
                "OSShowcase",
                "SafetyAndHandling",
                "Tips",
                "AgeBasedSafetySettings",
            ],
            "SupervisorHostCertificates": [public_key],
        })

    def install_managed_profile(
        self,
        display_name: str,
        payload_content: dict[str, Any],
        payload_uuid: str = str(uuid4()),
        keybag_file: Optional[Path] = None,
    ) -> None:
        profile_data = plistlib.dumps({
            "PayloadContent": [payload_content],
            "PayloadDisplayName": display_name,
            "PayloadIdentifier": payload_uuid,
            "PayloadRemovalDisallowed": False,
            "PayloadType": "Configuration",
            "PayloadUUID": payload_uuid,
            "PayloadVersion": 1,
        })
        if keybag_file is not None:
            self.install_profile_silent(keybag_file, profile_data)
        else:
            self.install_profile(profile_data)

    def install_restrictions_profile(
        self,
        enforced_software_update_delay: int = 0,
        payload_uuid: str = GLOBAL_RESTRICTIONS_UUID,
        keybag_file: Optional[Path] = None,
    ) -> None:
        self.install_managed_profile(
            "Restrictions",
            {
                "PayloadDescription": "Configures restrictions",
                "PayloadDisplayName": "Restrictions",
                "PayloadIdentifier": f"com.apple.applicationaccess.{payload_uuid}",
                "PayloadType": "com.apple.applicationaccess",
                "PayloadUUID": payload_uuid,
                "PayloadVersion": 1,
                "allowActivityContinuation": True,
                "allowAddingGameCenterFriends": True,
                "allowAirPlayIncomingRequests": True,
                "allowAirPrint": True,
                "allowAirPrintCredentialsStorage": True,
                "allowAirPrintiBeaconDiscovery": True,
                "allowAppCellularDataModification": True,
                "allowAppClips": True,
                "allowAppInstallation": True,
                "allowAppRemoval": True,
                "allowApplePersonalizedAdvertising": True,
                "allowAssistant": True,
                "allowAssistantWhileLocked": True,
                "allowAutoCorrection": True,
                "allowAutoUnlock": True,
                "allowAutomaticAppDownloads": True,
                "allowBluetoothModification": True,
                "allowBookstore": True,
                "allowBookstoreErotica": True,
                "allowCamera": True,
                "allowCellularPlanModification": True,
                "allowChat": True,
                "allowCloudBackup": True,
                "allowCloudDocumentSync": True,
                "allowCloudPhotoLibrary": True,
                "allowContinuousPathKeyboard": True,
                "allowDefinitionLookup": True,
                "allowDeviceNameModification": True,
                "allowDeviceSleep": True,
                "allowDictation": True,
                "allowESIMModification": True,
                "allowEnablingRestrictions": True,
                "allowEnterpriseAppTrust": True,
                "allowEnterpriseBookBackup": True,
                "allowEnterpriseBookMetadataSync": True,
                "allowEraseContentAndSettings": True,
                "allowExplicitContent": True,
                "allowFilesNetworkDriveAccess": True,
                "allowFilesUSBDriveAccess": True,
                "allowFindMyDevice": True,
                "allowFindMyFriends": True,
                "allowFingerprintForUnlock": True,
                "allowFingerprintModification": True,
                "allowGameCenter": True,
                "allowGlobalBackgroundFetchWhenRoaming": True,
                "allowInAppPurchases": True,
                "allowKeyboardShortcuts": True,
                "allowManagedAppsCloudSync": True,
                "allowMultiplayerGaming": True,
                "allowMusicService": True,
                "allowNews": True,
                "allowNotificationsModification": True,
                "allowOpenFromManagedToUnmanaged": True,
                "allowOpenFromUnmanagedToManaged": True,
                "allowPairedWatch": True,
                "allowPassbookWhileLocked": True,
                "allowPasscodeModification": True,
                "allowPasswordAutoFill": True,
                "allowPasswordProximityRequests": True,
                "allowPasswordSharing": True,
                "allowPersonalHotspotModification": True,
                "allowPhotoStream": True,
                "allowPredictiveKeyboard": True,
                "allowProximitySetupToNewDevice": True,
                "allowRadioService": True,
                "allowRemoteAppPairing": True,
                "allowRemoteScreenObservation": True,
                "allowSafari": True,
                "allowScreenShot": True,
                "allowSharedStream": True,
                "allowSpellCheck": True,
                "allowSpotlightInternetResults": True,
                "allowSystemAppRemoval": True,
                "allowUIAppInstallation": True,
                "allowUIConfigurationProfileInstallation": True,
                "allowUSBRestrictedMode": True,
                "allowUnpairedExternalBootToRecovery": False,
                "allowUntrustedTLSPrompt": True,
                "allowVPNCreation": True,
                "allowVideoConferencing": True,
                "allowVoiceDialing": True,
                "allowWallpaperModification": True,
                "allowiTunes": True,
                "enforcedSoftwareUpdateDelay": enforced_software_update_delay,
                "forceAirDropUnmanaged": False,
                "forceAirPrintTrustedTLSRequirement": False,
                "forceAssistantProfanityFilter": False,
                "forceAuthenticationBeforeAutoFill": False,
                "forceAutomaticDateAndTime": False,
                "forceClassroomAutomaticallyJoinClasses": False,
                "forceClassroomRequestPermissionToLeaveClasses": False,
                "forceClassroomUnpromptedAppAndDeviceLock": False,
                "forceClassroomUnpromptedScreenObservation": False,
                "forceDelayedSoftwareUpdates": True,
                "forceEncryptedBackup": False,
                "forceITunesStorePasswordEntry": False,
                "forceLimitAdTracking": False,
                "forceWatchWristDetection": False,
                "forceWiFiPowerOn": False,
                "forceWiFiWhitelisting": False,
                "ratingApps": 1000,
                "ratingMovies": 1000,
                "ratingRegion": "us",
                "ratingTVShows": 1000,
                "safariAcceptCookies": 2.0,
                "safariAllowAutoFill": True,
                "safariAllowJavaScript": True,
                "safariAllowPopups": True,
                "safariForceFraudWarning": False,
            },
            payload_uuid=payload_uuid,
            keybag_file=keybag_file,
        )
