import contextlib
import plistlib
from enum import Enum
from pathlib import Path
from typing import Any, Optional, cast
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder

from pymobiledevice3.exceptions import CloudConfigurationAlreadyPresentError, ConnectionTerminatedError, ProfileError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT = 14002
GLOBAL_HTTP_PROXY_UUID = "86a52338-52f7-4c09-b005-52baf3dc4882"
GLOBAL_RESTRICTIONS_UUID = "e22a0a66-08a8-43f5-9bbc-5279af35bb2b"


class Purpose(Enum):
    PostSetupInstallation = "PostSetupInstallation"


class MobileConfigService(LockdownService):
    """
    Manage configuration profiles and cloud (supervision) configuration.

    Wraps the ``com.apple.mobile.MCInstall`` lockdown service used by MDM/Apple
    Configurator. It can list, install and remove configuration profiles, drive
    supervision and cloud-configuration state, and erase the device. Some operations
    require supervised/silent installation, which is unlocked by `escalate` using a
    supervision identity (a PEM keybag holding both certificate and private key).

    Being a `LockdownService`, instances may be used as an async context manager::

        async with MobileConfigService(lockdown) as mc:
            profiles = await mc.get_profile_list()
    """

    SERVICE_NAME = "com.apple.mobile.MCInstall"
    RSD_SERVICE_NAME = "com.apple.mobile.MCInstall.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def hello(self) -> None:
        """Perform the ``HelloHostIdentifier`` handshake with the service."""
        await self._send_recv({"RequestType": "HelloHostIdentifier"})

    async def flush(self) -> None:
        """Issue a ``Flush`` request to the service."""
        await self._send_recv({"RequestType": "Flush"})

    async def escalate(self, keybag_file: Path) -> None:
        """
        Authenticate as a supervisor to unlock silent/supervised operations.

        Runs the ``Escalate`` challenge-response handshake using the supervision identity,
        then requests keybag migration. Must be called before silent profile installation.

        :param keybag_file: path to a PEM file containing both the supervisor certificate
            and its (unencrypted) private key.
        """
        with open(keybag_file, "rb") as f:
            keybag_data = f.read()
        private_key = serialization.load_pem_private_key(keybag_data, password=None)
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise ProfileError(f"unsupported supervision private key type: {type(private_key).__name__}")
        cer = x509.load_pem_x509_certificate(keybag_data)
        public_key = cer.public_bytes(Encoding.DER)
        escalate_response = await self._send_recv({"RequestType": "Escalate", "SupervisorCertificate": public_key})
        signed_challenge = (
            PKCS7SignatureBuilder()
            .set_data(escalate_response["Challenge"])
            .add_signer(cer, private_key, hashes.SHA256())
            .sign(Encoding.DER, [])
        )
        await self._send_recv({"RequestType": "EscalateResponse", "SignedRequest": signed_challenge})
        await self._send_recv({"RequestType": "ProceedWithKeybagMigration"})

    async def get_stored_profile(self, purpose: Purpose = Purpose.PostSetupInstallation) -> dict[str, Any]:
        """
        Retrieve a profile stored on the device for a given purpose.

        :param purpose: purpose the profile was stored under.
        :returns: the device's response plist.
        """
        return await self._send_recv({"RequestType": "GetStoredProfile", "Purpose": purpose.value})

    async def store_profile(self, profile_data: bytes, purpose: Purpose = Purpose.PostSetupInstallation) -> None:
        """
        Store a profile on the device for later use under a given purpose.

        :param profile_data: raw profile bytes to store.
        :param purpose: purpose to store the profile under.
        """
        await self._send_recv({"RequestType": "StoreProfile", "ProfileData": profile_data, "Purpose": purpose.value})

    async def get_cloud_configuration(self) -> Optional[dict[str, Any]]:
        """
        Retrieve the device's cloud (supervision) configuration.

        :returns: the ``CloudConfiguration`` dictionary, or None if not set.
        """
        return (await self._send_recv({"RequestType": "GetCloudConfiguration"})).get("CloudConfiguration")

    async def set_cloud_configuration(self, cloud_configuration: dict[str, Any]) -> None:
        """
        Set the device's cloud (supervision) configuration.

        :param cloud_configuration: cloud configuration dictionary to apply.
        """
        await self._send_recv({"RequestType": "SetCloudConfiguration", "CloudConfiguration": cloud_configuration})

    async def establish_provisional_enrollment(self, nonce: bytes) -> None:
        """
        Establish a provisional MDM enrollment.

        :param nonce: enrollment nonce.
        """
        await self._send_recv({"RequestType": "EstablishProvisionalEnrollment", "Nonce": nonce})

    async def set_wifi_power_state(self, state: bool) -> None:
        """
        Turn the device's Wi-Fi radio on or off.

        :param state: True to power Wi-Fi on, False to power it off.
        """
        await self._send_recv({"RequestType": "SetWiFiPowerState", "PowerState": state})

    async def erase_device(self, preserve_data_plan: bool, disallow_proximity_setup: bool) -> None:
        """
        Erase all content and settings from the device.

        The connection is normally terminated by the device as it begins erasing; that
        termination is suppressed so the call returns cleanly.

        :param preserve_data_plan: whether to preserve the cellular data plan across the erase.
        :param disallow_proximity_setup: whether to disallow proximity setup after the erase.
        """
        with contextlib.suppress(ConnectionTerminatedError):
            await self._send_recv({
                "RequestType": "EraseDevice",
                "PreserveDataPlan": preserve_data_plan,
                "DisallowProximitySetup": disallow_proximity_setup,
            })

    async def get_profile_list(self) -> dict[str, Any]:
        """
        List the configuration profiles installed on the device.

        :returns: the device's response plist (including ``ProfileMetadata`` keyed by
            profile identifier).
        """
        return await self._send_recv({"RequestType": "GetProfileList"})

    async def install_profile(self, payload: bytes) -> None:
        """
        Install a configuration profile, prompting the user for confirmation.

        :param payload: raw configuration profile bytes to install.
        """
        await self._send_recv({"RequestType": "InstallProfile", "Payload": payload})

    async def install_profile_silent(self, keybag_file: Path, profile: bytes) -> None:
        """
        Install a configuration profile silently, without user interaction.

        Escalates to supervisor privileges with the supervision identity, then installs
        the profile.

        :param keybag_file: path to a PEM file containing the supervisor certificate and
            its private key, used to escalate.
        :param profile: raw configuration profile bytes to install.
        """
        await self.escalate(keybag_file)
        await self._send_recv({"RequestType": "InstallProfileSilent", "Payload": profile})

    async def remove_profile(self, identifier: str) -> None:
        """
        Remove an installed configuration profile by its identifier.

        Looks up the profile's metadata in the installed profile list and, if present,
        sends a signed-free removal request. Does nothing if no profiles are installed or
        the identifier is not currently installed.

        :param identifier: payload identifier of the profile to remove.
        """
        profiles = await self.get_profile_list()
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
        await self._send_recv({"RequestType": "RemoveProfile", "ProfileIdentifier": data})

    async def _send_recv(self, request: dict[str, Any]) -> dict[str, Any]:
        response = await self.service.send_recv_plist(request)
        if response.get("Status", None) != "Acknowledged":
            error_chain = response.get("ErrorChain")
            if error_chain is not None:
                error_code = cast(list[dict[str, Any]], error_chain)[0]["ErrorCode"]
                if error_code == ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT:
                    raise CloudConfigurationAlreadyPresentError()
            raise ProfileError(f"invalid response {response}")
        return response

    async def install_wifi_profile(
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
        """
        Build and install a ``com.apple.wifi.managed`` profile for a Wi-Fi network.

        :param encryption_type: Wi-Fi encryption type (e.g. ``WPA``, ``WEP``, ``None``).
        :param ssid: network SSID.
        :param password: network password.
        :param auto_join: whether the device should automatically join the network.
        :param captive_bypass: whether to bypass the captive portal check.
        :param disable_association_mac_randomization: whether to disable MAC-address
            randomization when associating.
        :param hidden_network: whether the network is hidden (does not broadcast its SSID).
        :param is_hotspot: whether the network is treated as a personal hotspot.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
        payload_uuid = str(uuid4())
        await self.install_managed_profile(
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

    async def install_http_proxy(self, server: str, server_port: int, keybag_file: Optional[Path] = None) -> None:
        """
        Build and install a global manual HTTP-proxy profile.

        The profile uses the fixed `GLOBAL_HTTP_PROXY_UUID` so it can later be removed by
        `remove_http_proxy`.

        :param server: proxy server host.
        :param server_port: proxy server port.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
        payload_uuid = str(uuid4())
        await self.install_managed_profile(
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

    async def remove_http_proxy(self) -> None:
        """Remove the global HTTP-proxy profile previously installed by `install_http_proxy`."""
        await self.remove_profile(GLOBAL_HTTP_PROXY_UUID)

    async def supervise(self, organization: str, keybag_file: Path) -> None:
        """
        Place the device under supervision by writing a cloud configuration.

        Sets a supervised cloud configuration that names the organization, registers the
        supervisor certificate, and skips all setup-assistant panes.

        :param organization: organization name recorded in the cloud configuration.
        :param keybag_file: path to a PEM file containing the supervisor certificate whose
            DER public bytes are registered as a supervisor host certificate.
        """
        cer = x509.load_pem_x509_certificate(keybag_file.read_bytes())
        public_key = cer.public_bytes(Encoding.DER)
        await self.set_cloud_configuration({
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

    async def install_managed_profile(
        self,
        display_name: str,
        payload_content: dict[str, Any],
        payload_uuid: str = str(uuid4()),
        keybag_file: Optional[Path] = None,
    ) -> None:
        """
        Wrap a single payload in a ``Configuration`` profile and install it.

        :param display_name: profile display name.
        :param payload_content: the inner payload dictionary to wrap.
        :param payload_uuid: UUID used as both the profile identifier and UUID.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
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
            await self.install_profile_silent(keybag_file, profile_data)
        else:
            await self.install_profile(profile_data)

    async def install_restrictions_profile(
        self,
        enforced_software_update_delay: int = 0,
        payload_uuid: str = GLOBAL_RESTRICTIONS_UUID,
        keybag_file: Optional[Path] = None,
    ) -> None:
        """
        Build and install a ``com.apple.applicationaccess`` restrictions profile.

        The profile permits essentially every restricted capability; only the software
        update delay is parameterized.

        :param enforced_software_update_delay: number of days to delay visibility of
            software updates.
        :param payload_uuid: UUID used as the profile identifier and UUID.
        :param keybag_file: when provided, install silently using this supervision identity;
            otherwise install with a user prompt.
        """
        await self.install_managed_profile(
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
