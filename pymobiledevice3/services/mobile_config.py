import contextlib
import plistlib
from collections import Counter
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder

from pymobiledevice3.exceptions import CloudConfigurationAlreadyPresentError, ConnectionTerminatedError, ProfileError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

ERROR_CLOUD_CONFIGURATION_ALREADY_PRESENT = 14002
GLOBAL_HTTP_PROXY_UUID = "86a52338-52f7-4c09-b005-52baf3dc4882"
GLOBAL_RESTRICTIONS_UUID = "e22a0a66-08a8-43f5-9bbc-5279af35bb2b"
CERTIFICATE_PAYLOAD_TYPES = {
    "com.apple.security.acme",
    "com.apple.security.certificatepreference",
    "com.apple.security.identitypreference",
    "com.apple.security.pem",
    "com.apple.security.pkcs1",
    "com.apple.security.pkcs12",
    "com.apple.security.root",
    "com.apple.security.scep",
}
ROOT_CERTIFICATE_PAYLOAD_TYPES = {"com.apple.security.root"}
NON_ROOT_CERTIFICATE_PAYLOAD_TYPES = CERTIFICATE_PAYLOAD_TYPES - ROOT_CERTIFICATE_PAYLOAD_TYPES
VPN_PAYLOAD_TYPES = {
    "com.apple.vpn.managed",
    "com.apple.vpn.managed.applayer",
}
AUDIT_PAYLOAD_RULES = (
    ("mdm", "high", "has_mdm", {"com.apple.mdm"}),
    ("global_http_proxy", "high", "has_global_http_proxy", {"com.apple.proxy.http.global"}),
    ("vpn", "medium", "has_vpn", VPN_PAYLOAD_TYPES),
    ("root_certificate", "medium", "has_root_certificates", ROOT_CERTIFICATE_PAYLOAD_TYPES),
    ("certificate", "medium", "has_certificates", NON_ROOT_CERTIFICATE_PAYLOAD_TYPES),
    ("web_content_filter", "medium", "has_web_content_filter", {"com.apple.webcontent-filter"}),
    ("dns_settings", "medium", "has_dns_settings", {"com.apple.dnsProxy.managed", "com.apple.dnsSettings.managed"}),
    ("wifi", "low", "has_wifi", {"com.apple.wifi.managed"}),
    ("restrictions", "low", "has_restrictions", {"com.apple.applicationaccess"}),
)
AUDIT_FLAG_NAMES = (
    *(rule[2] for rule in AUDIT_PAYLOAD_RULES),
    "has_removal_disallowed_profiles",
)
PROFILE_SUMMARY_KEYS = {
    "IsEncrypted": "is_encrypted",
    "PayloadDisplayName": "display_name",
    "PayloadExpirationDate": "expiration_date",
    "PayloadIdentifier": "identifier",
    "PayloadOrganization": "organization",
    "PayloadRemovalDate": "removal_date",
    "PayloadRemovalDisallowed": "removal_disallowed",
    "PayloadUUID": "uuid",
    "PayloadVersion": "version",
}
PAYLOAD_SUMMARY_KEYS = {
    "PayloadDisplayName": "display_name",
    "PayloadIdentifier": "identifier",
    "PayloadType": "type",
    "PayloadUUID": "uuid",
    "PayloadVersion": "version",
}


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

    async def hello(self) -> None:
        await self._send_recv({"RequestType": "HelloHostIdentifier"})

    async def flush(self) -> None:
        await self._send_recv({"RequestType": "Flush"})

    async def escalate(self, keybag_file: Path) -> None:
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
        escalate_response = await self._send_recv({"RequestType": "Escalate", "SupervisorCertificate": public_key})
        signed_challenge = (
            PKCS7SignatureBuilder()
            .set_data(escalate_response["Challenge"])
            .add_signer(cer, private_key, hashes.SHA256())
            .sign(Encoding.DER, [])
        )
        await self._send_recv({"RequestType": "EscalateResponse", "SignedRequest": signed_challenge})
        await self._send_recv({"RequestType": "ProceedWithKeybagMigration"})

    async def get_stored_profile(self, purpose: Purpose = Purpose.PostSetupInstallation) -> dict:
        return await self._send_recv({"RequestType": "GetStoredProfile", "Purpose": purpose.value})

    async def store_profile(self, profile_data: bytes, purpose: Purpose = Purpose.PostSetupInstallation) -> None:
        await self._send_recv({"RequestType": "StoreProfile", "ProfileData": profile_data, "Purpose": purpose.value})

    async def get_cloud_configuration(self) -> dict:
        return (await self._send_recv({"RequestType": "GetCloudConfiguration"})).get("CloudConfiguration")

    async def set_cloud_configuration(self, cloud_configuration: dict) -> None:
        await self._send_recv({"RequestType": "SetCloudConfiguration", "CloudConfiguration": cloud_configuration})

    async def establish_provisional_enrollment(self, nonce: bytes) -> None:
        await self._send_recv({"RequestType": "EstablishProvisionalEnrollment", "Nonce": nonce})

    async def set_wifi_power_state(self, state: bool) -> None:
        await self._send_recv({"RequestType": "SetWiFiPowerState", "PowerState": state})

    async def erase_device(self, preserve_data_plan: bool, disallow_proximity_setup: bool) -> None:
        with contextlib.suppress(ConnectionTerminatedError):
            await self._send_recv({
                "RequestType": "EraseDevice",
                "PreserveDataPlan": preserve_data_plan,
                "DisallowProximitySetup": disallow_proximity_setup,
            })

    async def get_profile_list(self) -> dict:
        return await self._send_recv({"RequestType": "GetProfileList"})

    async def get_profile_audit(self) -> dict:
        return self.audit_profile_list(await self.get_profile_list())

    @classmethod
    def audit_profile_list(cls, profile_list: dict) -> dict:
        profile_metadata = profile_list.get("ProfileMetadata") or {}
        profile_manifest = profile_list.get("ProfileManifest") or {}
        ordered_identifiers = profile_list.get("OrderedIdentifiers") or []
        unordered_identifiers = sorted((set(profile_metadata) | set(profile_manifest)) - set(ordered_identifiers))
        identifiers = list(
            dict.fromkeys([
                *ordered_identifiers,
                *unordered_identifiers,
            ])
        )

        profiles = []
        payload_type_counts: Counter[str] = Counter()
        findings = []
        flags = dict.fromkeys(AUDIT_FLAG_NAMES, False)

        for fallback_identifier in identifiers:
            metadata = profile_metadata.get(fallback_identifier) or {}
            manifest = profile_manifest.get(fallback_identifier) or {}
            payloads = list(cls._iter_profile_payloads(metadata)) or list(cls._iter_profile_payloads(manifest))
            payload_summaries = [cls._payload_summary(payload) for payload in payloads]
            payload_types = sorted({
                payload_summary["type"] for payload_summary in payload_summaries if payload_summary.get("type")
            })

            summary = {
                "identifier": metadata.get("PayloadIdentifier") or fallback_identifier,
                "payload_count": len(payload_summaries),
                "payload_types": payload_types,
                "payloads": payload_summaries,
            }
            for source_key, output_key in PROFILE_SUMMARY_KEYS.items():
                if source_key in metadata and output_key != "identifier":
                    summary[output_key] = metadata[source_key]

            flags["has_removal_disallowed_profiles"] = (
                flags["has_removal_disallowed_profiles"] or summary.get("removal_disallowed") is True
            )

            for payload_summary in payload_summaries:
                payload_type = payload_summary.get("type")
                if payload_type is not None:
                    payload_type_counts[payload_type] += 1
                if payload_type in CERTIFICATE_PAYLOAD_TYPES:
                    flags["has_certificates"] = True

                for category, severity, flag_name, payload_types_to_flag in AUDIT_PAYLOAD_RULES:
                    if payload_type not in payload_types_to_flag:
                        continue
                    flags[flag_name] = True
                    findings.append({
                        "category": category,
                        "payload_display_name": payload_summary.get("display_name"),
                        "payload_identifier": payload_summary.get("identifier"),
                        "payload_type": payload_type,
                        "profile_identifier": summary["identifier"],
                        "severity": severity,
                    })

            profiles.append(summary)

        return {
            "findings": findings,
            "flags": flags,
            "payload_count": sum(payload_type_counts.values()),
            "payload_types": dict(sorted(payload_type_counts.items())),
            "profile_count": len(profiles),
            "profiles": profiles,
        }

    @classmethod
    def _iter_profile_payloads(cls, value: Any):
        if isinstance(value, list):
            for item in value:
                yield from cls._iter_profile_payloads(item)
            return

        if not isinstance(value, dict):
            return

        payload_type = value.get("PayloadType")
        if payload_type is not None and payload_type != "Configuration":
            yield value

        for child_key in ("PayloadContent", "PayloadItems"):
            yield from cls._iter_profile_payloads(value.get(child_key))

    @staticmethod
    def _payload_summary(payload: dict) -> dict:
        return {
            output_key: payload[source_key]
            for source_key, output_key in PAYLOAD_SUMMARY_KEYS.items()
            if source_key in payload
        }

    async def install_profile(self, payload: bytes) -> None:
        await self._send_recv({"RequestType": "InstallProfile", "Payload": payload})

    async def install_profile_silent(self, keybag_file: Path, profile: bytes) -> None:
        await self.escalate(keybag_file)
        await self._send_recv({"RequestType": "InstallProfileSilent", "Payload": profile})

    async def remove_profile(self, identifier: str) -> None:
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

    async def _send_recv(self, request: dict) -> dict:
        response = await self.service.send_recv_plist(request)
        if response.get("Status", None) != "Acknowledged":
            error_chain = response.get("ErrorChain")
            if error_chain is not None:
                error_code = error_chain[0]["ErrorCode"]
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
        await self.remove_profile(GLOBAL_HTTP_PROXY_UUID)

    async def supervise(self, organization: str, keybag_file: Path) -> None:
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
