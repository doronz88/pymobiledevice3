import os
import uuid
from collections import Counter
from enum import Enum
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Optional
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from parameter_decorators import str_to_path

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.lockdown_service import LockdownService

GET_APPS_ADDITIONAL_INFO = {"ReturnAttributes": ["CFBundleIdentifier", "StaticDiskUsage", "DynamicDiskUsage"]}

TEMP_REMOTE_BASEDIR = "/PublicStaging/pymobiledevice3"
APP_STORE_SIGNER_IDENTITIES = {"Apple iPhone OS Application Signing"}
APP_SUMMARY_KEYS = {
    "ApplicationType": "application_type",
    "CFBundleDisplayName": "display_name",
    "CFBundleIdentifier": "bundle_identifier",
    "CFBundleName": "name",
    "CFBundleShortVersionString": "short_version",
    "CFBundleVersion": "version",
    "DynamicDiskUsage": "dynamic_disk_usage",
    "HasSettingsBundle": "has_settings_bundle",
    "IsAppClip": "is_app_clip",
    "IsDemotedApp": "is_demoted",
    "IsPlaceholder": "is_placeholder",
    "IsUpgradeable": "is_upgradeable",
    "MinimumOSVersion": "minimum_os_version",
    "SequenceNumber": "sequence_number",
    "SignerIdentity": "signer_identity",
    "StaticDiskUsage": "static_disk_usage",
    "UIFileSharingEnabled": "file_sharing_enabled",
}
APP_PRIVACY_USAGE_KEYS = {
    "NSAppleMusicUsageDescription": "media_library",
    "NSBluetoothAlwaysUsageDescription": "bluetooth",
    "NSBluetoothPeripheralUsageDescription": "bluetooth",
    "NSCalendarsFullAccessUsageDescription": "calendar",
    "NSCalendarsUsageDescription": "calendar",
    "NSCalendarsWriteOnlyAccessUsageDescription": "calendar",
    "NSCameraUsageDescription": "camera",
    "NSContactsUsageDescription": "contacts",
    "NSFaceIDUsageDescription": "face_id",
    "NSHealthShareUsageDescription": "health",
    "NSHealthUpdateUsageDescription": "health",
    "NSHomeKitUsageDescription": "homekit",
    "NSLocalNetworkUsageDescription": "local_network",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "location",
    "NSLocationAlwaysUsageDescription": "location",
    "NSLocationUsageDescription": "location",
    "NSLocationWhenInUseUsageDescription": "location",
    "NSMicrophoneUsageDescription": "microphone",
    "NSMotionUsageDescription": "motion",
    "NSPhotoLibraryAddUsageDescription": "photos",
    "NSPhotoLibraryUsageDescription": "photos",
    "NSRemindersUsageDescription": "reminders",
    "NSSiriUsageDescription": "siri",
    "NSSpeechRecognitionUsageDescription": "speech_recognition",
}


class ZipFileType(Enum):
    IPCC = "ipcc"
    IPA = "ipa"

    def is_ipcc(self) -> bool:
        return self == ZipFileType.IPCC

    def is_ipa(self) -> bool:
        return self == ZipFileType.IPA


def create_ipa_contents_from_directory(directory: str) -> bytes:
    payload_prefix = "Payload/" + os.path.basename(directory)
    with TemporaryDirectory() as temp_dir:
        zip_path = Path(temp_dir) / "ipa"
        with ZipFile(zip_path, "w", ZIP_DEFLATED) as zip_file:
            for root, _dirs, files in os.walk(directory):
                for file in files:
                    full_path = Path(root) / file
                    full_path.touch()
                    zip_file.write(full_path, arcname=f"{payload_prefix}/{os.path.relpath(full_path, directory)}")
        return zip_path.read_bytes()


def classify_zip_file(zip_bytes: bytes) -> ZipFileType:
    """checks the zipped bytes if it's a .ipcc or .ipa"""
    try:
        with ZipFile(BytesIO(zip_bytes), "r") as zip_file:
            dirs = next((name for name in zip_file.namelist() if "/" in name), "").split("/")

            if dirs[0] != "Payload":
                raise AppInstallError("package does not have a payload")
            if dirs[1].endswith(".app"):
                return ZipFileType.IPA
            elif dirs[1].endswith(".bundle"):
                return ZipFileType.IPCC
            else:
                raise AppInstallError("package does not have the appropriate folders structure")

    except BadZipFile as e:
        raise AppInstallError("Invalid bytes package") from e


class InstallationProxyService(LockdownService):
    SERVICE_NAME = "com.apple.mobile.installation_proxy"
    RSD_SERVICE_NAME = "com.apple.mobile.installation_proxy.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def _watch_completion(self, handler: Optional[Callable] = None, *args) -> None:
        while True:
            response = await self.service.recv_plist()
            if not response:
                break
            error = response.get("Error")
            if error:
                raise AppInstallError(f"{error}: {response.get('ErrorDescription')}")
            completion = response.get("PercentComplete")
            if completion:
                if handler:
                    self.logger.debug("calling handler")
                    handler(completion, *args)
                self.logger.info(f"{completion}% Complete")
            if response.get("Status") == "Complete":
                self.logger.info("Installation succeed.")
                return
        raise AppInstallError()

    async def send_cmd_for_bundle_identifier(
        self,
        bundle_identifier: str,
        cmd: str = "Archive",
        options: Optional[dict] = None,
        handler: Optional[Callable] = None,
        *args,
    ) -> None:
        """
        Send a command associated with a specific bundle identifier to the service.

        This asynchronous method constructs a dictionary containing the given command
        and bundle identifier, then sends it to the service. Additional options and
        a handler routine can also be specified. The completion of the operation can
        be monitored using the provided completion handler.

        :param bundle_identifier: The application identifier associated with the command.
        :param cmd: The command name to execute. Defaults to "Archive".
        :param options: A dictionary of optional parameters for the command. Defaults to None.
        :param handler: Callable to handle the completion of the command. Defaults to None.
        :param args: Additional arguments to pass to the handler when monitoring completion.
        :return: None
        """
        cmd: dict = {"Command": cmd, "ApplicationIdentifier": bundle_identifier}

        if options is None:
            options = {}

        cmd.update({"ClientOptions": options})
        await self.service.send_plist(cmd)
        await self._watch_completion(handler, *args)

    async def upgrade(
        self, ipa_path: str, options: Optional[dict] = None, handler: Optional[Callable] = None, *args
    ) -> None:
        """
        Performs an asynchronous upgrade operation for the application using the specified installation
        package path and additional options, if provided. It invokes the internal method to handle
        the process locally while supporting optional handlers and arguments.

        :param ipa_path: The file path to the IPA installation package.
        :type ipa_path: str
        :param options: A dictionary containing optional configuration parameters for the
            upgrade process. This parameter is optional.
        :type options: Optional[dict]
        :param handler: A callable object or function that serves as a handler for managing
            notifications or updates during the upgrade process. This parameter is optional.
        :type handler: Optional[Callable]
        :param args: Variadic arguments that can hold additional data or configurations for
            the upgrade process.
        :return: This method does not return any value.
        :rtype: None
        """
        await self.install_from_local(ipa_path, "Upgrade", options, handler, args)

    async def restore(
        self, bundle_identifier: str, options: Optional[dict] = None, handler: Optional[Callable] = None, *args
    ) -> None:
        """
        Restores a specified bundle identified by its bundle identifier.

        This method sends a command to restore the associated bundle using the provided
        bundle identifier. Additional options, a custom handler, and extra arguments
        can be provided to customize the behavior during the restoration process.

        :param bundle_identifier: The unique identifier for the bundle to restore.
        :type bundle_identifier: str
        :param options: Optional dictionary containing additional options for the restore process.
        :type options: Optional[dict]
        :param handler: An optional callable function used to handle specific events or
            outcomes during the restore process.
        :type handler: Optional[Callable]
        :param args: Additional arguments to customize the restore behavior.
        :return: None
        :rtype: None
        """
        await self.send_cmd_for_bundle_identifier(bundle_identifier, "Restore", options, handler, args)

    async def uninstall(
        self, bundle_identifier: str, options: Optional[dict] = None, handler: Optional[Callable] = None, *args
    ) -> None:
        """
        Uninstalls an app identified by the given bundle identifier. This method sends a command
        to perform the uninstall operation and allows optional configuration settings, a custom
        handler, and additional arguments to modify the behavior of the operation.

        :param bundle_identifier: The unique string identifying the app to be uninstalled.
        :type bundle_identifier: str
        :param options: A dictionary of optional parameters to customize the uninstall operation.
            Defaults to None.
        :type options: Optional[dict]
        :param handler: A callable that can be used to handle events or responses during the
            uninstall process. Defaults to None.
        :type handler: Optional[Callable]
        :param args: Additional arguments that can be passed to extend the uninstall functionality.
            These arguments are optional.
        :return: This method does not return a value. It performs the uninstall operation
            asynchronously.
        :rtype: None
        """
        await self.send_cmd_for_bundle_identifier(bundle_identifier, "Uninstall", options, handler, args)

    async def install_from_bytes(
        self,
        package_bytes: bytes,
        cmd: str = "Install",
        options: Optional[dict] = None,
        handler: Optional[Callable] = None,
        *args,
    ) -> None:
        """
        Installs a package from raw byte data. This method handles both standard package
        types and carrier bundles (IPCC). It processes the package, stores it on the
        device temporarily, and initiates the installation using the specified command
        and options.

        :param package_bytes: The raw byte content of the package to be installed.
        :param cmd: The command to use for installation. Defaults to "Install".
        :param options: Configuration options as a dictionary for the installation
            process. Defaults to None.
        :param handler: An optional callable handler to manage specific installation
            callbacks. Defaults to None.
        :param args: Additional positional arguments passed during package installation.
        :return: None
        """
        ipcc_mode = classify_zip_file(package_bytes).is_ipcc()

        if options is None:
            options = {}

        if ipcc_mode:
            options["PackageType"] = "CarrierBundle"

        async with AfcService(self.lockdown) as afc:
            fpath = f"{TEMP_REMOTE_BASEDIR}/{uuid.uuid4()}.{'ipcc' if ipcc_mode else 'ipa'}"
            try:
                if not ipcc_mode:
                    await afc.makedirs(TEMP_REMOTE_BASEDIR)
                    await afc.set_file_contents(fpath, package_bytes)
                else:
                    await self.upload_ipcc_from_bytes(package_bytes, fpath, afc)

                await self.send_package(cmd, options, handler, fpath, *args)
            finally:
                await afc.rm_single(fpath, force=True)

    @str_to_path("package_path")
    async def install_from_local(
        self,
        package_path: Path,
        cmd: str = "Install",
        options: Optional[dict] = None,
        handler: Optional[Callable] = None,
        developer: bool = False,
        *args,
    ) -> None:
        """
        Install package from a local path in either `.ipa` or `.ipcc` format.

        This function handles the installation of an iOS package from a local path specified by
        `package_path`. It differentiates between `.ipa` (application archive) and `.ipcc`
        (carrier bundle) packages. If `package_path` is a directory, it assumes it is an app
        and converts it into a `.ipa` format. The function also accepts optional configuration
        options and a handler for processing.

        :param package_path: Path to the local package to be installed.
        :param cmd: The command to send for installation, default is "Install".
        :param options: Optional dictionary containing additional options for the installation process.
        :param handler: An optional callable to handle events during the installation process.
        :param developer: A boolean specifying if the package should be installed in developer mode.
        :param args: Additional arguments to be passed during the installation process.
        :return: None
        """
        ipcc_mode = package_path.suffix == ".ipcc"

        if options is None:
            options = {}

        if ipcc_mode:
            options["PackageType"] = "CarrierBundle"
        else:
            if package_path.is_dir():
                # treat as app, convert into an ipa
                ipa_contents = create_ipa_contents_from_directory(str(package_path))
            else:
                # treat as ipa
                ipa_contents = package_path.read_bytes()

        if developer:
            options["PackageType"] = "Developer"

        async with AfcService(self.lockdown) as afc:
            fname = f"{TEMP_REMOTE_BASEDIR}/{uuid.uuid4()}.{'ipcc' if ipcc_mode else 'ipa'}"
            try:
                if not ipcc_mode:
                    await afc.makedirs(TEMP_REMOTE_BASEDIR)
                    await afc.set_file_contents(fname, ipa_contents)

                else:
                    await self.upload_ipcc_from_path(package_path, fname, afc)

                await self.send_package(cmd, options, handler, fname, *args)
            finally:
                await afc.rm_single(fname, force=True)

    async def send_package(self, cmd: str, options: Optional[dict], handler: Callable, package_path: str, *args):
        """
        Asynchronously sends a package with specified command, options, and handler for monitoring its completion.

        The method prepares a payload containing the command, client options, and package path,
        then sends it using the `service.send_plist` function. After sending, it waits for the
        completion of the handler processing, which may involve additional arguments.

        :param cmd: Command to be executed on the service.
        :type cmd: str
        :param options: Dictionary containing client options to customize the command behavior.
        :type options: Optional[dict]
        :param handler: Callable function to handle the processing of the completion event.
        :type handler: Callable
        :param package_path: Path to the package that needs to be sent.
        :type package_path: str
        :param args: Additional arguments that are passed to the handler for processing.
        :type args: tuple
        :return: None
        :rtype: None
        """
        await self.service.send_plist({
            "Command": cmd,
            "ClientOptions": options,
            "PackagePath": package_path,
        })

        await self._watch_completion(handler, args)

    async def upload_ipcc_from_path(self, file: Path, remote_path: str, afc_client: AfcService) -> None:
        """
        Uploads an IPCC file from a given local path to a specified remote location using an AFC client.

        This function opens the specified file in binary read mode, logs the upload initiation process,
        and uploads the file contents to the remote path using the provided AFC client.

        :param file: A Path object representing the local file to be uploaded.
        :param remote_path: The destination path on the remote system where the file will be uploaded.
        :param afc_client: An instance of AfcService used to handle the upload process.
        :return: None
        """
        with file.open("rb") as fb:
            file_name = file.name
            file_stream = BytesIO(fb.read())
            self.logger.info(f"Uploading {file_name} contents..")
            await self._upload_ipcc(file_stream, afc_client, remote_path)

    async def upload_ipcc_from_bytes(self, file_bytes: bytes, remote_path: str, afc_client: AfcService) -> None:
        """
        Uploads an IPCC file to the specified remote path using the provided AFC client.

        This method takes the IPCC file bytes, creates an in-memory stream from them,
        and uploads the content to the remote path using the provided AFC client. It
        logs the process for informational purposes.

        :param file_bytes: The binary content of the IPCC file to be uploaded.
        :type file_bytes: bytes
        :param remote_path: The destination path where the IPCC file will be uploaded.
        :type remote_path: str
        :param afc_client: The AFC service client used to perform the upload operation.
        :type afc_client: AfcService
        :return: This method does not return a value.
        :rtype: None
        """
        file_stream = BytesIO(file_bytes)
        self.logger.info("Uploading IPCC from given bytes..")
        await self._upload_ipcc(file_stream, afc_client, remote_path)

    async def _upload_ipcc(self, file_stream: BytesIO, afc_client: AfcService, dst: str) -> None:
        self.logger.info(f"Uploading {dst} contents..")
        await afc_client.makedirs(dst)

        # we unpack it and upload it directly instead of saving it in a temp folder
        with ZipFile(file_stream, "r") as file_zip:
            for file_name in file_zip.namelist():
                if file_name.endswith(("/", "\\")):
                    await afc_client.makedirs(f"{dst}/{file_name}")
                    continue

                with file_zip.open(file_name) as inside_file_zip:
                    file_data = inside_file_zip.read()
                    await afc_client.makedirs(dst)
                    await afc_client.set_file_contents(f"{dst}/{file_name}", file_data)

        self.logger.info("Upload complete.")

    async def check_capabilities_match(
        self, capabilities: Optional[dict] = None, options: Optional[dict] = None
    ) -> dict:
        """
        Verifies if the given capabilities match the specified options by sending a
        command to a service and receiving a response indicating the result of the match.
        This is typically used for checking compatibility or suitability of a configuration.

        :param capabilities: Optional dictionary representing the desired capabilities to be
            checked for a match. If not provided, no specific capabilities will be checked.
        :type capabilities: Optional[dict]
        :param options: Optional dictionary specifying additional options for the match
            process. If not provided, defaults to an empty dictionary.
        :type options: Optional[dict]
        :return: Dictionary containing the result of the capabilities lookup, indicating if the
            match was successful or providing related information.
        :rtype: dict
        """
        if options is None:
            options = {}
        cmd = {"Command": "CheckCapabilitiesMatch", "ClientOptions": options}

        if capabilities:
            cmd["Capabilities"] = capabilities

        await self.service.send_plist(cmd)
        return (await self.service.recv_plist()).get("LookupResult")

    async def browse(self, options: Optional[dict] = None, attributes: Optional[list[str]] = None) -> list[dict]:
        """
        Asynchronously sends a browse command to a service, processes responses iteratively,
        and collects the resulting data into a list of dictionaries.

        This function allows querying a service with specified options and attributes to retrieve
        a browsable list of items. It handles communication with the service through command and
        response exchanges, gathering data until the process is completed.

        :param options:
            Optional dictionary representing client options for the browse command.
            Defaults to None if not provided.
        :param attributes:
            Optional list of strings representing specific attributes to be returned
            as part of the browse response. Defaults to None.
        :return:
            A list of dictionaries containing the collected browsable items retrieved
            from the service.
        """
        if options is None:
            options = {}
        if attributes:
            options["ReturnAttributes"] = attributes

        cmd = {"Command": "Browse", "ClientOptions": options}

        await self.service.send_plist(cmd)

        result = []
        while True:
            response = await self.service.recv_plist()
            if not response:
                break

            data = response.get("CurrentList")
            if data is not None:
                result += data

            if response.get("Status") == "Complete":
                break

        return result

    async def lookup(self, options: Optional[dict] = None) -> dict:
        """
        Perform an asynchronous lookup operation by sending the provided options to the service
        and retrieving the result.

        :param options: Optional dictionary specifying client options for the lookup process.
            If not provided, defaults to an empty dictionary.
        :return: A dictionary containing the 'LookupResult' extracted from the service's response.
        """
        if options is None:
            options = {}
        cmd = {"Command": "Lookup", "ClientOptions": options}
        await self.service.send_plist(cmd)
        return (await self.service.recv_plist()).get("LookupResult")

    async def get_apps(
        self,
        application_type: str = "Any",
        calculate_sizes: bool = False,
        bundle_identifiers: Optional[list[str]] = None,
        show_placeholders: bool = False,
    ) -> dict[str, dict]:
        """
        Retrieve application information based on specified criteria.

        This asynchronous method fetches details about applications installed or available
        on a system, based on provided filter options such as application type, bundle
        identifiers, and whether placeholders should be included. Additionally, it allows
        calculation of application sizes if requested.

        :param application_type: The type of applications to fetch. Defaults to "Any". Examples
            include "System" or "User".
        :param calculate_sizes: A flag indicating whether to calculate and include application
            size information. Defaults to False.
        :param bundle_identifiers: A list of specific bundle identifiers to filter the
            results. If None, all applications matching the other criteria are returned.
        :param show_placeholders: A flag indicating whether to include placeholder
            applications in the results. Defaults to False.
            See: <https://github.com/doronz88/pymobiledevice3/issues/1602> for details.
        :return: A dictionary where keys are bundle identifiers and values are nested
            dictionaries containing application details.
        """
        options = {}
        if bundle_identifiers is not None:
            options["BundleIDs"] = bundle_identifiers

        options["ApplicationType"] = application_type
        if show_placeholders:
            options["ShowPlaceholders"] = True
        result = await self.lookup(options)
        if calculate_sizes:
            options.update(GET_APPS_ADDITIONAL_INFO)
            additional_info = await self.lookup(options)
            for bundle_identifier, app in additional_info.items():
                result[bundle_identifier].update(app)
        return result

    async def get_apps_audit(
        self,
        application_type: str = "Any",
        calculate_sizes: bool = False,
        show_placeholders: bool = False,
    ) -> dict:
        return self.audit_apps(
            await self.get_apps(
                application_type=application_type,
                calculate_sizes=calculate_sizes,
                show_placeholders=show_placeholders,
            )
        )

    @classmethod
    def audit_apps(cls, apps: dict[str, dict]) -> dict:
        application_type_counts: Counter[str] = Counter()
        background_mode_counts: Counter[str] = Counter()
        privacy_usage_counts: Counter[str] = Counter()
        signer_identity_counts: Counter[str] = Counter()
        findings = []
        summaries = []
        flags = {
            "has_app_clips": False,
            "has_beta_apps": False,
            "has_debuggable_apps": False,
            "has_demoted_apps": False,
            "has_file_sharing_enabled_apps": False,
            "has_non_app_store_user_apps": False,
            "has_placeholder_apps": False,
            "has_user_apps": False,
        }

        for fallback_bundle_identifier, app in sorted(apps.items()):
            summary = cls._app_summary(fallback_bundle_identifier, app)
            application_type = summary.get("application_type", "<missing>")
            application_type_counts[application_type] += 1
            flags["has_user_apps"] = flags["has_user_apps"] or application_type == "User"

            signer_identity = summary.get("signer_identity")
            if signer_identity is not None:
                signer_identity_counts[signer_identity] += 1

            background_modes = cls._string_list(app.get("UIBackgroundModes"))
            if background_modes:
                summary["background_modes"] = sorted(background_modes)
                background_mode_counts.update(background_modes)

            privacy_usages = sorted({category for key, category in APP_PRIVACY_USAGE_KEYS.items() if key in app})
            if privacy_usages:
                summary["privacy_usage_descriptions"] = privacy_usages
                privacy_usage_counts.update(privacy_usages)

            url_scheme_count = cls._url_scheme_count(app)
            if url_scheme_count:
                summary["url_scheme_count"] = url_scheme_count

            entitlement_summary = cls._entitlement_summary(app.get("Entitlements"))
            if entitlement_summary:
                summary["entitlements"] = entitlement_summary

            bundle_identifier = summary["bundle_identifier"]
            if cls._is_true(app.get("IsPlaceholder")):
                flags["has_placeholder_apps"] = True
                findings.append(cls._finding("placeholder", "medium", bundle_identifier, application_type))
            if cls._is_true(app.get("IsDemotedApp")):
                flags["has_demoted_apps"] = True
                findings.append(cls._finding("demoted", "low", bundle_identifier, application_type))
            if cls._is_true(app.get("IsAppClip")):
                flags["has_app_clips"] = True
                findings.append(cls._finding("app_clip", "low", bundle_identifier, application_type))
            if cls._is_true(app.get("UIFileSharingEnabled")):
                flags["has_file_sharing_enabled_apps"] = True
                findings.append(cls._finding("file_sharing_enabled", "low", bundle_identifier, application_type))
            if cls._is_beta_app(app):
                flags["has_beta_apps"] = True
                findings.append(cls._finding("beta", "medium", bundle_identifier, application_type))
            if cls._is_debuggable(app):
                flags["has_debuggable_apps"] = True
                findings.append(cls._finding("debuggable", "high", bundle_identifier, application_type))
            if cls._is_non_app_store_user_app(summary):
                flags["has_non_app_store_user_apps"] = True
                findings.append(cls._finding("non_app_store_signer", "medium", bundle_identifier, application_type))

            summaries.append(summary)

        return {
            "app_count": len(summaries),
            "application_types": dict(sorted(application_type_counts.items())),
            "background_modes": dict(sorted(background_mode_counts.items())),
            "findings": findings,
            "flags": flags,
            "privacy_usage_descriptions": dict(sorted(privacy_usage_counts.items())),
            "signer_identities": dict(sorted(signer_identity_counts.items())),
            "apps": summaries,
        }

    @staticmethod
    def _app_summary(fallback_bundle_identifier: str, app: dict) -> dict:
        summary = {
            output_key: app[source_key] for source_key, output_key in APP_SUMMARY_KEYS.items() if source_key in app
        }
        summary.setdefault("bundle_identifier", fallback_bundle_identifier)
        return summary

    @staticmethod
    def _entitlement_summary(entitlements: Any) -> dict:
        if not isinstance(entitlements, dict):
            return {}

        summary = {}
        application_groups = InstallationProxyService._string_list(
            entitlements.get("com.apple.security.application-groups")
        )
        associated_domains = InstallationProxyService._string_list(
            entitlements.get("com.apple.developer.associated-domains")
        )
        keychain_access_groups = InstallationProxyService._string_list(entitlements.get("keychain-access-groups"))
        if application_groups:
            summary["application_group_count"] = len(application_groups)
        if associated_domains:
            summary["associated_domain_count"] = len(associated_domains)
        if keychain_access_groups:
            summary["keychain_access_group_count"] = len(keychain_access_groups)
        if "aps-environment" in entitlements:
            summary["has_aps_environment"] = True
        if InstallationProxyService._is_true(entitlements.get("beta-reports-active")):
            summary["beta_reports_active"] = True
        if InstallationProxyService._is_true(entitlements.get("get-task-allow")):
            summary["get_task_allow"] = True
        return summary

    @staticmethod
    def _finding(category: str, severity: str, bundle_identifier: str, application_type: str) -> dict:
        return {
            "application_type": application_type,
            "bundle_identifier": bundle_identifier,
            "category": category,
            "severity": severity,
        }

    @staticmethod
    def _is_true(value: Any) -> bool:
        if isinstance(value, str):
            return value.lower() == "true"
        return value is True

    @staticmethod
    def _is_beta_app(app: dict) -> bool:
        entitlements = app.get("Entitlements")
        beta_reports_active = isinstance(entitlements, dict) and InstallationProxyService._is_true(
            entitlements.get("beta-reports-active")
        )
        return (
            InstallationProxyService._is_true(app.get("BetaApp"))
            or InstallationProxyService._is_true(app.get("IsBetaApp"))
            or beta_reports_active
        )

    @staticmethod
    def _is_debuggable(app: dict) -> bool:
        entitlements = app.get("Entitlements")
        return isinstance(entitlements, dict) and InstallationProxyService._is_true(entitlements.get("get-task-allow"))

    @staticmethod
    def _is_non_app_store_user_app(summary: dict) -> bool:
        return (
            summary.get("application_type") == "User"
            and summary.get("signer_identity") is not None
            and summary["signer_identity"] not in APP_STORE_SIGNER_IDENTITIES
        )

    @staticmethod
    def _url_scheme_count(app: dict) -> int:
        count = 0
        for url_type in app.get("CFBundleURLTypes") or ():
            if not isinstance(url_type, dict):
                continue
            count += len(InstallationProxyService._string_list(url_type.get("CFBundleURLSchemes")))
        return count

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]
