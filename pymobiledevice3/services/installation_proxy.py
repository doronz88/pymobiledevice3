import os
import uuid
from enum import Enum
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, cast
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

if TYPE_CHECKING:
    _F = TypeVar("_F", bound=Callable[..., Any])

    def str_to_path(*params: str, reannotate: bool = True) -> Callable[[_F], _F]: ...

else:
    from parameter_decorators import str_to_path

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.plist_types import PlistSendable
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.lockdown_service import LockdownService

GET_APPS_ADDITIONAL_INFO = {"ReturnAttributes": ["CFBundleIdentifier", "StaticDiskUsage", "DynamicDiskUsage"]}

TEMP_REMOTE_BASEDIR = "/PublicStaging/pymobiledevice3"


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
    """
    Client for the ``com.apple.mobile.installation_proxy`` lockdown service.

    Provides access to the device's application installation database: installing,
    upgrading, uninstalling, archiving/restoring, browsing and looking up apps, as well
    as uploading carrier bundles (IPCC). Most operations send a plist command over the
    service connection and stream back progress and status responses.
    """

    SERVICE_NAME = "com.apple.mobile.installation_proxy"
    RSD_SERVICE_NAME = "com.apple.mobile.installation_proxy.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def _watch_completion(self, handler: Optional[Callable[..., Any]] = None, *args: Any) -> None:
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
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Send a command that targets an installed app by its bundle identifier and wait for completion.

        Sends a plist of the form ``{"Command": cmd, "ApplicationIdentifier": bundle_identifier,
        "ClientOptions": options}`` to the service, then consumes progress/status responses until
        the operation completes. Used to back `restore` and `uninstall`.

        :param bundle_identifier: Bundle identifier of the target app, sent as ``ApplicationIdentifier``.
        :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Archive"``.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the service reports an error or finishes without a ``Complete`` status.
        """
        request: dict[str, Any] = {"Command": cmd, "ApplicationIdentifier": bundle_identifier}

        if options is None:
            options = {}

        request.update({"ClientOptions": options})
        await self.service.send_plist(request)
        await self._watch_completion(handler, *args)

    async def upgrade(
        self,
        ipa_path: str,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Upgrade an installed app from a local package.

        Delegates to `install_from_local` with the ``"Upgrade"`` command.

        :param ipa_path: Local path to the package (``.ipa``/``.ipcc`` or an app directory).
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the upgrade fails.
        """
        await self.install_from_local(Path(ipa_path), "Upgrade", options, handler, False, *args)

    async def restore(
        self,
        bundle_identifier: str,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Restore a previously archived app, identified by its bundle identifier.

        Sends the ``"Restore"`` command via `send_cmd_for_bundle_identifier`.

        :param bundle_identifier: Bundle identifier of the app to restore.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the restore fails.
        """
        await self.send_cmd_for_bundle_identifier(bundle_identifier, "Restore", options, handler, args)

    async def uninstall(
        self,
        bundle_identifier: str,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Uninstall an app, identified by its bundle identifier.

        Sends the ``"Uninstall"`` command via `send_cmd_for_bundle_identifier`.

        :param bundle_identifier: Bundle identifier of the app to uninstall.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the uninstall fails.
        """
        await self.send_cmd_for_bundle_identifier(bundle_identifier, "Uninstall", options, handler, args)

    async def install_from_bytes(
        self,
        package_bytes: bytes,
        cmd: str = "Install",
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Install an app or carrier bundle from a zipped package held in memory.

        The package type is detected from the zip contents (see `classify_zip_file`): a
        ``.app`` payload is treated as an ``.ipa``, a ``.bundle`` payload as an ``.ipcc``. For
        IPCC packages, ``PackageType`` is forced to ``"CarrierBundle"`` in the options. The bytes
        are uploaded to a temporary path under ``/PublicStaging/pymobiledevice3`` via AFC, the
        command is dispatched with `send_package`, and the temporary file is removed
        afterwards.

        :param package_bytes: Raw bytes of the ``.ipa``/``.ipcc`` zip package.
        :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Install"``.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the bytes are not a valid package, lack a ``Payload`` directory,
            or if the installation fails.
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
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        developer: bool = False,
        *args: Any,
    ) -> None:
        """
        Install an app or carrier bundle from a local path.

        Dispatches on ``package_path``: a ``.ipcc`` suffix is treated as a carrier bundle
        (``PackageType`` forced to ``"CarrierBundle"``); a directory is treated as an unpackaged
        app and zipped into an ``.ipa`` via `create_ipa_contents_from_directory`; any other
        path is read as ``.ipa`` bytes. When ``developer`` is set, ``PackageType`` is forced to
        ``"Developer"``. The payload is uploaded to a temporary path under
        ``/PublicStaging/pymobiledevice3`` via AFC, the command is dispatched with
        `send_package`, and the temporary file is removed afterwards.

        :param package_path: Local path to a ``.ipa`` file, a ``.ipcc`` file, or an app directory.
            String values are coerced to `Path`.
        :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Install"``.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param developer: When ``True``, sets ``PackageType`` to ``"Developer"`` in the options.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the installation fails.
        """
        ipcc_mode = package_path.suffix == ".ipcc"

        if options is None:
            options = {}

        ipa_contents = b""
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

    async def send_package(
        self,
        cmd: str,
        options: Optional[dict[str, Any]],
        handler: Optional[Callable[..., Any]],
        package_path: str,
        *args: Any,
    ):
        """
        Send an install/upgrade command for a package already staged on the device, and wait for completion.

        Sends ``{"Command": cmd, "ClientOptions": options, "PackagePath": package_path}`` to the
        service, then consumes progress/status responses until the operation completes. Typically
        invoked by `install_from_local` and `install_from_bytes` after uploading the
        package via AFC.

        :param cmd: Installation-proxy command name, sent as ``Command``.
        :param options: Command options, sent as ``ClientOptions``.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param package_path: On-device path to the staged package, sent as ``PackagePath``.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the service reports an error or finishes without a ``Complete`` status.
        """
        await self.service.send_plist(
            cast(
                PlistSendable,
                {
                    "Command": cmd,
                    "ClientOptions": options,
                    "PackagePath": package_path,
                },
            )
        )

        await self._watch_completion(handler, args)

    async def upload_ipcc_from_path(self, file: Path, remote_path: str, afc_client: AfcService) -> None:
        """
        Upload a local IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

        Reads the file into memory and forwards it to the unpacking uploader, which recreates the
        zip's directory tree under ``remote_path`` on the device via the given AFC client.

        :param file: Local path to the ``.ipcc`` zip file.
        :param remote_path: Destination directory on the device where the bundle is unpacked.
        :param afc_client: Connected `AfcService` used to write
            the files.
        :returns: None.
        """
        with file.open("rb") as fb:
            file_name = file.name
            file_stream = BytesIO(fb.read())
            self.logger.info(f"Uploading {file_name} contents..")
            await self._upload_ipcc(file_stream, afc_client, remote_path)

    async def upload_ipcc_from_bytes(self, file_bytes: bytes, remote_path: str, afc_client: AfcService) -> None:
        """
        Upload an in-memory IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

        Wraps the bytes in a stream and forwards them to the unpacking uploader, which recreates the
        zip's directory tree under ``remote_path`` on the device via the given AFC client.

        :param file_bytes: Raw bytes of the ``.ipcc`` zip.
        :param remote_path: Destination directory on the device where the bundle is unpacked.
        :param afc_client: Connected `AfcService` used to write
            the files.
        :returns: None.
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
        self, capabilities: Optional[dict[str, Any]] = None, options: Optional[dict[str, Any]] = None
    ) -> Optional[dict[str, Any]]:
        """
        Ask the device whether it satisfies a set of app capabilities.

        Sends the ``"CheckCapabilitiesMatch"`` command. When ``capabilities`` is provided it is
        sent under the ``Capabilities`` key; otherwise no capabilities key is sent. Returns the
        single ``LookupResult`` value from the response.

        :param capabilities: Capabilities to check, sent as ``Capabilities``. If falsy, the key is
            omitted.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :returns: The ``LookupResult`` value from the response describing the matched capabilities,
            or ``None`` if absent.
        """
        if options is None:
            options = {}
        cmd: dict[str, Any] = {"Command": "CheckCapabilitiesMatch", "ClientOptions": options}

        if capabilities:
            cmd["Capabilities"] = capabilities

        await self.service.send_plist(cmd)
        return cast(Optional[dict[str, Any]], (await self.service.recv_plist()).get("LookupResult"))

    async def browse(
        self, options: Optional[dict[str, Any]] = None, attributes: Optional[list[str]] = None
    ) -> list[dict[str, Any]]:
        """
        Enumerate installed apps via the ``"Browse"`` command.

        Sends the command and accumulates each response's ``CurrentList`` entries until the service
        reports a ``Complete`` status (or returns an empty response).

        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param attributes: When provided, set as the ``ReturnAttributes`` option to limit which
            per-app attributes are returned.
        :returns: A list of per-app info dictionaries collected from all ``CurrentList`` responses.
        """
        if options is None:
            options = {}
        if attributes:
            options["ReturnAttributes"] = attributes

        cmd: dict[str, Any] = {"Command": "Browse", "ClientOptions": options}

        await self.service.send_plist(cmd)

        result: list[dict[str, Any]] = []
        while True:
            response = await self.service.recv_plist()
            if not response:
                break

            data = response.get("CurrentList")
            if data is not None:
                result += cast(list[dict[str, Any]], data)

            if response.get("Status") == "Complete":
                break

        return result

    async def lookup(self, options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
        """
        Look up installed apps via the ``"Lookup"`` command.

        Sends the command and returns the single ``LookupResult`` value from the response. The
        options dict (e.g. ``BundleIDs``, ``ApplicationType``, ``ReturnAttributes``) determines
        which apps and attributes are returned.

        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :returns: The ``LookupResult`` mapping bundle identifiers to per-app info dictionaries, or
            ``None`` if absent.
        """
        if options is None:
            options = {}
        cmd: dict[str, Any] = {"Command": "Lookup", "ClientOptions": options}
        await self.service.send_plist(cmd)
        return cast(Optional[dict[str, Any]], (await self.service.recv_plist()).get("LookupResult"))

    async def get_apps(
        self,
        application_type: str = "Any",
        calculate_sizes: bool = False,
        bundle_identifiers: Optional[list[str]] = None,
        show_placeholders: bool = False,
    ) -> dict[str, dict[str, Any]]:
        """
        Retrieve installed apps, keyed by bundle identifier.

        Builds a lookup query from the given filters and calls `lookup`. When
        ``calculate_sizes`` is set, a second lookup is issued requesting ``CFBundleIdentifier``,
        ``StaticDiskUsage`` and ``DynamicDiskUsage``, and those size attributes are merged into the
        per-app entries.

        :param application_type: Value for the ``ApplicationType`` option. Defaults to ``"Any"``;
            other values include ``"System"`` and ``"User"``.
        :param calculate_sizes: When ``True``, also fetch and merge static/dynamic disk usage for
            each app.
        :param bundle_identifiers: When provided, restrict the query to these bundle identifiers via
            the ``BundleIDs`` option.
        :param show_placeholders: When ``True``, set the ``ShowPlaceholders`` option to include
            placeholder (e.g. installing/downloading) apps.
            See <https://github.com/doronz88/pymobiledevice3/issues/1602> for details.
        :returns: A dictionary mapping each bundle identifier to its per-app info dictionary.
        """
        options: dict[str, Any] = {}
        if bundle_identifiers is not None:
            options["BundleIDs"] = bundle_identifiers

        options["ApplicationType"] = application_type
        if show_placeholders:
            options["ShowPlaceholders"] = True
        result = await self.lookup(options)
        if result is None:
            raise AppInstallError("Lookup response is missing LookupResult")
        if calculate_sizes:
            options.update(GET_APPS_ADDITIONAL_INFO)
            additional_info = await self.lookup(options)
            if additional_info is None:
                raise AppInstallError("Lookup response is missing LookupResult")
            for bundle_identifier, app in additional_info.items():
                result[bundle_identifier].update(app)
        return result
