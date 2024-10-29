import os
from enum import Enum
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Optional
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from parameter_decorators import str_to_path

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.lockdown_service import LockdownService

GET_APPS_ADDITIONAL_INFO = {'ReturnAttributes': ['CFBundleIdentifier', 'StaticDiskUsage', 'DynamicDiskUsage']}

TEMP_REMOTE_BASEDIR = '/PublicStaging'
TEMP_REMOTE_IPA_FILE = f'{TEMP_REMOTE_BASEDIR}/pymobiledevice3.ipa'
TEMP_REMOTE_IPCC_FOLDER = f'{TEMP_REMOTE_BASEDIR}/pymobiledevice3.ipcc'


class ZipFileType(Enum):
    IPCC = 'ipcc'
    IPA = 'ipa'

    def is_ipcc(self) -> bool:
        return self == ZipFileType.IPCC

    def is_ipa(self) -> bool:
        return self == ZipFileType.IPA


def create_ipa_contents_from_directory(directory: str) -> bytes:
    payload_prefix = 'Payload/' + os.path.basename(directory)
    with TemporaryDirectory() as temp_dir:
        zip_path = Path(temp_dir) / 'ipa'
        with ZipFile(zip_path, 'w', ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    full_path = Path(root) / file
                    full_path.touch()
                    zip_file.write(full_path,
                                   arcname=f'{payload_prefix}/{os.path.relpath(full_path, directory)}')
        return zip_path.read_bytes()


def classify_zip_file(zip_bytes: bytes) -> ZipFileType:
    """ checks the zipped bytes if it's a .ipcc or .ipa """
    try:
        with ZipFile(BytesIO(zip_bytes), 'r') as zip_file:
            # sometimes packages at first index don't have enough infos to check
            dirs = zip_file.namelist()[1].split('/')

            if dirs[0] != 'Payload':
                raise AppInstallError('package does not have a payload')
            if dirs[1].endswith('.app'):
                return ZipFileType.IPA
            elif dirs[1].endswith('.bundle'):
                return ZipFileType.IPCC
            else:
                raise AppInstallError('package does not have the appropriate folders structure')

    except BadZipFile:
        raise AppInstallError('invalid bytes package')


class InstallationProxyService(LockdownService):
    SERVICE_NAME = 'com.apple.mobile.installation_proxy'
    RSD_SERVICE_NAME = 'com.apple.mobile.installation_proxy.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def _watch_completion(self, handler: Callable = None, ipcc: bool = False, *args) -> None:
        while True:
            response = self.service.recv_plist()
            if not response:
                break
            error = response.get('Error')
            if error:
                raise AppInstallError(f'{error}: {response.get("ErrorDescription")}')
            completion = response.get('PercentComplete')
            if completion:
                if handler:
                    self.logger.debug('calling handler')
                    handler(completion, *args)
                self.logger.info(f'{response.get("PercentComplete")}% Complete')
            if response.get('Status') == 'Complete':
                if ipcc:
                    # there is no progress when installing a .ipcc file,
                    # so we just put a simple message indicating it's done
                    self.logger.info('Installation succeed.')
                return
        raise AppInstallError()

    def send_cmd_for_bundle_identifier(self, bundle_identifier: str, cmd: str = 'Archive',
                                       options: Optional[dict] = None,
                                       handler: Optional[dict] = None, *args) -> None:
        """ send a low-level command to installation relay """
        cmd = {'Command': cmd,
               'ApplicationIdentifier': bundle_identifier}

        if options is None:
            options = {}

        cmd.update({'ClientOptions': options})
        self.service.send_plist(cmd)
        self._watch_completion(handler, *args)

    def install(self, package_path: str, options: Optional[dict] = None, handler: Callable = None, *args) -> None:
        """ install given ipa/ipcc from device path """
        self.install_from_local(package_path, 'Install', options, handler, args)

    def upgrade(self, ipa_path: str, options: Optional[dict] = None, handler: Callable = None, *args) -> None:
        """ upgrade given ipa from device path """
        self.install_from_local(ipa_path, 'Upgrade', options, handler, args)

    def restore(self, bundle_identifier: str, options: Optional[dict] = None, handler: Callable = None, *args) -> None:
        """ no longer supported on newer iOS versions """
        self.send_cmd_for_bundle_identifier(bundle_identifier, 'Restore', options, handler, args)

    def uninstall(self, bundle_identifier: str, options: Optional[dict] = None, handler: Callable = None,
                  *args) -> None:
        """ uninstall given bundle_identifier """
        self.send_cmd_for_bundle_identifier(bundle_identifier, 'Uninstall', options, handler, args)

    def install_from_bytes(self, package_bytes: bytes, cmd: str = 'Install', options: Optional[dict] = None,
                           handler: Callable = None, *args) -> None:
        """ upload given ipa/ipcc bytes object onto device and install it """
        ipcc_mode = classify_zip_file(package_bytes).is_ipcc()

        if options is None:
            options = {}

        if ipcc_mode:
            options['PackageType'] = 'CarrierBundle'

        with AfcService(self.lockdown) as afc:
            if not ipcc_mode:
                afc.set_file_contents(TEMP_REMOTE_IPA_FILE, package_bytes)
            else:
                self.upload_ipcc_from_bytes(package_bytes, afc)

        self.send_package(cmd, options, handler, ipcc_mode, *args)

    @str_to_path('package_path')
    def install_from_local(self, package_path: Path, cmd: str = 'Install', options: Optional[dict] = None,
                           handler: Callable = None, *args) -> None:
        """ upload given ipa/ipcc onto device and install it """
        ipcc_mode = package_path.suffix == '.ipcc'

        if options is None:
            options = {}

        if ipcc_mode:
            options['PackageType'] = 'CarrierBundle'
        else:
            if package_path.is_dir():
                # treat as app, convert into an ipa
                ipa_contents = create_ipa_contents_from_directory(str(package_path))
            else:
                # treat as ipa
                ipa_contents = package_path.read_bytes()

        with AfcService(self.lockdown) as afc:
            if not ipcc_mode:
                afc.makedirs(TEMP_REMOTE_BASEDIR)
                afc.set_file_contents(TEMP_REMOTE_IPA_FILE, ipa_contents)

            else:
                self.upload_ipcc_from_path(package_path, afc)

        self.send_package(cmd, options, handler, ipcc_mode, *args)

    def send_package(self, cmd: str, options: Optional[dict], handler: Callable, ipcc_mode: bool = False, *args):
        self.service.send_plist({
            'Command': cmd,
            'ClientOptions': options,
            'PackagePath': (
                TEMP_REMOTE_IPCC_FOLDER if ipcc_mode
                else TEMP_REMOTE_IPA_FILE
            )
        })

        self._watch_completion(handler, ipcc_mode, args)

    def upload_ipcc_from_path(self, file: Path, afc_client: AfcService) -> None:
        """Used to upload a .ipcc file to an iPhone as a folder"""
        with file.open('rb') as fb:
            file_name = file.name
            file_stream = BytesIO(fb.read())
            self._upload_ipcc(file_stream, afc_client, file_name)

    def upload_ipcc_from_bytes(self, file_bytes: bytes, afc_client: AfcService) -> None:
        """Used to upload a .ipcc bytes array to an iPhone as a folder"""
        file_stream = BytesIO(file_bytes)
        file_name = "bytes"
        self._upload_ipcc(file_stream, afc_client, file_name)

    def _upload_ipcc(self, file_stream: BytesIO, afc_client: AfcService, file_name: str) -> None:
        self.logger.info(f'Uploading {file_name} contents..')

        afc_client.makedirs(TEMP_REMOTE_IPCC_FOLDER)

        # we unpack it and upload it directly instead of saving it in a temp folder
        with ZipFile(file_stream, 'r') as file_zip:
            for file_name in file_zip.namelist():

                if file_name.endswith(('/', '\\')):
                    afc_client.makedirs(f'{TEMP_REMOTE_IPCC_FOLDER}/{file_name}')
                    continue

                with file_zip.open(file_name) as inside_file_zip:
                    file_data = inside_file_zip.read()
                    afc_client.makedirs(TEMP_REMOTE_BASEDIR)
                    afc_client.set_file_contents(f'{TEMP_REMOTE_IPCC_FOLDER}/{file_name}', file_data)

        self.logger.info('Upload complete.')

    def check_capabilities_match(self, capabilities: Optional[dict] = None, options: Optional[dict] = None) -> dict:
        if options is None:
            options = {}
        cmd = {'Command': 'CheckCapabilitiesMatch',
               'ClientOptions': options}

        if capabilities:
            cmd['Capabilities'] = capabilities

        return self.service.send_recv_plist(cmd).get('LookupResult')

    def browse(self, options: Optional[dict] = None, attributes: list[str] = None) -> list[dict]:
        if options is None:
            options = {}
        if attributes:
            options['ReturnAttributes'] = attributes

        cmd = {'Command': 'Browse',
               'ClientOptions': options}

        self.service.send_plist(cmd)

        result = []
        while True:
            response = self.service.recv_plist()
            if not response:
                break

            data = response.get('CurrentList')
            if data is not None:
                result += data

            if response.get('Status') == 'Complete':
                break

        return result

    def lookup(self, options: Optional[dict] = None) -> dict:
        """ search installation database """
        if options is None:
            options = {}
        cmd = {'Command': 'Lookup', 'ClientOptions': options}
        return self.service.send_recv_plist(cmd).get('LookupResult')

    def get_apps(self, application_type: str = 'Any', calculate_sizes: bool = False,
                 bundle_identifiers: Optional[list[str]] = None) -> dict[str, dict]:
        """ get applications according to given criteria """
        options = {}
        if bundle_identifiers is not None:
            options['BundleIDs'] = bundle_identifiers

        options['ApplicationType'] = application_type
        result = self.lookup(options)
        if calculate_sizes:
            options.update(GET_APPS_ADDITIONAL_INFO)
            additional_info = self.lookup(options)
            for bundle_identifier, app in additional_info.items():
                result[bundle_identifier].update(app)
        return result
