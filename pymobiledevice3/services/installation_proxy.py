import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, List, Mapping, Optional
from zipfile import ZIP_DEFLATED, ZipFile

from parameter_decorators import str_to_path

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.lockdown_service import LockdownService

GET_APPS_ADDITIONAL_INFO = {'ReturnAttributes': ['CFBundleIdentifier', 'StaticDiskUsage', 'DynamicDiskUsage']}

TEMP_REMOTE_IPA_FILE = '/pymobiledevice3.ipa'


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


class InstallationProxyService(LockdownService):
    SERVICE_NAME = 'com.apple.mobile.installation_proxy'
    RSD_SERVICE_NAME = 'com.apple.mobile.installation_proxy.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def _watch_completion(self, handler: Callable = None, *args) -> None:
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
                return
        raise AppInstallError()

    def send_cmd_for_bundle_identifier(self, bundle_identifier: str, cmd: str = 'Archive', options: Mapping = None,
                                       handler: Mapping = None, *args) -> None:
        """ send a low-level command to installation relay """
        cmd = {'Command': cmd,
               'ApplicationIdentifier': bundle_identifier}

        if options is None:
            options = {}

        cmd.update({'ClientOptions': options})
        self.service.send_plist(cmd)
        self._watch_completion(handler, *args)

    def install(self, ipa_path: str, options: Mapping = None, handler: Callable = None, *args) -> None:
        """ install given ipa from device path """
        self.install_from_local(ipa_path, 'Install', options, handler, args)

    def upgrade(self, ipa_path: str, options: Mapping = None, handler: Callable = None, *args) -> None:
        """ upgrade given ipa from device path """
        self.install_from_local(ipa_path, 'Upgrade', options, handler, args)

    def restore(self, bundle_identifier: str, options: Mapping = None, handler: Callable = None, *args) -> None:
        """ no longer supported on newer iOS versions """
        self.send_cmd_for_bundle_identifier(bundle_identifier, 'Restore', options, handler, args)

    def uninstall(self, bundle_identifier: str, options: Mapping = None, handler: Callable = None, *args) -> None:
        """ uninstall given bundle_identifier """
        self.send_cmd_for_bundle_identifier(bundle_identifier, 'Uninstall', options, handler, args)

    @str_to_path('ipa_or_app_path')
    def install_from_local(self, ipa_or_app_path: Path, cmd: str = 'Install', options: Optional[Mapping] = None,
                           handler: Callable = None, *args) -> None:
        """ upload given ipa onto device and install it """
        if options is None:
            options = {}
        if ipa_or_app_path.is_dir():
            # treat as app, convert into an ipa
            ipa_contents = create_ipa_contents_from_directory(str(ipa_or_app_path))
        else:
            # treat as ipa
            ipa_contents = ipa_or_app_path.read_bytes()

        with AfcService(self.lockdown) as afc:
            afc.set_file_contents(TEMP_REMOTE_IPA_FILE, ipa_contents)
        self.service.send_plist({'Command': cmd,
                                 'ClientOptions': options,
                                 'PackagePath': TEMP_REMOTE_IPA_FILE})
        self._watch_completion(handler, args)

    def check_capabilities_match(self, capabilities: Mapping = None, options: Mapping = None) -> Mapping:
        if options is None:
            options = {}
        cmd = {'Command': 'CheckCapabilitiesMatch',
               'ClientOptions': options}

        if capabilities:
            cmd['Capabilities'] = capabilities

        return self.service.send_recv_plist(cmd).get('LookupResult')

    def browse(self, options: Mapping = None, attributes: List[str] = None) -> List[Mapping]:
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

    def lookup(self, options: Optional[Mapping] = None) -> Mapping:
        """ search installation database """
        if options is None:
            options = {}
        cmd = {'Command': 'Lookup', 'ClientOptions': options}
        return self.service.send_recv_plist(cmd).get('LookupResult')

    def get_apps(self, application_type: str = 'Any', calculate_sizes: bool = False,
                 bundle_identifiers: Optional[List[str]] = None) -> Mapping[str, Mapping]:
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
