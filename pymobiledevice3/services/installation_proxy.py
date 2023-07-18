import os
import posixpath
from typing import Callable, List, Mapping

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.lockdown_service import LockdownService

GET_APPS_ADDITIONAL_INFO = {'ReturnAttributes': ['CFBundleIdentifier', 'StaticDiskUsage', 'DynamicDiskUsage']}


class InstallationProxyService(LockdownService):
    SERVICE_NAME = 'com.apple.mobile.installation_proxy'
    RSD_SERVICE_NAME = 'com.apple.mobile.installation_proxy.shim.remote'

    def __init__(self, lockdown: LockdownClient):
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

    def install_from_local(self, ipa_path: str, cmd='Install', options: Mapping = None, handler: Callable = None,
                           *args) -> None:
        """ upload given ipa onto device and install it """
        if options is None:
            options = {}
        remote_path = posixpath.join('/', os.path.basename(ipa_path))
        with AfcService(self.lockdown) as afc:
            afc.set_file_contents(remote_path, open(ipa_path, 'rb').read())
        cmd = {'Command': cmd,
               'ClientOptions': options,
               'PackagePath': remote_path}
        self.service.send_plist(cmd)
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

    def lookup(self, options: Mapping = None) -> Mapping:
        """ search installation database """
        if options is None:
            options = {}
        cmd = {'Command': 'Lookup', 'ClientOptions': options}
        return self.service.send_recv_plist(cmd).get('LookupResult')

    def get_apps(self, app_types: List[str] = None) -> Mapping[str, Mapping]:
        """ get applications according to given criteria """
        result = self.lookup()
        # query for additional info
        additional_info = self.lookup(GET_APPS_ADDITIONAL_INFO)
        for bundle_identifier, app in additional_info.items():
            result[bundle_identifier].update(app)
        # filter results
        filtered_result = {}
        for bundle_identifier, app in result.items():
            if (app_types is None) or (app['ApplicationType'] in app_types):
                filtered_result[bundle_identifier] = app
        return filtered_result
