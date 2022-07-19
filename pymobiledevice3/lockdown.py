#!/usr/bin/env python3
import datetime
import logging
import os
import platform
import plistlib
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Mapping

from packaging.version import Version

from pymobiledevice3 import usbmux
from pymobiledevice3.ca import ca_do_everything
from pymobiledevice3.exceptions import *
from pymobiledevice3.exceptions import LockdownError, SetProhibitedError, PasscodeRequiredError
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.usbmux import PlistMuxConnection
from pymobiledevice3.utils import sanitize_ios_version

SYSTEM_BUID = '30142955-444094379208051516'

# we store pairing records and ssl keys in ~/.pymobiledevice3
HOMEFOLDER = Path.home() / '.pymobiledevice3'

LOCKDOWN_PATH = {
    'win32': Path(os.environ.get('ALLUSERSPROFILE', ''), 'Apple', 'Lockdown'),
    'darwin': Path('/var/db/lockdown/'),
    'linux': Path('/var/lib/lockdown/'),
}


def write_home_file(filename, data):
    HOMEFOLDER.mkdir(parents=True, exist_ok=True)
    filepath = HOMEFOLDER / filename
    filepath.write_bytes(data)
    return str(filepath)


def reconnect_on_remote_close(f):
    """
    lockdownd's _socket_select will close the connection after 60 seconds of "radio-silent" (no data has been
    transmitted). When this happens, we'll attempt to reconnect.
    """

    def _reconnect_on_remote_close(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (BrokenPipeError, ConnectionTerminatedError):
            self = args[0]

            # first we release the socket on our end to avoid a ResourceWarning
            self.close()

            # now we re-establish the connection
            self.logger.debug('remote device closed the connection. reconnecting...')
            self.service = ServiceConnection.create(self.udid, self.SERVICE_PORT,
                                                    connection_type=self.usbmux_device.connection_type)
            self.validate_pairing()
            return f(*args, **kwargs)

    return _reconnect_on_remote_close


DOMAINS = ['com.apple.disk_usage',
           'com.apple.disk_usage.factory',
           'com.apple.mobile.battery',
           # FIXME: For some reason lockdownd segfaults on this, works sometimes tho
           # 'com.apple.mobile.debug',
           'com.apple.iqagent',
           'com.apple.purplebuddy',
           'com.apple.PurpleBuddy',
           'com.apple.mobile.chaperone',
           'com.apple.mobile.third_party_termination',
           'com.apple.mobile.lockdownd',
           'com.apple.mobile.lockdown_cache',
           'com.apple.xcode.developerdomain',
           'com.apple.international',
           'com.apple.mobile.data_sync',
           'com.apple.mobile.tethered_sync',
           'com.apple.mobile.mobile_application_usage',
           'com.apple.mobile.backup',
           'com.apple.mobile.nikita',
           'com.apple.mobile.restriction',
           'com.apple.mobile.user_preferences',
           'com.apple.mobile.sync_data_class',
           'com.apple.mobile.software_behavior',
           'com.apple.mobile.iTunes.SQLMusicLibraryPostProcessCommands',
           'com.apple.mobile.iTunes.accessories',
           'com.apple.mobile.internal',  # < iOS 4.0+
           'com.apple.mobile.wireless_lockdown',  # < iOS 4.0+
           'com.apple.fairplay',
           'com.apple.iTunes',
           'com.apple.mobile.iTunes.store',
           'com.apple.mobile.iTunes',
           'com.apple.fmip',
           'com.apple.Accessibility', ]


class LockdownClient(object):
    DEFAULT_CLIENT_NAME = 'pymobiledevice3'
    SERVICE_PORT = 62078

    def __init__(self, udid: str = None, client_name: str = DEFAULT_CLIENT_NAME, autopair: bool = True,
                 connection_type: str = None, pair_timeout: int = None, hostname: str = None,
                 pair_record: Mapping = None):
        """
        :param udid: serial number for device to connect to
        :param client_name: user agent to use when identifying for lockdownd
        :param autopair: should automatically attempt pairing with device
        :param connection_type: can be either "USB" or "Network" to specify what connection type to use
        :param pair_timeout: if autopair, use this timeout for user's Trust dialog. If None, will wait forever
        :param hostname: use given hostname to generate the HostID inside the pair record
        :param pair_record: use this pair record instead of the one already stored
        """
        device = usbmux.select_device(udid, connection_type=connection_type)
        if device is None:
            if udid:
                raise ConnectionFailedError()
            else:
                raise NoDeviceConnectedError()

        self.usbmux_device = device
        self.logger = logging.getLogger(__name__)
        self.paired = False
        self.session_id = None
        self.service = ServiceConnection.create(udid, self.SERVICE_PORT, connection_type=device.connection_type)
        self.host_id = self.generate_host_id(hostname)
        self.system_buid = SYSTEM_BUID
        self.label = client_name
        self.pair_record = pair_record
        self.ssl_file = None

        if self.query_type() != 'com.apple.mobile.lockdown':
            raise IncorrectModeError()

        self.all_values = self.get_value()
        self.udid = self.all_values.get('UniqueDeviceID', self.usbmux_device.serial)
        self.unique_chip_id = self.all_values.get('UniqueChipID')
        self.device_public_key = self.all_values.get('DevicePublicKey')
        self.product_version = self.all_values.get('ProductVersion')
        self.product_type = self.all_values.get('ProductType')
        self.identifier = self.udid

        if not self.identifier:
            if self.unique_chip_id:
                self.identifier = f'{self.unique_chip_id:x}'
            else:
                raise PyMobileDevice3Exception('Could not get UDID or ECID, failing')

        if not self.validate_pairing():
            # device is not paired

            if not autopair:
                # but pairing by default was not requested
                return

            self.pair(timeout=pair_timeout)

            # get session_id
            if not self.validate_pairing():
                raise FatalPairingError()

        # reload data after pairing
        self.all_values = self.get_value()

    def __repr__(self):
        return f'<{self.__class__.__name__} ID:{self.identifier} VERSION:{self.product_version} ' \
               f'TYPE:{self.product_type} PAIRED:{self.paired}>'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def query_type(self) -> str:
        return self._request('QueryType').get('Type')

    @property
    def all_domains(self) -> Mapping:
        result = self.all_values

        for domain in DOMAINS:
            result.update({domain: self.get_value(domain)})

        return result

    @property
    def short_info(self) -> Mapping:
        keys_to_copy = ['DeviceClass', 'DeviceName', 'BuildVersion', 'ProductVersion', 'ProductType']
        result = {
            'ConnectionType': self.usbmux_device.connection_type,
            'Serial': self.usbmux_device.serial,
        }
        for key in keys_to_copy:
            result[key] = self.all_values.get(key)
        return result

    @property
    def share_iphone_analytics_enabled(self) -> bool:
        return self.get_value('com.apple.MobileDeviceCrashCopy', 'ShouldSubmit')

    @property
    def voice_over(self) -> bool:
        return bool(self.get_value('com.apple.Accessibility').get('VoiceOverTouchEnabledByiTunes', 0))

    @voice_over.setter
    def voice_over(self, value: bool):
        self.set_value(int(value), 'com.apple.Accessibility', 'VoiceOverTouchEnabledByiTunes')

    @property
    def invert_display(self) -> bool:
        return bool(self.get_value('com.apple.Accessibility').get('InvertDisplayEnabledByiTunes', 0))

    @invert_display.setter
    def invert_display(self, value: bool):
        self.set_value(int(value), 'com.apple.Accessibility', 'InvertDisplayEnabledByiTunes')

    @property
    def enable_wifi_pairing(self) -> bool:
        return self.get_value('com.apple.mobile.wireless_lockdown').get('EnableWifiPairing', False)

    @enable_wifi_pairing.setter
    def enable_wifi_pairing(self, value: bool):
        try:
            self.set_value(value, 'com.apple.mobile.wireless_lockdown', 'EnableWifiPairing')
        except MissingValueError as e:
            raise PasscodeRequiredError from e

    @property
    def enable_wifi_connections(self):
        return self.get_value('com.apple.mobile.wireless_lockdown').get('EnableWifiConnections', False)

    @enable_wifi_connections.setter
    def enable_wifi_connections(self, value: bool):
        self.set_value(value, 'com.apple.mobile.wireless_lockdown', 'EnableWifiConnections')

    @property
    def ecid(self):
        return self.all_values['UniqueChipID']

    @property
    def date(self):
        return datetime.datetime.fromtimestamp(self.get_value(key='TimeIntervalSince1970'))

    @property
    def language(self):
        return self.get_value(key='Language', domain='com.apple.international')

    @property
    def locale(self):
        return self.get_value(key='Locale', domain='com.apple.international')

    @property
    def preflight_info(self):
        return self.get_value(key='FirmwarePreflightInfo')

    @property
    def sanitized_ios_version(self):
        return sanitize_ios_version(self.product_version)

    def set_language(self, language: str):
        self.set_value(language, key='Language', domain='com.apple.international')

    def set_locale(self, locale: str):
        self.set_value(locale, key='Locale', domain='com.apple.international')

    @staticmethod
    def generate_host_id(hostname: str = None) -> str:
        hostname = platform.node() if hostname is None else hostname
        host_id = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
        return str(host_id).upper()

    @reconnect_on_remote_close
    def enter_recovery(self):
        return self._request('EnterRecovery')

    def stop_session(self):
        if self.session_id and self.service:
            response = self._request('StopSession', {'SessionID': self.session_id})
            self.session_id = None
            if not response or response.get('Result') != 'Success':
                raise CannotStopSessionError()
            return response

    def get_itunes_pairing_record(self):
        platform_type = 'linux' if not sys.platform.startswith('linux') else sys.platform
        filename = LOCKDOWN_PATH[platform_type] / f'{self.identifier}.plist'
        try:
            with open(filename, 'rb') as f:
                pair_record = plistlib.load(f)
        except (PermissionError, FileNotFoundError, plistlib.InvalidFileException):
            return None
        return pair_record

    def get_local_pairing_record(self):
        self.logger.debug('Looking for pymobiledevice3 pairing record')
        path = HOMEFOLDER / f'{self.identifier}.plist'
        if not path.exists():
            self.logger.error(f'No pymobiledevice3 pairing record found for device {self.identifier}')
            return None
        return plistlib.loads(path.read_bytes())

    def validate_pairing(self) -> bool:
        try:
            self._init_preferred_pair_record()
        except NotPairedError:
            return False

        if self.pair_record is None:
            return False

        cert_pem = self.pair_record['HostCertificate']
        private_key_pem = self.pair_record['HostPrivateKey']

        if Version(self.product_version) < Version('11.0'):
            try:
                self._request('ValidatePair', {'PairRecord': self.pair_record})
            except PairingError:
                return False

        self.host_id = self.pair_record.get('HostID', self.host_id)
        self.system_buid = self.pair_record.get('SystemBUID', self.system_buid)

        try:
            start_session = self._request('StartSession', {'HostID': self.host_id, 'SystemBUID': self.system_buid})
        except InvalidHostIDError:
            # no host id means there is no such pairing record
            return False

        self.session_id = start_session.get('SessionID')
        if start_session.get('EnableSessionSSL'):
            lf = b'\n'
            self.ssl_file = write_home_file(f'{self.identifier}_ssl.txt', cert_pem + lf + private_key_pem)
            self.service.ssl_start(self.ssl_file, self.ssl_file)

        self.paired = True
        return True

    @reconnect_on_remote_close
    def pair(self, timeout: int = None):
        self.device_public_key = self.get_value('', 'DevicePublicKey')
        if not self.device_public_key:
            self.logger.error('Unable to retrieve DevicePublicKey')
            self.service.close()
            raise PairingError()

        self.logger.info('Creating host key & certificate')
        cert_pem, private_key_pem, device_certificate = ca_do_everything(self.device_public_key)

        pair_record = {'DevicePublicKey': self.device_public_key,
                       'DeviceCertificate': device_certificate,
                       'HostCertificate': cert_pem,
                       'HostID': self.host_id,
                       'RootCertificate': cert_pem,
                       'SystemBUID': self.system_buid}

        pair_options = {'PairRecord': pair_record, 'ProtocolVersion': '2',
                        'PairingOptions': {'ExtendedPairingErrors': True}}

        pair = self._request_pair(pair_options, timeout=timeout)

        pair_record['HostPrivateKey'] = private_key_pem
        pair_record['EscrowBag'] = pair.get('EscrowBag')
        self.pair_record = pair_record
        write_home_file(f'{self.identifier}.plist', plistlib.dumps(pair_record))

        record_data = plistlib.dumps(pair_record)

        client = usbmux.create_mux()
        if isinstance(client, PlistMuxConnection):
            client.save_pair_record(self.udid, self.usbmux_device.devid, record_data)
        client.close()

        self.paired = True

    @reconnect_on_remote_close
    def unpair(self) -> Mapping:
        return self._request('Unpair', {'PairRecord': self.pair_record, 'ProtocolVersion': '2'}, verify_request=False)

    @reconnect_on_remote_close
    def reset_pairing(self):
        return self._request('ResetPairing', {'FullReset': True})

    @reconnect_on_remote_close
    def get_value(self, domain: str = None, key: str = None):
        options = {}

        if domain:
            options['Domain'] = domain
        if key:
            options['Key'] = key

        res = self._request('GetValue', options)
        if res:
            r = res.get('Value')
            if hasattr(r, 'data'):
                return r.data
            return r

    @reconnect_on_remote_close
    def remove_value(self, domain: str = None, key: str = None) -> Mapping:
        options = {}

        if domain:
            options['Domain'] = domain
        if key:
            options['Key'] = key

        return self._request('RemoveValue', options)

    @reconnect_on_remote_close
    def set_value(self, value, domain: str = None, key: str = None) -> Mapping:
        options = {}

        if domain:
            options['Domain'] = domain
        if key:
            options['Key'] = key

        options['Value'] = value
        return self._request('SetValue', options)

    def get_service_connection_attributes(self, name, escrow_bag=None) -> Mapping:
        if not self.paired:
            raise NotPairedError()

        options = {'Service': name}
        if escrow_bag is not None:
            options['EscrowBag'] = escrow_bag

        response = self._request('StartService', options)
        if not response or response.get('Error'):
            if response.get('Error', '') == 'PasswordProtected':
                raise PasswordRequiredError(
                    'your device is protected with password, please enter password in device and try again')
            raise StartServiceError(response.get('Error'))
        return response

    @reconnect_on_remote_close
    def start_service(self, name, escrow_bag=None) -> ServiceConnection:
        attr = self.get_service_connection_attributes(name, escrow_bag=escrow_bag)
        service_connection = ServiceConnection.create(self.udid, attr['Port'],
                                                      connection_type=self.usbmux_device.connection_type)
        if attr.get('EnableServiceSSL', False):
            service_connection.ssl_start(self.ssl_file, self.ssl_file)
        return service_connection

    async def aio_start_service(self, name, escrow_bag=None) -> ServiceConnection:
        attr = self.get_service_connection_attributes(name, escrow_bag=escrow_bag)
        service_connection = ServiceConnection.create(self.udid, attr['Port'],
                                                      connection_type=self.usbmux_device.connection_type)
        if attr.get('EnableServiceSSL', False):
            await service_connection.aio_ssl_start(self.ssl_file, self.ssl_file)
        return service_connection

    def start_developer_service(self, name, escrow_bag=None) -> ServiceConnection:
        try:
            return self.start_service(name, escrow_bag)
        except (StartServiceError, ConnectionFailedError):
            self.logger.error(
                'Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. '
                'You can do so using: pymobiledevice3 mounter mount'
            )
            raise

    def close(self):
        self.service.close()

    def _request(self, request: str, options: Mapping = None, verify_request: bool = True) -> Mapping:
        message = {'Label': self.label, 'Request': request}
        if options:
            message.update(options)
        response = self.service.send_recv_plist(message)

        if verify_request and response['Request'] != request:
            raise LockdownError(f'incorrect response returned. got {response["Request"]} instead of {request}')

        error = response.get('Error')
        if error is not None:
            exception_errors = {'PasswordProtected': PasswordRequiredError,
                                'PairingDialogResponsePending': PairingDialogResponsePendingError,
                                'UserDeniedPairing': UserDeniedPairingError,
                                'InvalidHostID': InvalidHostIDError,
                                'SetProhibited': SetProhibitedError,
                                'MissingValue': MissingValueError, }
            raise exception_errors.get(error, LockdownError)(error)

        # iOS < 5: 'Error' is not present, so we need to check the 'Result' instead
        if response.get('Result') == 'Failure':
            raise LockdownError()

        return response

    def _request_pair(self, pair_options: Mapping, timeout: int = None):
        try:
            return self._request('Pair', pair_options)
        except PairingDialogResponsePendingError:
            if timeout == 0:
                raise

        self.logger.info('waiting user pairing dialog...')
        start = time.time()
        while timeout is None or time.time() <= start + timeout:
            with suppress(PairingDialogResponsePendingError):
                return self._request('Pair', pair_options)
            time.sleep(1)
        raise PairingDialogResponsePendingError()

    def _init_preferred_pair_record(self):
        if self.pair_record is not None:
            # if already have one, use it
            return

        pair_record = self.get_itunes_pairing_record()
        if pair_record is not None:
            self.logger.debug(f'Using iTunes pair record: {self.identifier}.plist')

        mux = usbmux.create_mux()
        if isinstance(mux, PlistMuxConnection):
            pair_record = mux.get_pair_record(self.udid)
        else:
            pair_record = self.get_local_pairing_record()
        mux.close()

        if pair_record is None:
            return

        self.pair_record = pair_record
