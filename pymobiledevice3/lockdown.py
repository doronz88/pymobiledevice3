#!/usr/bin/env python3
import logging
import os
import platform
import plistlib
import re
import sys
import uuid

from pymobiledevice3 import usbmux
from pymobiledevice3.ca import ca_do_everything
from pymobiledevice3.service_connection import ServiceConnection


class NotTrustedError(Exception):
    pass


class PairingError(Exception):
    pass


class NotPairedError(Exception):
    pass


class CannotStopSessionError(Exception):
    pass


class StartServiceError(Exception):
    pass


class FatalPairingError(Exception):
    pass


class NoDeviceConnected(Exception):
    pass


# we store pairing records and ssl keys in ~/.pymobiledevice3
HOMEFOLDER = ".pymobiledevice3"
MAXTRIES = 20


def read_file(filename):
    f = open(filename, 'rb')
    data = f.read()
    f.close()
    return data


def write_file(filename, data):
    f = open(filename, 'wb')
    f.write(data)
    f.close()


def get_home_path(folder_name, filename):
    home = os.path.expanduser('~')
    folder_path = os.path.join(home, folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return os.path.join(folder_path, filename)


def read_home_file(folder_name, filename):
    path = get_home_path(folder_name, filename)
    if not os.path.exists(path):
        return None
    return read_file(path)


# return path to HOME+folder_name+filename
def write_home_file(folder_name, filename, data):
    filepath = get_home_path(folder_name, filename)
    write_file(filepath, data)
    return filepath


def list_devices():
    mux = usbmux.USBMux()
    mux.process(0.1)
    return [d.serial for d in mux.devices]


class LockdownClient(object):
    DEFAULT_CLIENT_NAME = 'pyMobileDevice'
    SERVICE_PORT = 62078

    def __init__(self, udid=None, client_name=DEFAULT_CLIENT_NAME):
        if udid is None:
            available_udids = list_devices()
            if len(available_udids) == 0:
                raise NoDeviceConnected()
            udid = available_udids[0]

        self.logger = logging.getLogger(__name__)
        self.paired = False
        self.SessionID = None
        self.service = ServiceConnection.create(udid, self.SERVICE_PORT)
        self.host_id = self.generate_host_id()
        self.system_buid = self.generate_host_id()
        self.paired = False
        self.label = client_name

        assert self.query_type() == 'com.apple.mobile.lockdown'

        self.all_values = self.get_value()
        self.udid = self.all_values.get('UniqueDeviceID').replace('-', '')
        self.unique_chip_id = self.all_values.get('UniqueChipID')
        self.device_public_key = self.all_values.get('DevicePublicKey')
        self.ios_version = self.all_values.get('ProductVersion')
        self.identifier = self.udid
        if not self.identifier:
            if self.unique_chip_id:
                self.identifier = "%x" % self.unique_chip_id
            else:
                raise Exception('Could not get UDID or ECID, failing')

        if not self.validate_pairing():
            self.pair()
            self.service = ServiceConnection.create(udid, self.SERVICE_PORT)
            if not self.validate_pairing():
                raise FatalPairingError
        self.paired = True
        return

    def compare_ios_version(self, ios_version):
        """
        currrent_version > ios_version return 1
        currrent_version = ios_version return 0
        currrent_version < ios_version return -1
        :param ios_version:
        :return: int
        """
        version_reg = r'^\d*\.\d*\.?\d*$'
        if not re.match(version_reg, ios_version):
            raise Exception('ios_version invalid:%s' % ios_version)
        a = self.ios_version.split('.')
        b = ios_version.split('.')
        length = min(len(a), len(b))
        for i in range(length):
            if int(a[i]) < int(b[i]):
                return -1
            if int(a[i]) > int(b[i]):
                return 1
        if len(a) > len(b):
            return 1
        elif len(a) < len(b):
            return -1
        else:
            return 0

    def query_type(self):
        self.service.send_plist({"Request": "QueryType"})
        res = self.service.recv_plist()
        return res.get("Type")

    def generate_host_id(self):
        hostname = platform.node()
        hostid = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
        return str(hostid).upper()

    def enter_recovery(self):
        self.service.send_plist({"Request": "EnterRecovery"})
        return self.service.recv_plist()

    def stop_session(self):
        if self.SessionID and self.service:
            self.service.send_plist({"Label": self.label, "Request": "StopSession", "SessionID": self.SessionID})
            self.SessionID = None
            res = self.service.recv_plist()
            if not res or res.get("Result") != "Success":
                raise CannotStopSessionError
            return res

    def validate_pairing(self):
        if sys.platform == 'win32':
            folder = os.path.join(os.environ['ALLUSERSPROFILE'], 'Apple', 'Lockdown')
        elif sys.platform == 'darwin':
            folder = '/var/db/lockdown/'
        elif sys.platform.startswith('linux'):
            folder = '/var/lib/lockdown/'
        else:
            raise NotImplementedError('non-supported platform')

        filename = os.path.join(folder, f'{self.identifier}.plist')

        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                pair_record = plistlib.load(f)
            logging.warning(f'Using iTunes pair record: {self.identifier}.plist')
        else:
            logging.warning(f'No iTunes pairing record found for device {self.identifier}')
            if self.compare_ios_version('13.0') >= 0:
                self.logger.warning('Getting pair record from usbmuxd')
                client = usbmux.UsbmuxdClient()
                pair_record = client.get_pair_record(self.udid)
            else:
                self.logger.warning('Looking for pymobiledevice3 pairing record')
                record = read_home_file(HOMEFOLDER, f'{self.identifier}.plist')
                if record:
                    pair_record = plistlib.loads(record)
                    self.logger.warning(f'Found pymobiledevice3 pairing record for device {self.uuid}')
                else:
                    self.logger.error(f'No pymobiledevice3 pairing record found for device {self.identifier}')
                    return False

        self.pair_record = pair_record

        cert_pem = pair_record["HostCertificate"]
        private_key_pem = pair_record["HostPrivateKey"]

        if self.compare_ios_version("11.0") < 0:
            validate_pair = {"Label": self.label, "Request": "ValidatePair", "PairRecord": pair_record}
            self.service.send_plist(validate_pair)
            r = self.service.recv_plist()
            if (not r) or ('Error' in r):
                pair_record = None
                self.logger.error("ValidatePair fail", validate_pair)
                return False

        self.host_id = pair_record.get("HostID", self.host_id)
        self.system_buid = pair_record.get("SystemBUID", self.system_buid)
        d = {"Label": self.label, "Request": "StartSession", "HostID": self.host_id, 'SystemBUID': self.system_buid}
        self.service.send_plist(d)
        start_session = self.service.recv_plist()
        self.SessionID = start_session.get("SessionID")
        if start_session.get("EnableSessionSSL"):
            self.ssl_file = self.identifier + "_ssl.txt"
            lf = b"\n"
            self.ssl_file = write_home_file(HOMEFOLDER, self.ssl_file, cert_pem + lf + private_key_pem)
            self.service.ssl_start(self.ssl_file, self.ssl_file)

        self.paired = True
        return True

    def pair(self):
        self.device_public_key = self.get_value("", "DevicePublicKey")
        if self.device_public_key == '':
            self.logger.error("Unable to retrieve DevicePublicKey")
            return False

        self.logger.info("Creating host key & certificate")
        cert_pem, private_key_pem, device_certificate = ca_do_everything(self.device_public_key)

        pair_record = {"DevicePublicKey": plistlib.Data(self.device_public_key),
                       "DeviceCertificate": plistlib.Data(device_certificate),
                       "HostCertificate": plistlib.Data(cert_pem),
                       "HostID": self.host_id,
                       "RootCertificate": plistlib.Data(cert_pem),
                       "SystemBUID": "30142955-444094379208051516"}

        pair = {"Label": self.label, "Request": "Pair", "PairRecord": pair_record}
        self.service.send_plist(pair)
        pair = self.service.recv_plist()

        if pair and pair.get("Result") == "Success" or pair.has_key("EscrowBag"):
            pair_record["HostPrivateKey"] = plistlib.Data(private_key_pem)
            pair_record["EscrowBag"] = pair.get("EscrowBag")
            write_home_file(HOMEFOLDER, "%s.plist" % self.identifier, plistlib.dumps(pair_record))
            self.paired = True
            return True

        elif pair and pair.get("Error") == "PasswordProtected":
            self.service.close()
            raise NotTrustedError
        else:
            self.logger.error(pair.get("Error"))
            self.service.close()
            raise PairingError

    def get_value(self, domain=None, key=None):
        if isinstance(key, str) and hasattr(self, 'record') and hasattr(self.pair_record, key):
            return self.pair_record[key]

        req = {"Request": "GetValue", "Label": self.label}

        if domain:
            req["Domain"] = domain
        if key:
            req["Key"] = key

        self.service.send_plist(req)
        res = self.service.recv_plist()
        if res:
            r = res.get("Value")
            if hasattr(r, "data"):
                return r.data
            return r

    def set_value(self, value, domain=None, key=None):
        req = {"Request": "SetValue", "Label": self.label}

        if domain:
            req["Domain"] = domain
        if key:
            req["Key"] = key

        req["Value"] = value
        self.service.send_plist(req)
        response = self.service.recv_plist()
        self.logger.debug(response)
        return response

    def start_service(self, name, ssl=False, escrow_bag=None) -> ServiceConnection:
        if not self.paired:
            self.logger.info('NotPaired')
            raise NotPairedError()

        request = {'Label': self.label, 'Request': 'StartService', 'Service': name}
        if escrow_bag is not None:
            request['EscrowBag'] = escrow_bag

        self.service.send_plist(request)
        response = self.service.recv_plist()
        ssl_enabled = response.get('EnableServiceSSL', ssl)
        if not response or response.get('Error'):
            if response.get("Error", "") == 'PasswordProtected':
                raise StartServiceError(
                    'your device is protected with password, please enter password in device and try again')
            raise StartServiceError(response.get("Error"))
        service_connection = ServiceConnection.create(self.udid, response.get('Port'))
        if ssl_enabled:
            service_connection.ssl_start(self.ssl_file, self.ssl_file)
        return service_connection


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    l = LockdownClient()
    if l:
        n = write_home_file(HOMEFOLDER, "%s_infos.plist" % l.udid, plistlib.writePlistToString(l.all_values))
        logger.info("Wrote infos to %s", n)
    else:
        logger.error("Unable to connect to device")
