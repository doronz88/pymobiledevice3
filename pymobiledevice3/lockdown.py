#!/usr/bin/env python3
import plistlib
import platform
import logging
import uuid
import sys
import os
import re

from pymobiledevice3.plist_service import PlistService
from pymobiledevice3.ca import ca_do_everything
from pymobiledevice3.util import readHomeFile, writeHomeFile
from pymobiledevice3.usbmux import usbmux


class NotTrustedError(Exception):
    pass


class PairingError(Exception):
    pass


class NotPairedError(Exception):
    pass


class CannotStopSessionError(Exception):
    pass


class StartServiceError(Exception):
    def __init__(self, message):
        print("[ERROR] %s" % message)


class FatalPairingError(Exception):
    pass


# we store pairing records and ssl keys in ~/.pymobiledevice3
HOMEFOLDER = ".pymobiledevice3"
MAXTRIES = 20


def list_devices():
    mux = usbmux.USBMux()
    mux.process(1)
    return [d.serial for d in mux.devices]


class LockdownClient(object):
    def __init__(self, udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.paired = False
        self.SessionID = None
        self.c = PlistService(62078, udid)
        self.hostID = self.generate_host_id()
        self.SystemBUID = self.generate_host_id()
        self.paired = False
        self.label = "pyMobileDevice"

        assert self.query_type() == "com.apple.mobile.lockdown"

        self.allValues = self.get_value()
        self.udid = self.allValues.get("UniqueDeviceID").replace('-', '')
        self.UniqueChipID = self.allValues.get("UniqueChipID")
        self.DevicePublicKey = self.allValues.get("DevicePublicKey")
        self.ios_version = self.allValues.get("ProductVersion")
        self.identifier = self.udid
        if not self.identifier:
            if self.UniqueChipID:
                self.identifier = "%x" % self.UniqueChipID
            else:
                raise Exception("Could not get UDID or ECID, failing")

        if not self.validate_pairing():
            self.pair()
            self.c = PlistService(62078, udid)
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
        self.c.send_plist({"Request": "QueryType"})
        res = self.c.recv_plist()
        return res.get("Type")

    def generate_host_id(self):
        hostname = platform.node()
        hostid = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
        return str(hostid).upper()

    def enter_recovery(self):
        self.c.send_plist({"Request": "EnterRecovery"})
        return self.c.recv_plist()

    def stop_session(self):
        if self.SessionID and self.c:
            self.c.send_plist({"Label": self.label, "Request": "StopSession", "SessionID": self.SessionID})
            self.SessionID = None
            res = self.c.recv_plist()
            if not res or res.get("Result") != "Success":
                raise CannotStopSessionError
            return res

    def validate_pairing(self):
        pair_record = None
        cert_pem = None
        private_key_pem = None

        if sys.platform == "win32":
            folder = os.environ["ALLUSERSPROFILE"] + "/Apple/Lockdown/"
        elif sys.platform == "darwin":
            folder = "/var/db/lockdown/"
        elif len(sys.platform) >= 5:
            if sys.platform[0:5] == "linux":
                folder = "/var/lib/lockdown/"
        try:
            pair_record = plistlib.load(folder + "%s.plist" % self.identifier)
            logging.warning("Using iTunes pair record: %s.plist" % self.identifier)
        except:
            logging.warning(("No iTunes pairing record found for device %s" % self.identifier))
            if self.compare_ios_version("13.0") >= 0:
                self.logger.warning("Getting pair record from usbmuxd")
                client = usbmux.UsbmuxdClient()
                pair_record = client.get_pair_record(self.udid)
            else:
                self.logger.warning("Looking for pymobiledevice3 pairing record")
                record = readHomeFile(HOMEFOLDER, "%s.plist" % self.identifier)
                if record:
                    pair_record = plistlib.readPlistFromString(record)
                    self.logger.warning("Found pymobiledevice3 pairing record for device %s" % self.udid)
                else:
                    self.logger.error("No  pymobiledevice3 pairing record found for device %s" % self.identifier)
                    return False
        self.record = pair_record

        cert_pem = pair_record["HostCertificate"]
        private_key_pem = pair_record["HostPrivateKey"]

        if self.compare_ios_version("11.0") < 0:
            ValidatePair = {"Label": self.label, "Request": "ValidatePair", "PairRecord": pair_record}
            self.c.send_plist(ValidatePair)
            r = self.c.recv_plist()
            if not r or r.has_key("Error"):
                pair_record = None
                self.logger.error("ValidatePair fail", ValidatePair)
                return False

        self.hostID = pair_record.get("HostID", self.hostID)
        self.SystemBUID = pair_record.get("SystemBUID", self.SystemBUID)
        d = {"Label": self.label, "Request": "StartSession", "HostID": self.hostID, 'SystemBUID': self.SystemBUID}
        self.c.send_plist(d)
        start_session = self.c.recv_plist()
        self.SessionID = start_session.get("SessionID")
        if start_session.get("EnableSessionSSL"):
            self.sslfile = self.identifier + "_ssl.txt"
            lf = b"\n"
            self.sslfile = writeHomeFile(HOMEFOLDER, self.sslfile, cert_pem + lf + private_key_pem)
            self.c.ssl_start(self.sslfile, self.sslfile)

        self.paired = True
        return True

    def get_itunes_record_path(self):
        folder = None
        if sys.platform == "win32":
            folder = os.environ["ALLUSERSPROFILE"] + "/Apple/Lockdown/"
        elif sys.platform == "darwin":
            folder = "/var/db/lockdown/"
        elif len(sys.platform) >= 5:
            if sys.platform[0:5] == "linux":
                folder = "/var/lib/lockdown/"
        try:
            pair_record = plistlib.readPlist(folder + "%s.plist" % self.identifier)
            print("Using iTunes pair record: %s.plist" % self.identifier)
        except:
            print("No iTunes pairing record found for device %s" % self.identifier)
            if self.compare_ios_version("13.0") >= 0:
                print("Getting pair record from usbmuxd")
                client = usbmux.UsbmuxdClient()
                pair_record = client.get_pair_record(self.udid)
            else:
                print("Looking for pymobiledevice3 pairing record")
                record = readHomeFile(HOMEFOLDER, "%s.plist" % self.identifier)
                if record:
                    pair_record = plistlib.readPlistFromString(record)
                    print("Found pymobiledevice3 pairing record for device %s" % self.udid)
                else:
                    print("No  pymobiledevice3 pairing record found for device %s" % self.identifier)
                    return False
        self.record = pair_record

        cert_pem = pair_record["HostCertificate"]
        private_key_pem = pair_record["HostPrivateKey"]

        if self.compare_ios_version("11.0") < 0:
            validate_pair = {"Label": self.label, "Request": "ValidatePair", "PairRecord": pair_record}
            self.c.send_plist(validate_pair)
            r = self.c.recv_plist()
            if not r or r.has_key("Error"):
                pair_record = None
                self.logger.error("ValidatePair fail: %s", validate_pair)
                return False

        self.hostID = pair_record.get("HostID", self.hostID)
        self.SystemBUID = pair_record.get("SystemBUID", self.SystemBUID)
        d = {"Label": self.label, "Request": "StartSession", "HostID": self.hostID, 'SystemBUID': self.SystemBUID}
        self.c.send_plist(d)
        start_session = self.c.recv_plist()
        self.SessionID = start_session.get("SessionID")
        if start_session.get("EnableSessionSSL"):
            self.sslfile = self.identifier + "_ssl.txt"
            lf = b"\n"
            self.sslfile = writeHomeFile(HOMEFOLDER, self.sslfile, cert_pem + lf + private_key_pem)
            self.c.ssl_start(self.sslfile, self.sslfile)

        self.paired = True
        return True

    def pair(self):
        self.DevicePublicKey = self.get_value("", "DevicePublicKey")
        if self.DevicePublicKey == '':
            self.logger.error("Unable to retreive DevicePublicKey")
            return False

        self.logger.info("Creating host key & certificate")
        cert_pem, private_key_pem, device_certificate = ca_do_everything(self.DevicePublicKey)

        pair_record = {"DevicePublicKey": plistlib.Data(self.DevicePublicKey),
                       "DeviceCertificate": plistlib.Data(device_certificate),
                       "HostCertificate": plistlib.Data(cert_pem),
                       "HostID": self.hostID,
                       "RootCertificate": plistlib.Data(cert_pem),
                       "SystemBUID": "30142955-444094379208051516"}

        pair = {"Label": self.label, "Request": "Pair", "PairRecord": pair_record}
        self.c.send_plist(pair)
        pair = self.c.recv_plist()

        if pair and pair.get("Result") == "Success" or pair.has_key("EscrowBag"):
            pair_record["HostPrivateKey"] = plistlib.Data(private_key_pem)
            pair_record["EscrowBag"] = pair.get("EscrowBag")
            writeHomeFile(HOMEFOLDER, "%s.plist" % self.identifier, plistlib.writePlistToString(pair_record))
            self.paired = True
            return True

        elif pair and pair.get("Error") == "PasswordProtected":
            self.c.close()
            raise NotTrustedError
        else:
            self.logger.error(pair.get("Error"))
            self.c.close()
            raise PairingError

    def get_value(self, domain=None, key=None):
        if isinstance(key, str) and hasattr(self, 'record') and hasattr(self.record, key):
            return self.record[key]

        req = {"Request": "GetValue", "Label": self.label}

        if domain:
            req["Domain"] = domain
        if key:
            req["Key"] = key

        self.c.send_plist(req)
        res = self.c.recv_plist()
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
        self.c.send_plist(req)
        res = self.c.recv_plist()
        self.logger.debug(res)
        return res

    def start_service(self, name, ssl=False):
        if not self.paired:
            self.logger.info("NotPaired")
            raise NotPairedError

        self.c.send_plist({"Label": self.label, "Request": "StartService", "Service": name})
        start_service = self.c.recv_plist()
        ssl_enabled = start_service.get("EnableServiceSSL", ssl)
        if not start_service or start_service.get("Error"):
            raise StartServiceError(start_service.get("Error"))
        plist_service = PlistService(start_service.get("Port"), self.udid)
        if ssl_enabled:
            plist_service.ssl_start(self.sslfile, self.sslfile)
        return plist_service

    def start_service_with_escrow_bag(self, name, escrow_bag=None):
        if not self.paired:
            self.logger.info("NotPaired")
            raise NotPairedError

        if not escrow_bag:
            escrow_bag = self.record['EscrowBag']

        self.c.send_plist({"Label": self.label, "Request": "StartService", "Service": name, 'EscrowBag': escrow_bag})
        start_service = self.c.recv_plist()
        if not start_service or start_service.get("Error"):
            if start_service.get("Error", "") == 'PasswordProtected':
                raise StartServiceError(
                    'your device is protected with password, please enter password in device and try again')
            raise StartServiceError(start_service.get("Error"))
        ssl_enabled = start_service.get("EnableServiceSSL", False)
        plist_service = PlistService(start_service.get("Port"), self.udid)
        if ssl_enabled:
            plist_service.ssl_start(self.sslfile, self.sslfile)
        return plist_service


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    l = LockdownClient()
    if l:
        n = writeHomeFile(HOMEFOLDER, "%s_infos.plist" % l.udid, plistlib.writePlistToString(l.allValues))
        logger.info("Wrote infos to %s", n)
    else:
        logger.error("Unable to connect to device")
