#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# $Id$
#
# Copyright (c) 2012-2014 "dark[-at-]gotohack.org"
#
# This file is part of pymobiledevice
#
# pymobiledevice is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#


from plist_service import PlistService
from ca import ca_do_everything
from util import write_file, readHomeFile, writeHomeFile
import os
import plistlib
import sys
import uuid
import platform
import time
from usbmux import usbmux


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



#we store pairing records and ssl keys in ~/.pymobiledevice
HOMEFOLDER = ".pymobiledevice"
MAXTRIES = 20


def list_devices():
    mux = usbmux.USBMux()
    mux.process(1)
    return [d.serial for d in mux.devices]


class LockdownClient(object):

    def __init__(self,udid=None):
        self.paired = False
        self.SessionID = None
        self.c = PlistService(62078,udid)
        self.hostID = self.generate_hostID()
        self.SystemBUID = self.generate_hostID()
        self.paired = False
        self.label = "pyMobileDevice"
        
        assert self.queryType() == "com.apple.mobile.lockdown"

        self.udid = self.getValue("", "UniqueDeviceID")
        self.allValues = self.getValue()
        self.UniqueChipID = self.allValues.get("UniqueChipID")
        self.DevicePublicKey =  self.getValue("", "DevicePublicKey")
        self.identifier = self.udid
        if not self.identifier:
            if self.UniqueChipID:
                self.identifier = "%x" % self.UniqueChipID
            else:
                print "Could not get UDID or ECID, failing"
                raise

        if not self.validate_pairing():
            self.pair()
            if not self.validate_pairing():
                raise FatalPairingError
        self.paired = True
        return

    def queryType(self):
        self.c.sendPlist({"Request":"QueryType"})
        res = self.c.recvPlist()
        return res.get("Type")

    def generate_hostID(self):
        hostname = platform.node()
        hostid = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
        return str(hostid).upper()
       
       
    def enter_recovery(self):
        self.c.sendPlist({"Request": "EnterRecovery"})
        print self.c.recvPlist()
    

    def stop_session(self):
        if self.SessionID and self.c:
            self.c.sendPlist({"Label": self.label, "Request": "StopSession", "SessionID": self.SessionID})
            self.SessionID = None
            res = self.c.recvPlist()
            if not res or res.get("Result") != "Success":
                raise CannotStopSessionError
            return res
                    

    def validate_pairing(self):
        pair_record = None
        certPem = None
        privateKeyPem = None
        
        if sys.platform == "win32":
            folder = os.environ["ALLUSERSPROFILE"] + "/Apple/Lockdown/"
        elif sys.platform == "darwin":
            folder = "/var/db/lockdown/"
        elif sys.platform == 'linux2':
            folder = '/var/lib/lockdown/'
        try:
            pair_record = plistlib.readPlist(folder + "%s.plist" % self.identifier) 
        except:
            pair_record = None
        if pair_record:
            print "Using iTunes pair record: %s.plist" % self.identifier
            certPem = pair_record["HostCertificate"].data
            privateKeyPem = pair_record["HostPrivateKey"].data

        else:
            print "No iTunes pairing record found for device %s" % self.identifier
            print "Looking for pymobiledevice pairing record"
            record = readHomeFile(HOMEFOLDER, "%s.plist" % self.identifier)
            if record:
                pair_record = plistlib.readPlistFromString(record)
                print "Found pymobiledevice pairing record for device %s" % self.udid
                certPem = pair_record["HostCertificate"].data
                privateKeyPem = pair_record["HostPrivateKey"].data
            else:
                print "No  pymobiledevice pairing record found for device %s" % self.identifier
                return False

        self.record = pair_record
        ValidatePair = {"Label": self.label, "Request": "ValidatePair", "PairRecord": pair_record}
        self.c = PlistService(62078,self.udid) 
        self.c.sendPlist(ValidatePair)
        r = self.c.recvPlist()
        if not r or r.has_key("Error"):
            pair_record = None
            print "ValidatePair fail", ValidatePair
            return False

        self.hostID = pair_record.get("HostID", self.hostID)
        self.SystemBUID = pair_record.get("SystemBUID", self.SystemBUID)
        d = {"Label": self.label, "Request": "StartSession", "HostID": self.hostID, 'SystemBUID': self.SystemBUID}
        self.c.sendPlist(d)
        startsession = self.c.recvPlist() 
        self.SessionID = startsession.get("SessionID")
        if startsession.get("EnableSessionSSL"):
            sslfile = self.identifier + "_ssl.txt"
            sslfile = writeHomeFile(HOMEFOLDER, sslfile, certPem + "\n" + privateKeyPem)
            self.c.ssl_start(sslfile, sslfile)
        
        self.paired = True
        return True


    def pair(self):
        self.DevicePublicKey =  self.getValue("", "DevicePublicKey")
        if self.DevicePublicKey == '':
            print "Unable to retreive DevicePublicKey"
            return False

        print "Creating host key & certificate"
        certPem, privateKeyPem, DeviceCertificate = ca_do_everything(self.DevicePublicKey)

        pair_record = {"DevicePublicKey": plistlib.Data(self.DevicePublicKey),
                       "DeviceCertificate": plistlib.Data(DeviceCertificate),
                       "HostCertificate": plistlib.Data(certPem),
                       "HostID": self.hostID,
                       "RootCertificate": plistlib.Data(certPem),
                       "SystemBUID": "30142955-444094379208051516" }

        pair = {"Label": self.label, "Request": "Pair", "PairRecord": pair_record}
        self.c = PlistService(62078,self.udid)
        self.c.sendPlist(pair)
        pair = self.c.recvPlist()
        
        if pair and  pair.get("Result") == "Success" or pair.has_key("EscrowBag"):
            pair_record["HostPrivateKey"] = plistlib.Data(privateKeyPem)
            pair_record["EscrowBag"] = pair.get("EscrowBag")
            writeHomeFile(HOMEFOLDER, "%s.plist" % self.identifier, plistlib.writePlistToString(pair_record))
            self.paired = True
            return True

        elif pair and  pair.get("Error") == "PasswordProtected":
            self.c.close()
            raise NotTrustedError

        else:
            self.c.close()
            raise PairingError

    
    def getValue(self, domain=None, key=None):

        if(isinstance(key, str) and hasattr(self, 'record') and hasattr(self.record, key)):
            return self.record[key]
        req = {"Request":"GetValue", "Label": self.label}
        
        if domain:
            req["Domain"] = domain
        if key:
            req["Key"] = key

        self.c.sendPlist(req)
        res = self.c.recvPlist()
        if res:
            r = res.get("Value")
            if hasattr(r, "data"):
                return r.data
            return r

    def setValue(self, domain=None, key=None):

        req = {"Request":"SetValue", "Label": self.label}
        
        if domain:
            req["Domain"] = domain
        if key:
            req["Key"] = key

        self.c.sendPlist(req)
        res = self.c.recvPlist()
        print res
        return res

        
    def startService(self, name):
        if not self.paired:
            print "NotPaired"
            raise NotPairedError    

        self.c.sendPlist({"Label": self.label, "Request": "StartService", "Service": name})
        StartService = self.c.recvPlist()
        if not StartService or StartService.get("Error"):
            print StartService
            raise StartServiceError
        return PlistService(StartService.get("Port"))

    def startServiceWithEscrowBag(self, name, escrowBag = None):
        if not self.paired:
            print "NotPaired"
            raise NotPairedError
        
        if (not escrowBag):
            escrowBag = self.record['EscrowBag']
        

        self.c.sendPlist({"Label": self.label, "Request": "StartService", "Service": name, 'EscrowBag':escrowBag})
        StartService = self.c.recvPlist()
        if not StartService or StartService.get("Error"):
            print StartService
            raise StartServiceError
        return PlistService(StartService.get("Port"))



if __name__ == "__main__":
    l = LockdownClient()
    if l:
        n = writeHomeFile(HOMEFOLDER, "%s_infos.plist" % l.udid, plistlib.writePlistToString(l.allValues))
        print "Wrote infos to %s" % n
    else:
        print "Unable to connect to device"
