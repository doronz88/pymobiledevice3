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

from pymobiledevice.lockdown import LockdownClient
from pprint import pprint
import time
from six.moves import _thread

# NP Client to device Notifications (post_notification) 
NP_SYNC_WILL_START           = "com.apple.itunes-mobdev.syncWillStart"
NP_SYNC_DID_START            = "com.apple.itunes-mobdev.syncDidStart"
NP_SYNC_DID_FINISH           = "com.apple.itunes-mobdev.syncDidFinish"
NP_SYNC_LOCK_REQUEST         = "com.apple.itunes-mobdev.syncLockRequest"

# Device to NP Client Notifications (get_notification)
NP_SYNC_CANCEL_REQUEST       = "com.apple.itunes-client.syncCancelRequest"
NP_SYNC_SUSPEND_REQUEST      = "com.apple.itunes-client.syncSuspendRequest"
NP_SYNC_RESUME_REQUEST       = "com.apple.itunes-client.syncResumeRequest"
NP_PHONE_NUMBER_CHANGED      = "com.apple.mobile.lockdown.phone_number_changed"
NP_DEVICE_NAME_CHANGED       = "com.apple.mobile.lockdown.device_name_changed"
NP_TIMEZONE_CHANGED          = "com.apple.mobile.lockdown.timezone_changed"
NP_TRUSTED_HOST_ATTACHED     = "com.apple.mobile.lockdown.trusted_host_attached"
NP_HOST_DETACHED             = "com.apple.mobile.lockdown.host_detached"
NP_HOST_ATTACHED             = "com.apple.mobile.lockdown.host_attached"
NP_REGISTRATION_FAILED       = "com.apple.mobile.lockdown.registration_failed"
NP_ACTIVATION_STATE          = "com.apple.mobile.lockdown.activation_state"
NP_BRICK_STATE               = "com.apple.mobile.lockdown.brick_state"
NP_DISK_USAGE_CHANGED        = "com.apple.mobile.lockdown.disk_usage_changed"
NP_DS_DOMAIN_CHANGED         = "com.apple.mobile.data_sync.domain_changed"
NP_BACKUP_DOMAIN_CHANGED     = "com.apple.mobile.backup.domain_changed"
NP_APP_INSTALLED             = "com.apple.mobile.application_installed"
NP_APP_UNINSTALLED           = "com.apple.mobile.application_uninstalled"
NP_DEV_IMAGE_MOUNTED         = "com.apple.mobile.developer_image_mounted"
NP_ATTEMPTACTIVATION         = "com.apple.springboard.attemptactivation"
NP_ITDBPREP_DID_END          = "com.apple.itdbprep.notification.didEnd"
NP_LANGUAGE_CHANGED          = "com.apple.language.changed"
NP_ADDRESS_BOOK_PREF_CHANGED = "com.apple.AddressBook.PreferenceChanged"


class NPClient(object):
    def __init__(self, lockdown=None, serviceName="com.apple.mobile.notification_proxy"):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()
        self.service = self.lockdown.startService(serviceName)


    def stop_session(self):
        print("Disconecting...")
        self.service.close()


    def post_notification(self, notification):
        #Sends a notification to the device's notification_proxy.
        
        self.service.sendPlist({"Command": "PostNotification",
                                "Name": notification})

        self.service.sendPlist({"Command": "Shutdown"})
        res = self.service.recvPlist()
        pprint(res)
        if res:
            if res.get("Command") == "ProxyDeath":
                return res.get("Command")
            else:
                print("Got unknown NotificationProxy command %s" % res.get("Command"))
                pprint(res)
        return None


    def observe_notification(self, notification):
        #Tells the device to send a notification on the specified event
        
        print("Observing %s" % notification)
        self.service.sendPlist({"Command": "ObserveNotification",
                                "Name": notification})


    def get_notification(self, notification):
        #Checks if a notification has been sent by the device
        
        res = self.service.recvPlist()
        if res:
            if res.get("Command") == "RelayNotification":
                if res.get("Name"):
                    return res.get("Name")
            
            elif res.get("Command") == "ProxyDeath":
                    print("NotificationProxy died!")
            else:
                print("Got unknown NotificationProxy command %s" % res.get("Command"))
                pprint(res)
        return None  


    def notifier(self, name, args=None):

        if args == None:
            return None

        self.observe_notification(args.get("notification"))
        
        while args.get("running") == True:
            np_name = self.get_notification(args.get("notification"))
            if np_name:
                userdata = args.get("userdata")
                try:
                    thread.start_new_thread( args.get("callback") , (np_name, userdata, ) )
                except:
                    print("Error: unable to start thread")


    def subscribe(self, notification, cb, data=None):

        np_data = { 
            "running": True,
            "notification": notification,
            "callback": cb,
            "userdata": data,
        }

        try:
            import threading
            _thread.start_new_thread( self.notifier, ("NotificationProxyNotifier_"+notification, np_data, ) )
        except:
            print("Error: unable to start thread")

        while(1):
            time.sleep(1)



def cb_test(name,data=None):
    print("Got Notification >> %s" % name)
    print("Data:")
    pprint(data)


if __name__ == "__main__":
    np = NPClient()
    np.subscribe(NP_DEVICE_NAME_CHANGED, cb_test, data=None)
 
