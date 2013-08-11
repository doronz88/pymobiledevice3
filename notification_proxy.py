from lockdown import LockdownClient
from pprint import pprint
import plistlib


class NPClient(object):
    def __init__(self, lockdown=None, serviceName="com.apple.mobile.notification_proxy"):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

        self.service = self.lockdown.startService(serviceName)
        self.packet_num = 0

    def stop_session(self):
        print "Disconecting..."
        self.service.close()

    def post_notification(self, notification):
        #Sends a notification to the device's notification_proxy.
        self.service.sendPlist({"Command": "PostNotification",#}
                                "Name": notification})
        res = self.service.recvPlist()
        pprint(res)
        return res

    def observe_notification(self, notification):
        #Tells the device to send a notification on the specified event
        self.service.sendPlist({"Command": "ObserveNotification",#}
                                "Name": notification})
        res = self.service.recvPlist()
        pprint(res)
        return res


    def get_notification(self, notification):
        #Checks if a notification has been sent by the device
        res = self.service.recvPlist()
        pprint(res)
        return res  


if __name__ == "__main__":
    lockdown = LockdownClient()
    ProductVersion = lockdown.getValue("", "ProductVersion")
    assert ProductVersion[0] >= "4"

    np = NPClient()
    np.get_notification()
 
