import logging

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.afc import AFCClient, AFCShell


class HouseArrestService(AFCClient):
    def __init__(self, lockdown=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient()
        service_name = "com.apple.mobile.house_arrest"
        super(HouseArrestService, self).__init__(self.lockdown, service_name)

    def send_command(self, applicationId, cmd="VendContainer"):
        self.service.send_plist({"Command": cmd, "Identifier": applicationId})
        res = self.service.recv_plist()
        if res.get("Error"):
            self.logger.error("%s: %s", applicationId, res.get("Error"))
            return False
        else:
            return True

    def shell(self, application_id, cmd="VendContainer"):
        res = self.send_command(application_id, cmd)
        if res:
            AFCShell(client=self).cmdloop()
