import logging

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService, AfcShell


class HouseArrestService(AfcService):
    SERVICE_NAME = 'com.apple.mobile.house_arrest'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        service_name = self.SERVICE_NAME
        super(HouseArrestService, self).__init__(self.lockdown, service_name)

    def send_command(self, bundle_id, cmd='VendContainer'):
        self.service.send_plist({'Command': cmd, 'Identifier': bundle_id})
        res = self.service.recv_plist()
        if res.get('Error'):
            self.logger.error('%s: %s', bundle_id, res.get('Error'))
            return False
        else:
            return True

    def shell(self, application_id, cmd='VendContainer'):
        res = self.send_command(application_id, cmd)
        if res:
            AfcShell(self.lockdown).cmdloop()
