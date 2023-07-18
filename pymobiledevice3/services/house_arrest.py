from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService, AfcShell


class HouseArrestService(AfcService):
    SERVICE_NAME = 'com.apple.mobile.house_arrest'
    RSD_SERVICE_NAME = 'com.apple.mobile.house_arrest.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

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
            AfcShell(self.lockdown, afc_service=self).cmdloop()
