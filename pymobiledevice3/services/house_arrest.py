from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService, AfcShell

VEND_CONTAINER = 'VendContainer'
VEND_DOCUMENTS = 'VendDocuments'

DOCUMENTS_ROOT = '/Documents'


class HouseArrestService(AfcService):
    SERVICE_NAME = 'com.apple.mobile.house_arrest'
    RSD_SERVICE_NAME = 'com.apple.mobile.house_arrest.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def send_command(self, bundle_id: str, cmd: str = 'VendContainer') -> None:
        response = self.service.send_recv_plist({'Command': cmd, 'Identifier': bundle_id})
        error = response.get('Error')
        if error:
            raise PyMobileDevice3Exception(error)

    def shell(self, bundle_id: str, documents_only: bool = False) -> None:
        if documents_only:
            cmd = VEND_DOCUMENTS
        else:
            cmd = VEND_CONTAINER
        self.send_command(bundle_id, cmd)
        afc_shell = AfcShell(self.lockdown, afc_service=self)
        if documents_only:
            afc_shell.do_cd(DOCUMENTS_ROOT)
        afc_shell.cmdloop()
