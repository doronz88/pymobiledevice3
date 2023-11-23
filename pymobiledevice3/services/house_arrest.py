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

    def __init__(self, lockdown: LockdownServiceProvider, bundle_id: str, documents_only: bool = False):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)
        if documents_only:
            cmd = VEND_DOCUMENTS
        else:
            cmd = VEND_CONTAINER
        self.documents_only = documents_only
        self.send_command(bundle_id, cmd)

    def send_command(self, bundle_id: str, cmd: str = 'VendContainer') -> None:
        response = self.service.send_recv_plist({'Command': cmd, 'Identifier': bundle_id})
        error = response.get('Error')
        if error:
            raise PyMobileDevice3Exception(error)

    def shell(self) -> None:
        AfcShell.create(self.lockdown, service=self, auto_cd=DOCUMENTS_ROOT if self.documents_only else '/')
