from pymobiledevice3.exceptions import ArbitrationError, DeviceAlreadyInUseError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService


class DtDeviceArbitration(LockdownService):
    SERVICE_NAME = 'com.apple.dt.devicearbitration'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, is_developer_service=True)

    @property
    def version(self) -> dict:
        return self.service.send_recv_plist({'command': 'version'})

    def check_in(self, hostname: str, force: bool = False):
        request = {'command': 'check-in', 'hostname': hostname}
        if force:
            request['command'] = 'force-check-in'
        response = self.service.send_recv_plist(request)
        if response.get('result') != 'success':
            raise DeviceAlreadyInUseError(response)

    def check_out(self):
        request = {'command': 'check-out'}
        response = self.service.send_recv_plist(request)
        if response.get('result') != 'success':
            raise ArbitrationError(f'failed with: {response}')
