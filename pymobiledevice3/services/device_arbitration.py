from pymobiledevice3.exceptions import ArbitrationError, DeviceAlreadyInUseError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService


class DtDeviceArbitration(LockdownService):
    """
    Claim and release exclusive use of a device via the ``com.apple.dt.devicearbitration`` service.

    Device arbitration lets a host check a device in (claiming it, optionally forcibly) so other
    hosts know it is in use, and check it back out when done. This is a developer lockdown service
    (it requires the DeveloperDiskImage to be mounted) and is used as an async context manager.
    """

    SERVICE_NAME = "com.apple.dt.devicearbitration"

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, is_developer_service=True)

    async def _send_recv(self, request: dict) -> dict:
        return await self.service.send_recv_plist(request)

    async def version(self) -> dict:
        """
        Query the arbitration service version.

        Sends the ``version`` command.

        :returns: the device's version response.
        """
        return await self._send_recv({"command": "version"})

    async def check_in(self, hostname: str, force: bool = False):
        """
        Claim the device for the given host.

        Sends a ``check-in`` command tagging the device with ``hostname``. When ``force`` is True,
        a ``force-check-in`` command is sent instead, taking the device even if another host holds it.

        :param hostname: identifier of the host claiming the device.
        :param force: when True, forcibly claim the device even if it is already in use.
        :raises DeviceAlreadyInUseError: if the device is already checked in by another host
            (and ``force`` is not used).
        """
        request = {"command": "check-in", "hostname": hostname}
        if force:
            request["command"] = "force-check-in"
        response = await self._send_recv(request)
        if response.get("result") != "success":
            raise DeviceAlreadyInUseError(response)

    async def check_out(self):
        """
        Release a previously claimed device.

        Sends the ``check-out`` command.

        :raises ArbitrationError: if the device does not report success.
        """
        request = {"command": "check-out"}
        response = await self._send_recv(request)
        if response.get("result") != "success":
            raise ArbitrationError(f"failed with: {response}")
