from pymobiledevice3.exceptions import AppNotInstalledError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService, AfcShell

VEND_CONTAINER = "VendContainer"
VEND_DOCUMENTS = "VendDocuments"

DOCUMENTS_ROOT = "/Documents"


class HouseArrestService(AfcService):
    """
    AFC access to an installed application's container.

    house_arrest vends an application sandbox over the AFC protocol, allowing the
    container's files to be browsed and transferred. The container is selected by
    calling `send_command` (or via the `create` factory) with the target app's
    bundle id; ``documents_only`` controls whether the whole container or only its
    ``Documents`` subtree is exposed.

    Being an `AfcService`, instances may be used as an async context manager::

        async with await HouseArrestService.create(lockdown, bundle_id) as house_arrest:
            ...
    """

    SERVICE_NAME = "com.apple.mobile.house_arrest"
    RSD_SERVICE_NAME = "com.apple.mobile.house_arrest.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider, documents_only: bool = False):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)
        self.documents_only = documents_only

    @classmethod
    async def create(
        cls, lockdown: LockdownServiceProvider, bundle_id: str, documents_only: bool = False
    ) -> "HouseArrestService":
        """
        Create a service already vending the container of the given application.

        Instantiates the service and immediately issues the vend command, leaving the AFC
        session rooted at the application's container. On failure the service is closed
        before the error propagates.

        :param lockdown: service provider used to start the service and reach the device.
        :param bundle_id: bundle identifier of the application whose container to vend.
        :param documents_only: when True, vend only the container's ``Documents`` subtree
            (``VendDocuments``); otherwise vend the whole container (``VendContainer``).
        :returns: a connected `HouseArrestService` rooted at the application's container.
        :raises AppNotInstalledError: if no application with ``bundle_id`` is installed.
        :raises PyMobileDevice3Exception: if the device reports any other vend error.
        """
        service = cls(lockdown, documents_only=documents_only)
        cmd = VEND_DOCUMENTS if documents_only else VEND_CONTAINER
        try:
            await service.send_command(bundle_id, cmd)
        except PyMobileDevice3Exception:
            await service.close()
            raise
        return service

    async def send_command(self, bundle_id: str, cmd: str = "VendContainer") -> None:
        """
        Vend an application's container so subsequent AFC operations act on it.

        :param bundle_id: bundle identifier of the application to vend.
        :param cmd: vend command, either ``VendContainer`` (whole container) or
            ``VendDocuments`` (only the ``Documents`` subtree).
        :raises AppNotInstalledError: if no application with ``bundle_id`` is installed.
        :raises PyMobileDevice3Exception: if the device reports any other error.
        """
        response = await self.service.send_recv_plist({"Command": cmd, "Identifier": bundle_id})
        error = response.get("Error")
        if error:
            if error == "ApplicationLookupFailed":
                raise AppNotInstalledError(f"No app with bundle id {bundle_id} found")
            else:
                raise PyMobileDevice3Exception(error)

    def shell(self) -> None:
        """
        Launch an interactive AFC shell over the vended container.

        The shell starts in the container's ``Documents`` directory when the service was
        created with ``documents_only``, otherwise at the container root.
        """
        AfcShell.create(self.lockdown, service=self, auto_cd=DOCUMENTS_ROOT if self.documents_only else "/")
