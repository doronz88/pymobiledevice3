#!/usr/bin/env python3

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class PreboardService(LockdownService):
    """
    Manage preboard stashbags on the device via the ``com.apple.preboardservice_v2`` lockdown service.

    A stashbag holds key material that allows the device to unlock data-protection classes during an
    unattended reboot (e.g. before the user enters their passcode). This service creates and commits
    such stashbags. This is a lockdown service and is used as an async context manager; the
    RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.
    """

    RSD_SERVICE_NAME = "com.apple.preboardservice_v2.shim.remote"
    SERVICE_NAME = "com.apple.preboardservice_v2"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def create_stashbag(self, manifest):
        """
        Create a stashbag on the device.

        Sends a ``CreateStashbag`` command with the given manifest.

        :param manifest: the stashbag manifest describing the key material to stash.
        :returns: the device's response to the command.
        """
        return await self.service.send_recv_plist({"Command": "CreateStashbag", "Manifest": manifest})

    async def commit(self, manifest):
        """
        Commit a previously created stashbag on the device.

        Sends a ``CommitStashbag`` command with the given manifest.

        :param manifest: the stashbag manifest to commit.
        :returns: the device's response to the command.
        """
        return await self.service.send_recv_plist({"Command": "CommitStashbag", "Manifest": manifest})
