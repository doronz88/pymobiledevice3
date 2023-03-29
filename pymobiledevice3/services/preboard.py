#!/usr/bin/env python3


from typing import Mapping

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class PreboardService(BaseService):
    SERVICE_NAME = 'com.apple.preboardservice_v2'

    def __init__(self, lockdown: LockdownClient) -> None:
        super().__init__(lockdown, self.SERVICE_NAME)

    def create_stashbag(self, manifest: Mapping) -> Mapping:
        return self.service.send_recv_plist({'Command': 'CreateStashbag', 'Manifest': manifest})

    def commit(self, manifest: Mapping) -> Mapping:
        return self.service.send_recv_plist({'Command': 'CommitStashbag', 'Manifest': manifest})
