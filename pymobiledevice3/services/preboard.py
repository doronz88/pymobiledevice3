#!/usr/bin/env python3
import logging

from pymobiledevice3.lockdown import LockdownClient


class PreboardService(object):
    SERVICE_NAME = 'com.apple.preboardservice_v2'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.c = self.lockdown.start_service(self.SERVICE_NAME)

    def create_stashbag(self, manifest):
        return self.c.send_recv_plist({'Command': 'CreateStashbag', 'Manifest': manifest})

    def commit(self, manifest):
        return self.c.send_recv_plist({'Command': 'CommitStashbag', 'Manifest': manifest})
