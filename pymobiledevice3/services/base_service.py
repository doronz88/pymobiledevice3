import logging

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.service_connection import ServiceConnection


class BaseService:
    def __init__(self, lockdown: LockdownClient, service_name: str, is_developer_service=False,
                 service: ServiceConnection = None):
        """
        :param lockdown: lockdown connection
        :param service_name: wrapped service name - will attempt
        :param is_developer_service: should DeveloperDiskImage be mounted before
        :param service: an established service connection object. If none, will attempt connecting to service_name
        """

        if not service:
            start_service = lockdown.start_developer_service if is_developer_service else lockdown.start_service
            service = start_service(service_name)

        self.service_name = service_name
        self.lockdown = lockdown
        self.service = service
        self.logger = logging.getLogger(self.__module__)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.service.close()
