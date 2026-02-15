import asyncio
from datetime import datetime

import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.syslog import SyslogService

SYSLOG_TIME_FORMAT = "%Y %b %d %H:%M:%S"


def extract_log_time(log_line: str) -> datetime:
    """
    Extract the time from a syslog log line.
    :param log_line: Line to extract time from.
    :return: Parsed datetime object.
    """
    timestamp_end = log_line.find(":") + len("MM:SS")
    timestamp = log_line[: timestamp_end + 1]
    return datetime.strptime(f"{datetime.now().year} {timestamp}", SYSLOG_TIME_FORMAT)


@pytest.mark.asyncio
async def test_logs_watching_time(lockdown: LockdownClient) -> None:
    """
    Test that after watching logs 2 seconds after result in logs with later timestamp.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    async with SyslogService(lockdown) as syslog_service:
        first_log = await syslog_service.watch().__anext__()
        await asyncio.sleep(2)

    async with SyslogService(lockdown) as syslog_service:
        second_log = await syslog_service.watch().__anext__()
        assert extract_log_time(first_log) < extract_log_time(second_log)
