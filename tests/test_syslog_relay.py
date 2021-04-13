# -*- coding:utf-8 -*-

import time
from datetime import datetime

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.syslog_service import SyslogService

SYSLOG_TIME_FORMAT = '%b %d %H:%M:%S'


def extract_log_time(log_line: str) -> datetime:
    """
    Extract the time from a syslog log line.
    :param log_line: Line to extract time from.
    :return: Parsed datetime object.
    """
    timestamp_end = log_line.find(':') + len('MM:SS')
    return datetime.strptime(log_line[:timestamp_end + 1], SYSLOG_TIME_FORMAT)


def test_logs_watching_time():
    """
    Test that after watching logs 1 second after result in logs with later timestamp.
    """
    lockdown = LockdownClient()
    syslog_service = SyslogService(lockdown)
    first_log = next(syslog_service.watch())
    time.sleep(1)
    second_log = next(syslog_service.watch())
    assert extract_log_time(first_log) < extract_log_time(second_log)
