#!/usr/bin/env python3

import logging

from pymobiledevice3.lockdown import LockdownClient

CHUNK_SIZE = 4096
TIME_FORMAT = '%H:%M:%S'
SYSLOG_LINE_SPLITTER = '\n\x00'


class SyslogService(object):
    """
    View system logs
    """

    def __init__(self, lockdown=None, udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        self.c = self.lockdown.start_service('com.apple.syslog_relay')

    def watch(self):
        buf = ''
        while True:
            # read in chunks till we have at least one syslog line
            chunk = self.c.recv(CHUNK_SIZE).decode('utf-8')
            buf += chunk

            # SYSLOG_LINE_SPLITTER is used to split each syslog line
            if SYSLOG_LINE_SPLITTER in buf:
                lines = buf.split(SYSLOG_LINE_SPLITTER)

                # handle partial last lines
                if not buf.endswith(SYSLOG_LINE_SPLITTER):
                    buf = lines[-1]
                    lines = lines[:-1]

                for line in lines:
                    if len(line) == 0:
                        continue

                    yield line
