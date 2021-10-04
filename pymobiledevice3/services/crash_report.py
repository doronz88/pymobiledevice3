import logging
from pathlib import Path

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService


class CrashReports:
    COPY_MOBILE_NAME = 'com.apple.crashreportcopymobile'
    CRASH_MOVER_NAME = 'com.apple.crashreportmover'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.afc = AfcService(lockdown, service_name=self.COPY_MOBILE_NAME)

    def clear(self):
        """
        Clear all crash reports.
        """
        self.afc.rm('/', force=True)

    def ls(self, path: str = '/', depth: int = 1):
        """
        List file and folder in the crash reports directory.
        :param path: Path to list, relative to the crash reports directory.
        :param depth: Listing depth, -1 to list infinite.
        :return: List of files listed.
        """
        return list(self.afc.dirlist(path, depth))[1:]

    def pull(self, out: str, entry: str = '/', erase: bool = False):
        """
        Pull crash reports from the device.
        :param out: Directory to pull crash reports to.
        :param entry: File or Folder to pull.
        :param erase: Whether to erase the original file from the CrashReports directory.
        """
        Path(out).mkdir(exist_ok=True, parents=True)

        def log(src, dst):
            logging.info(f'{src} --> {dst}')

        self.afc.pull(entry, out, callback=log)

        if erase:
            self.afc.rm(entry)

    def flush(self):
        """ Trigger com.apple.crashreportmover to flush all products into CrashReports directory """
        ack = b'ping\x00'
        assert ack == self.lockdown.start_service(self.CRASH_MOVER_NAME).recvall(len(ack))
