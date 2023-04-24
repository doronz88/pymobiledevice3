import time
from ssl import SSLEOFError

from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

PASSWORD = '1234'


def change_password(lockdown, old: str = '', new: str = '') -> None:
    while True:
        try:
            with Mobilebackup2Service(lockdown) as service:
                service.change_password(old=old, new=new)
        except (SSLEOFError, ConnectionAbortedError):
            # after large backups, the device requires time to recover
            time.sleep(1)
        else:
            break


def test_backup(lockdown, tmp_path):
    with Mobilebackup2Service(lockdown) as service:
        service.backup(full=True, backup_directory=tmp_path)


def test_encrypted_backup(lockdown, tmp_path):
    change_password(lockdown, new=PASSWORD)
    with Mobilebackup2Service(lockdown) as service:
        service.backup(full=True, backup_directory=tmp_path)
    change_password(lockdown, old=PASSWORD)
