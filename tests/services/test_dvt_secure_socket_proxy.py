# -*- coding:utf-8 -*-

from pymobiledevice3.services.dvt_secure_socket_proxy import DvtSecureSocketProxyService


def test_system_information(lockdown):
    """
    Test getting system information.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        system_info = dvt.system_information()
    assert '_deviceDescription' in system_info and system_info['_deviceDescription'].startswith('Build Version')


def test_launch(lockdown):
    """
    Test launching a process.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        pid = dvt.launch('com.apple.mobilesafari')
        assert pid
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        for process in dvt.proclist():
            if pid == process['pid']:
                assert process['name'] == 'MobileSafari'
