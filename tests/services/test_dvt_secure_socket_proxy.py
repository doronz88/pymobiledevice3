import pytest

from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.exceptions import DvtDirListError
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl


def get_process_data(lockdown, name):
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        processes = DeviceInfo(dvt).proclist()
    return [process for process in processes if process['name'] == name][0]


def test_ls(lockdown):
    """
    Test listing a directory.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ls = set(DeviceInfo(dvt).ls('/'))
    assert {'usr', 'bin', 'etc', 'var', 'private', 'lib', 'Applications', 'Developer'} <= ls


def test_ls_failure(lockdown):
    """
    Test listing a directory.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with pytest.raises(DvtDirListError):
            DeviceInfo(dvt).ls('Directory that does not exist')


def test_proclist(lockdown):
    """
    Test listing processes.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    lockdownd = get_process_data(lockdown, 'lockdownd')
    assert lockdownd['realAppName'] == '/usr/libexec/lockdownd'
    assert not lockdownd['isApplication']


def test_applist(lockdown):
    """
    Test listing applications.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        apps = ApplicationListing(dvt).applist()

    safari = [app for app in apps if app['BundlePath'] == '/Applications/MobileSafari.app'][0]
    assert safari['DisplayName'] == 'Safari'
    assert safari['CFBundleIdentifier'] == 'com.apple.mobilesafari'
    assert safari['ExecutableName'] == 'MobileSafari'
    assert not safari['Placeholder']
    assert safari['Type'] == 'System'


def test_kill(lockdown):
    """
    Test killing a process.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    aggregated = get_process_data(lockdown, 'aggregated')

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ProcessControl(dvt).kill(aggregated['pid'])

    aggregated_after_kill = get_process_data(lockdown, 'aggregated')

    assert aggregated['startDate'] < aggregated_after_kill['startDate']


def test_launch(lockdown):
    """
    Test launching a process.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        pid = ProcessControl(dvt).launch('com.apple.mobilesafari')
        assert pid
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        for process in DeviceInfo(dvt).proclist():
            if pid == process['pid']:
                assert process['name'] == 'MobileSafari'


def test_system_information(lockdown):
    """
    Test getting system information.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        system_info = DeviceInfo(dvt).system_information()
    assert '_deviceDescription' in system_info and system_info['_deviceDescription'].startswith('Build Version')


def test_hardware_information(lockdown):
    """
    Test getting hardware information.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        hardware_info = DeviceInfo(dvt).hardware_information()
    assert hardware_info['numberOfCpus'] > 0


def test_network_information(lockdown):
    """
    Test getting network information.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        network_info = DeviceInfo(dvt).network_information()
    assert network_info['lo0'] == 'Loopback'
