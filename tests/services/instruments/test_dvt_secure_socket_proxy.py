import time

import pytest

from pymobiledevice3.exceptions import DvtDirListError, UnrecognizedSelectorError
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl


def get_process_data(dvt, name: str):
    processes = DeviceInfo(dvt).proclist()
    return [process for process in processes if process['name'] == name][0]


def test_ls(dvt):
    """
    Test listing a directory.
    """
    ls = set(DeviceInfo(dvt).ls('/'))
    assert {'usr', 'bin', 'etc', 'var', 'private', 'Applications', 'Developer'} <= ls


def test_ls_failure(dvt):
    """
    Test listing a directory.
    """
    with pytest.raises(DvtDirListError):
        DeviceInfo(dvt).ls('Directory that does not exist')


def test_proclist(dvt):
    """
    Test listing processes.
    """
    lockdownd = get_process_data(dvt, 'lockdownd')
    assert lockdownd['realAppName'] == '/usr/libexec/lockdownd'
    assert not lockdownd['isApplication']


def test_applist(dvt):
    """
    Test listing applications.
    """
    apps = ApplicationListing(dvt).applist()
    safari = [app for app in apps if app['DisplayName'] == 'StocksWidget'][0]
    assert safari['CFBundleIdentifier'] == 'com.apple.stocks.widget'
    assert safari['Restricted'] == 1
    assert safari['Type'] == 'PluginKit'


def test_memlimitoff(dvt):
    """
    Test disabling memory limit.
    """
    ProcessControl(dvt).disable_memory_limit_for_pid(get_process_data(dvt, 'SpringBoard')['pid'])


def test_kill(dvt):
    """
    Test killing a process.
    """
    aggregated = get_process_data(dvt, 'SpringBoard')
    ProcessControl(dvt).kill(aggregated['pid'])
    # give the os some time to start the process again
    time.sleep(3)
    aggregated_after_kill = get_process_data(dvt, 'SpringBoard')
    if 'startDate' in aggregated:
        assert aggregated['startDate'] < aggregated_after_kill['startDate']


def test_launch(dvt):
    """
    Test launching a process.
    """
    pid = ProcessControl(dvt).launch('com.apple.mobilesafari')
    assert pid
    for process in DeviceInfo(dvt).proclist():
        if pid == process['pid']:
            assert process['name'] == 'MobileSafari'


def test_system_information(dvt):
    """
    Test getting system information.
    """
    try:
        system_info = DeviceInfo(dvt).system_information()
    except UnrecognizedSelectorError:
        pytest.skip('device doesn\'t support this method')
    assert '_deviceDescription' in system_info and system_info['_deviceDescription'].startswith('Build Version')


def test_hardware_information(dvt):
    """
    Test getting hardware information.
    """
    hardware_info = DeviceInfo(dvt).hardware_information()
    assert hardware_info['numberOfCpus'] > 0


def test_network_information(dvt):
    """
    Test getting network information.
    """
    network_info = DeviceInfo(dvt).network_information()
    assert network_info['lo0'] == 'Loopback'
