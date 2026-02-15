import asyncio

import pytest

from pymobiledevice3.exceptions import DvtDirListError, UnrecognizedSelectorError
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl


async def get_process_data(dvt: DvtSecureSocketProxyService, name: str):
    processes = await DeviceInfo(dvt).proclist()
    return next(process for process in processes if process["name"] == name)


@pytest.mark.asyncio
async def test_ls(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test listing a directory.
    """
    ls = set(await DeviceInfo(dvt).ls("/"))
    assert {"usr", "bin", "etc", "var", "private", "Applications", "Developer"} <= ls


@pytest.mark.asyncio
async def test_ls_failure(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test listing a directory.
    """
    with pytest.raises(DvtDirListError):
        await DeviceInfo(dvt).ls("Directory that does not exist")


@pytest.mark.asyncio
async def test_proclist(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test listing processes.
    """
    lockdownd = await get_process_data(dvt, "lockdownd")
    assert lockdownd["realAppName"] == "/usr/libexec/lockdownd"
    assert not lockdownd["isApplication"]


@pytest.mark.asyncio
async def test_applist(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test listing applications.
    """
    apps = await ApplicationListing(dvt).applist()
    safari = next(app for app in apps if app["DisplayName"] == "StocksWidget")
    assert safari["CFBundleIdentifier"] == "com.apple.stocks.widget"
    assert safari["Restricted"] == 1
    assert safari["Type"] == "PluginKit"


@pytest.mark.asyncio
async def test_memlimitoff(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test disabling memory limit.
    """
    process = await get_process_data(dvt, "SpringBoard")
    await ProcessControl(dvt).disable_memory_limit_for_pid(process["pid"])


@pytest.mark.asyncio
async def test_kill(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test killing a process.
    """
    aggregated = await get_process_data(dvt, "SpringBoard")
    await ProcessControl(dvt).kill(aggregated["pid"])
    # give the os some time to start the process again
    await asyncio.sleep(3)
    aggregated_after_kill = await get_process_data(dvt, "SpringBoard")
    if "startDate" in aggregated:
        assert aggregated["startDate"] < aggregated_after_kill["startDate"]


@pytest.mark.asyncio
async def test_launch(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test launching a process.
    """
    pid = await ProcessControl(dvt).launch("com.apple.mobilesafari")
    assert pid
    for process in await DeviceInfo(dvt).proclist():
        if pid == process["pid"]:
            assert process["name"] == "MobileSafari"


@pytest.mark.asyncio
async def test_system_information(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test getting system information.
    """
    try:
        system_info = await DeviceInfo(dvt).system_information()
    except UnrecognizedSelectorError:
        pytest.skip("device doesn't support this method")
    assert "_deviceDescription" in system_info and system_info["_deviceDescription"].startswith("Build Version")


@pytest.mark.asyncio
async def test_hardware_information(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test getting hardware information.
    """
    hardware_info = await DeviceInfo(dvt).hardware_information()
    assert hardware_info["numberOfCpus"] > 0


@pytest.mark.asyncio
async def test_network_information(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test getting network information.
    """
    network_info = await DeviceInfo(dvt).network_information()
    assert network_info["lo0"] == "Loopback"
