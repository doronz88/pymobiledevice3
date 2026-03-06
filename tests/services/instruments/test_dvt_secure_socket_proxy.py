import asyncio

import pytest

from pymobiledevice3.exceptions import DvtDirListError, UnrecognizedSelectorError
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl


async def get_process_data(device_info: DeviceInfo, name: str):
    processes = await device_info.proclist()
    return next(process for process in processes if process["name"] == name)


@pytest.mark.asyncio
async def test_ls(service_provider) -> None:
    """
    Test listing a directory.
    """
    async with DvtProvider(service_provider) as dvt:
        ls = set(await DeviceInfo(dvt).ls("/"))
    assert {"usr", "bin", "etc", "var", "private", "Applications", "Developer"} <= ls


@pytest.mark.asyncio
async def test_ls_failure(service_provider) -> None:
    """
    Test listing a directory.
    """
    async with DvtProvider(service_provider) as dvt:
        with pytest.raises(DvtDirListError):
            await DeviceInfo(dvt).ls("Directory that does not exist")


@pytest.mark.asyncio
async def test_proclist(service_provider) -> None:
    """
    Test listing processes.
    """
    async with DvtProvider(service_provider) as dvt:
        lockdownd = await get_process_data(DeviceInfo(dvt), "lockdownd")
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
async def test_memlimitoff(dvt: DvtSecureSocketProxyService, service_provider) -> None:
    """
    Test disabling memory limit.
    """
    async with DvtProvider(service_provider) as dvt_provider:
        process = await get_process_data(DeviceInfo(dvt_provider), "SpringBoard")
    await ProcessControl(dvt).disable_memory_limit_for_pid(process["pid"])


@pytest.mark.asyncio
async def test_kill(dvt: DvtSecureSocketProxyService, service_provider) -> None:
    """
    Test killing a process.
    """
    async with DvtProvider(service_provider) as dvt_provider:
        aggregated = await get_process_data(DeviceInfo(dvt_provider), "SpringBoard")
    await ProcessControl(dvt).kill(aggregated["pid"])
    # give the os some time to start the process again
    await asyncio.sleep(3)
    async with DvtProvider(service_provider) as dvt_provider:
        aggregated_after_kill = await get_process_data(DeviceInfo(dvt_provider), "SpringBoard")
    if "startDate" in aggregated:
        assert aggregated["startDate"] < aggregated_after_kill["startDate"]


@pytest.mark.asyncio
async def test_launch(dvt: DvtSecureSocketProxyService, service_provider) -> None:
    """
    Test launching a process.
    """
    pid = await ProcessControl(dvt).launch("com.apple.mobilesafari")
    assert pid
    async with DvtProvider(service_provider) as dvt_provider:
        processes = await DeviceInfo(dvt_provider).proclist()
    for process in processes:
        if pid == process["pid"]:
            assert process["name"] == "MobileSafari"


@pytest.mark.asyncio
async def test_system_information(service_provider) -> None:
    """
    Test getting system information.
    """
    async with DvtProvider(service_provider) as dvt:
        try:
            system_info = await DeviceInfo(dvt).system_information()
        except UnrecognizedSelectorError:
            pytest.skip("device doesn't support this method")
    assert "_deviceDescription" in system_info and system_info["_deviceDescription"].startswith("Build Version")


@pytest.mark.asyncio
async def test_hardware_information(service_provider) -> None:
    """
    Test getting hardware information.
    """
    async with DvtProvider(service_provider) as dvt:
        hardware_info = await DeviceInfo(dvt).hardware_information()
    assert hardware_info["numberOfCpus"] > 0


@pytest.mark.asyncio
async def test_network_information(service_provider) -> None:
    """
    Test getting network information.
    """
    async with DvtProvider(service_provider) as dvt:
        network_info = await DeviceInfo(dvt).network_information()
    assert network_info["lo0"] == "Loopback"
