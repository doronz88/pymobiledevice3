import asyncio
from typing import Optional

import pytest

from pymobiledevice3.exceptions import DvtDirListError, UnrecognizedSelectorError
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl


async def get_process_data(device_info: DeviceInfo, name: str):
    processes = await device_info.proclist()
    return next(process for process in processes if process["name"] == name)


@pytest.mark.asyncio
async def test_ls(dvt) -> None:
    """
    Test listing a directory.
    """
    async with DeviceInfo(dvt) as device_info:
        ls = set(await device_info.ls("/"))
    assert {"usr", "bin", "etc", "var", "private", "Applications", "Developer"} <= ls


@pytest.mark.asyncio
async def test_ls_failure(dvt) -> None:
    """
    Test listing a directory.
    """
    async with DeviceInfo(dvt) as device_info:
        with pytest.raises(DvtDirListError):
            await device_info.ls("Directory that does not exist")


@pytest.mark.asyncio
async def test_proclist(dvt) -> None:
    """
    Test listing processes.
    """
    async with DeviceInfo(dvt) as device_info:
        lockdownd = await get_process_data(device_info, "lockdownd")
    assert lockdownd["realAppName"] == "/usr/libexec/lockdownd"
    assert not lockdownd["isApplication"]


@pytest.mark.asyncio
async def test_applist(dvt) -> None:
    """
    Test listing applications.
    """
    async with ApplicationListing(dvt) as application_listing:
        apps = await application_listing.applist()
    safari = next(app for app in apps if app["DisplayName"] == "StocksWidget")
    assert safari["CFBundleIdentifier"] == "com.apple.stocks.widget"
    assert safari["Restricted"] == 1
    assert safari["Type"] == "PluginKit"


@pytest.mark.asyncio
async def test_memlimitoff(dvt) -> None:
    """
    Test disabling memory limit.
    """
    async with DeviceInfo(dvt) as device_info:
        process = await get_process_data(device_info, "SpringBoard")
    async with ProcessControl(dvt) as process_control:
        await process_control.disable_memory_limit_for_pid(process["pid"])


@pytest.mark.asyncio
async def test_kill(dvt, service_provider) -> None:
    """
    Test killing a process.
    """
    async with DeviceInfo(dvt) as device_info:
        aggregated = await get_process_data(device_info, "SpringBoard")
    async with ProcessControl(dvt) as process_control:
        await process_control.kill(aggregated["pid"])
    # give the os some time to start the process again
    await asyncio.sleep(3)
    async with type(dvt)(service_provider) as second_dvt, DeviceInfo(second_dvt) as device_info:
        aggregated_after_kill = await get_process_data(device_info, "SpringBoard")
    if "startDate" in aggregated:
        assert aggregated["startDate"] < aggregated_after_kill["startDate"]


@pytest.mark.asyncio
async def test_launch(dvt, service_provider) -> None:
    """
    Test launching a process.
    """
    async with ProcessControl(dvt) as process_control:
        pid = await process_control.launch("com.apple.mobilesafari")
    assert pid
    async with type(dvt)(service_provider) as second_dvt, DeviceInfo(second_dvt) as device_info:
        processes = await device_info.proclist()
    for process in processes:
        if pid == process["pid"]:
            assert process["name"] == "MobileSafari"


@pytest.mark.asyncio
@pytest.mark.skip("this test is brittle, yet it was a quick way to test callbacks")
async def test_observe(dvt, service_provider) -> None:
    """
    Test observing a launched process and receiving its termination callback.
    """
    process_terminated: asyncio.Future[tuple[int, int, Optional[int]]] = asyncio.get_event_loop().create_future()
    signature_received: asyncio.Future[dict] = asyncio.get_event_loop().create_future()

    async def on_process_terminated(pid: int, exit_code: int, crashing_signal: Optional[int]) -> None:
        process_terminated.set_result((pid, exit_code, crashing_signal))

    async def on_tracking_signature(obj: dict) -> None:
        if not signature_received.done():
            signature_received.set_result(obj)

    async with ProcessControl(dvt) as process_control, DeviceInfo(dvt) as device_info:
        process_control.service._on_process_terminated = on_process_terminated

        # manually add a @dtx_on_invoke
        device_info.service._on_tracking_signature = on_tracking_signature
        device_info.service._dtx_dispatch["trackProcess:"] = "_on_tracking_signature"
        device_info.service._channel.on_invoke = device_info.service.__on_dispatch__

        pid = await process_control.launch("com.apple.mobilesafari")
        assert pid
        await process_control.service.startObservingPid_(pid)
        x = await device_info.service.symbolicator_signature_for_pid_tracking_selector_(pid, "trackProcess:")
        assert x is None or isinstance(x, bytes), (
            f"Expected symbolicator signature to be bytes or None, got {type(x).__name__}"
        )
        obj = await asyncio.wait_for(signature_received, 3)
        await process_control.kill(pid)
        assert obj is not None, "Expected a tracking object but got None"
        assert type(obj) is dict, f"Expected a tracking object of type dict but got {type(obj).__name__}"
        assert "pid" in obj, "Expected 'pid' key in tracking object"
        assert "signature" in obj, "Expected 'signature' key in tracking object"
        assert isinstance(obj["signature"], bytes), (
            f"Expected 'signature' value to be bytes but got {type(obj['signature']).__name__}"
        )
        terminated_pid, _exit_code, _crashing_signal = await asyncio.wait_for(process_terminated, 1)
        assert terminated_pid == pid


@pytest.mark.asyncio
async def test_system_information(dvt) -> None:
    """
    Test getting system information.
    """
    async with DeviceInfo(dvt) as device_info:
        try:
            system_info = await device_info.system_information()
        except UnrecognizedSelectorError:
            pytest.skip("device doesn't support this method")
    assert "_deviceDescription" in system_info and system_info["_deviceDescription"].startswith("Build Version")


@pytest.mark.asyncio
async def test_hardware_information(dvt) -> None:
    """
    Test getting hardware information.
    """
    async with DeviceInfo(dvt) as device_info:
        hardware_info = await device_info.hardware_information()
    assert hardware_info["numberOfCpus"] > 0


@pytest.mark.asyncio
async def test_network_information(dvt) -> None:
    """
    Test getting network information.
    """
    async with DeviceInfo(dvt) as device_info:
        network_info = await device_info.network_information()
    assert network_info["lo0"] == "Loopback"
