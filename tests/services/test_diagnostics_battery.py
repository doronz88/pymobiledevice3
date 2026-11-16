from typing import Any, Optional

import pytest

from pymobiledevice3.services.diagnostics import BatteryInfo, DiagnosticsService


def _service(entries: dict[str, Optional[dict[str, Any]]]) -> tuple[DiagnosticsService, list[str]]:
    """Build a DiagnosticsService whose IORegistry answers come from ``entries``, keyed by class."""
    queried: list[str] = []

    async def ioregistry(
        plane: Optional[str] = None, name: Optional[str] = None, ioclass: str = ""
    ) -> Optional[dict[str, Any]]:
        queried.append(ioclass)
        return entries.get(ioclass)

    service = object.__new__(DiagnosticsService)
    service.ioregistry = ioregistry  # pyright: ignore[reportAttributeAccessIssue]
    return service, queried


@pytest.mark.asyncio
async def test_get_battery_keeps_power_source_temperature():
    service, queried = _service({
        "IOPMPowerSource": {"Temperature": 3010, "Voltage": 4123},
        "AppleSmartBatteryPack": {"BatteryData": {"Temperature": 2629}},
    })
    assert await service.get_battery() == {"Temperature": 3010, "Voltage": 4123}
    assert queried == ["IOPMPowerSource"]


@pytest.mark.asyncio
async def test_get_battery_fills_temperature_from_battery_pack():
    service, queried = _service({
        "IOPMPowerSource": {"Voltage": 4439},
        "AppleSmartBatteryPack": {"BatteryData": {"Temperature": 2629, "VirtualTemperature": 2619}},
    })
    assert await service.get_battery() == {"Voltage": 4439, "Temperature": 2629}
    assert queried == ["IOPMPowerSource", "AppleSmartBatteryPack"]


@pytest.mark.asyncio
@pytest.mark.parametrize("pack", [None, {}, {"BatteryData": {}}])
async def test_get_battery_without_any_temperature(pack):
    service, _ = _service({"IOPMPowerSource": {"Voltage": 4439}, "AppleSmartBatteryPack": pack})
    assert await service.get_battery() == {"Voltage": 4439}


@pytest.mark.asyncio
async def test_get_battery_without_power_source():
    service, queried = _service({})
    assert await service.get_battery() is None
    assert queried == ["IOPMPowerSource"]


@pytest.mark.asyncio
async def test_get_battery_info_from_newer_ios_layout():
    service, _ = _service({
        "IOPMPowerSource": {
            "Voltage": 4499,
            "InstantAmperage": 5,
            "CurrentCapacity": 100,
            "IsCharging": False,
            "ExternalConnected": True,
            "FullyCharged": True,
            "CycleCount": 1,
            "BatteryData": {"DesignCapacity": 4830, "FullChargeCapacity": 5021},
        },
        "AppleSmartBatteryPack": {"BatteryData": {"Temperature": 2669, "DesignCapacity": 1900}},
    })
    assert await service.get_battery_info() == BatteryInfo(
        temperature=26.69,
        voltage=4499,
        instant_amperage=5,
        level=100,
        is_charging=False,
        external_connected=True,
        fully_charged=True,
        cycle_count=1,
        design_capacity=4830,
        full_charge_capacity=5021,
    )


@pytest.mark.asyncio
async def test_get_battery_info_reads_top_level_capacities():
    service, _ = _service({"IOPMPowerSource": {"Temperature": 3010, "DesignCapacity": 3110}})
    assert await service.get_battery_info() == BatteryInfo(temperature=30.1, design_capacity=3110)


@pytest.mark.asyncio
async def test_get_battery_info_without_power_source():
    service, _ = _service({})
    assert await service.get_battery_info() is None


@pytest.mark.asyncio
async def test_get_battery_info_on_device(service_provider):
    async with DiagnosticsService(lockdown=service_provider) as diagnostics:
        info = await diagnostics.get_battery_info()
    if info is None:
        pytest.skip("device has no battery")
    assert info.temperature is not None and 0 < info.temperature < 60
    assert info.voltage is not None and 3000 < info.voltage < 5000
    assert info.level is not None and 0 <= info.level <= 100
    assert isinstance(info.is_charging, bool)
    assert info.design_capacity is not None and info.design_capacity > 0


@pytest.mark.asyncio
async def test_get_battery_reports_temperature_on_device(service_provider):
    async with DiagnosticsService(lockdown=service_provider) as diagnostics:
        battery = await diagnostics.get_battery()
    if battery is None:
        pytest.skip("device has no battery")
    assert isinstance(battery["Temperature"], int)
