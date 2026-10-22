from collections.abc import AsyncGenerator
from typing import Any

import pytest

from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.location_simulation import (
    LocationSimulation,
    LocationSimulationService,
)


@pytest.fixture
async def location_simulation(service_provider) -> AsyncGenerator[LocationSimulation, Any]:
    try:
        async with DvtProvider(service_provider) as dvt:
            if LocationSimulationService.IDENTIFIER not in (dvt.dtx.supported_identifiers or {}):
                # e.g. iOS 13, which simulates location through com.apple.dt.simulatelocation instead
                pytest.skip("The device offers no DVT location simulation")
            async with LocationSimulation(dvt) as location_simulation:
                yield location_simulation
    except InvalidServiceError:
        pytest.skip("Skipping location simulation test since DVT provider service isn't accessible")


async def test_set_location(location_simulation: LocationSimulation) -> None:
    """
    Test set location.
    """
    # set to liberty island
    await location_simulation.set(40.690008, -74.045843)


async def test_clear_location(location_simulation: LocationSimulation) -> None:
    """
    Test clear location simulation
    """
    await location_simulation.clear()
