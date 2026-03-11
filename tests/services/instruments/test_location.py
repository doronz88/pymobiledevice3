import pytest

from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation


async def test_set_location(service_provider) -> None:
    """
    Test set location.
    """
    # set to liberty island
    try:
        async with DvtProvider(service_provider) as dvt, LocationSimulation(dvt) as location_simulation:
            await location_simulation.set(40.690008, -74.045843)
    except InvalidServiceError:
        pytest.skip("Skipping location simulation test since DVT provider service isn't accessible")


async def test_clear_location(service_provider) -> None:
    """
    Test clear location simulation
    """
    # set to liberty island
    try:
        async with DvtProvider(service_provider) as dvt, LocationSimulation(dvt) as location_simulation:
            await location_simulation.clear()
    except InvalidServiceError:
        pytest.skip("Skipping location simulation test since DVT provider service isn't accessible")
