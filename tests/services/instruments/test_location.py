from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation


async def test_set_location(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test set location.
    """
    # set to liberty island
    await LocationSimulation(dvt).set(40.690008, -74.045843)


async def test_clear_location(dvt: DvtSecureSocketProxyService) -> None:
    """
    Test clear location simulation
    """
    # set to liberty island
    await LocationSimulation(dvt).clear()
