from pymobiledevice3.services.dvt.instruments.location_simulation import (
    LocationSimulation,
)


def test_set_location(dvt):
    """
    Test set location.
    """
    # set to liberty island
    LocationSimulation(dvt).set(40.690008, -74.045843)


def test_clear_location(dvt):
    """
    Test clear location simulation
    """
    # set to liberty island
    LocationSimulation(dvt).clear()
