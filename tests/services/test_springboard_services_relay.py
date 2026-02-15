import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.springboard import SpringBoardServicesService

PNG_HEADER = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"


@pytest.mark.asyncio
async def test_get_icon_png_data(lockdown: LockdownClient) -> None:
    """
    Test that getting icon's data returns a valid PNG.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    async with SpringBoardServicesService(lockdown) as springboard:
        icon_data = await springboard.get_icon_pngdata("com.apple.weather")
        assert icon_data.startswith(PNG_HEADER)


@pytest.mark.asyncio
async def test_get_icon_date(lockdown: LockdownClient) -> None:
    """
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    async with SpringBoardServicesService(lockdown) as springboard:
        assert len((await springboard.get_icon_state())[0]) > 0


@pytest.mark.asyncio
async def test_set_icon_date(lockdown: LockdownClient) -> None:
    """
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    async with SpringBoardServicesService(lockdown) as springboard:
        icon_state = await springboard.get_icon_state()
        # swap docker icons
        icon_state[0] = icon_state[0][::-1]
        await springboard.set_icon_state(icon_state)

        assert (await springboard.get_icon_state())[0] == icon_state[0]

        icon_state[0] = icon_state[0][::-1]
        await springboard.set_icon_state(icon_state)

        assert (await springboard.get_icon_state())[0] == icon_state[0]
