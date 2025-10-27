from pymobiledevice3.services.springboard import SpringBoardServicesService

PNG_HEADER = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"


def test_get_icon_png_data(lockdown):
    """
    Test that getting icon's data returns a valid PNG.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with SpringBoardServicesService(lockdown) as springboard:
        icon_data = springboard.get_icon_pngdata("com.apple.weather")
        assert icon_data.startswith(PNG_HEADER)


def test_get_icon_date(lockdown):
    """
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with SpringBoardServicesService(lockdown) as springboard:
        assert len(springboard.get_icon_state()[0]) > 0


def test_set_icon_date(lockdown):
    """
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with SpringBoardServicesService(lockdown) as springboard:
        icon_state = springboard.get_icon_state()
        # swap docker icons
        icon_state[0] = icon_state[0][::-1]
        springboard.set_icon_state(icon_state)

        assert springboard.get_icon_state()[0] == icon_state[0]

        icon_state[0] = icon_state[0][::-1]
        springboard.set_icon_state(icon_state)

        assert springboard.get_icon_state()[0] == icon_state[0]
