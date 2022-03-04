import time

LOCKDOWND_SOCKET_SELECT_TIMEOUT = 60


def test_lockdown_reconnect(lockdown):
    d1 = lockdown.date

    # add some threshold to make sure lockdownd closed the connection on its end
    time.sleep(LOCKDOWND_SOCKET_SELECT_TIMEOUT + 5)

    d2 = lockdown.date

    assert d1 < d2
