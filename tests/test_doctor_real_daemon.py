"""Daemon identification against a real usbmuxd, rather than a fake of one.

The rest of the doctor's platform code is unit tested over fakes, which cannot catch the thing
most likely to be wrong here: what a *real* daemon looks like on disk and in /proc. These run only
where one is actually installed — locally if you have one, and in CI on the Ubuntu job that
installs it on purpose.

No device is required: identifying the daemon is about the daemon.
"""

import shutil
import sys

import pytest

from pymobiledevice3.osu.os_utils import UsbmuxDaemon, get_os_utils

pytestmark = [
    pytest.mark.cli,
    pytest.mark.skipif(sys.platform != "linux", reason="daemon identification by linkage is Linux-only"),
    pytest.mark.skipif(shutil.which("usbmuxd") is None, reason="no usbmuxd installed on this host"),
]


def test_a_real_usbmuxd_is_identified() -> None:
    daemon = get_os_utils().usbmux_daemon()

    if daemon is None:
        pytest.skip("usbmuxd is installed but not running")
    assert isinstance(daemon, UsbmuxDaemon)
    assert "usbmuxd" in daemon.name
    # Whatever it is, the answer must be decided rather than left vague -- an unreadable daemon is
    # the one outcome this test exists to catch, since it is what a root-owned /proc entry gives.
    assert daemon.discovers_over_wifi is not None, f"could not determine Wi-Fi support: {daemon.note}"


def test_stock_usbmuxd_is_reported_as_having_no_wifi_discovery() -> None:
    """Stock libimobiledevice usbmuxd has no network discovery; usbmuxd2 links Avahi and does.

    CI installs the stock one, so that is the answer expected there. A developer running usbmuxd2
    locally gets the other branch, which is equally correct — hence the assertion on consistency
    between the name and the capability rather than on one fixed answer.
    """
    daemon = get_os_utils().usbmux_daemon()

    if daemon is None:
        pytest.skip("usbmuxd is installed but not running")
    if daemon.name == "usbmuxd2":
        assert daemon.discovers_over_wifi is True
    else:
        assert daemon.discovers_over_wifi is False
