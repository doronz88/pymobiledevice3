import threading
import time
from collections.abc import Sequence

import pytest

from pymobiledevice3.restore import deviceinterfaced
from pymobiledevice3.restore.deviceinterfaced import (
    DEVICEINTERFACED_PLIST,
    DEVICEINTERFACED_TARGET,
    DeviceInterfacedControl,
)


class _FakeLaunchctl:
    def __init__(self, loaded: bool = True, bootout_status: int = 0) -> None:
        self.loaded = loaded
        self.bootout_status = bootout_status
        self.calls: list[tuple[tuple[str, ...], bool]] = []
        self.killed = threading.Event()

    def __call__(self, args: Sequence[str], privileged: bool) -> int:
        self.calls.append((tuple(args), privileged))
        if args[0] == "print":
            return 0 if self.loaded else 113
        if args[0] == "bootout":
            if self.bootout_status == 0:
                self.loaded = False
            return self.bootout_status
        if args[0] == "kill":
            self.killed.set()
        return 0

    def privileged(self) -> list[tuple[str, ...]]:
        return [args for args, privileged in self.calls if privileged and args[0] != "kill"]


def test_booted_out_daemon_is_loaded_and_started_again() -> None:
    launchctl = _FakeLaunchctl()

    with DeviceInterfacedControl(launchctl):
        assert launchctl.privileged() == [("bootout", DEVICEINTERFACED_TARGET)]

    assert launchctl.privileged() == [
        ("bootout", DEVICEINTERFACED_TARGET),
        ("bootstrap", "system", DEVICEINTERFACED_PLIST),
        ("kickstart", DEVICEINTERFACED_TARGET),
    ]
    # the read-only query never goes through sudo
    assert ("print", DEVICEINTERFACED_TARGET) in [args for args, privileged in launchctl.calls if not privileged]


def test_daemon_is_killed_while_bootout_is_refused_and_started_again() -> None:
    launchctl = _FakeLaunchctl(bootout_status=5)

    with DeviceInterfacedControl(launchctl):
        assert launchctl.killed.wait(5)

    kills = [args for args, privileged in launchctl.calls if args[0] == "kill"]
    assert kills and set(kills) == {("kill", "SIGKILL", DEVICEINTERFACED_TARGET)}
    assert launchctl.privileged() == [("bootout", DEVICEINTERFACED_TARGET), ("kickstart", DEVICEINTERFACED_TARGET)]
    # the kill loop has stopped
    calls = len(launchctl.calls)
    time.sleep(3 * deviceinterfaced.KILL_INTERVAL)
    assert len(launchctl.calls) == calls


def test_daemon_that_is_not_loaded_is_left_alone() -> None:
    launchctl = _FakeLaunchctl(loaded=False)

    with DeviceInterfacedControl(launchctl):
        pass

    assert launchctl.privileged() == []


def test_daemon_is_restored_when_it_does_not_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    launchctl = _FakeLaunchctl()

    def never_unloads(args: Sequence[str], privileged: bool) -> int:
        status = launchctl(args, privileged)
        launchctl.loaded = True
        return status

    monkeypatch.setattr(deviceinterfaced, "UNLOAD_POLL_COUNT", 2)
    monkeypatch.setattr(deviceinterfaced, "UNLOAD_POLL_INTERVAL", 0)

    with pytest.raises(TimeoutError), DeviceInterfacedControl(never_unloads):
        pass

    assert launchctl.privileged()[-2:] == [
        ("bootstrap", "system", DEVICEINTERFACED_PLIST),
        ("kickstart", DEVICEINTERFACED_TARGET),
    ]
