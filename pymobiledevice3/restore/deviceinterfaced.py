"""
Keep macOS ``deviceinterfaced`` off the USB device during a restore (idevicerestore 35dee10, ``--exclusive-usb``).

While the device re-enumerates during a restore, ``deviceinterfaced`` can claim the USB interface first, so
the device never shows up for us. For the duration of the restore the daemon is booted out, or, where
that is refused (SIP), killed over and over; afterwards it is loaded and started again. Only the ``launchctl``
subcommands that change the system-domain daemon run through ``sudo`` (which may prompt for a password).
"""

import enum
import logging
import subprocess
import threading
import time
from collections.abc import Sequence
from types import TracebackType
from typing import Callable, Optional

logger = logging.getLogger(__name__)

DEVICEINTERFACED_LABEL = "com.apple.deviceinterfaced"
DEVICEINTERFACED_TARGET = f"system/{DEVICEINTERFACED_LABEL}"
DEVICEINTERFACED_PLIST = (
    "/Library/Apple/System/Library/PrivateFrameworks/DeviceInterface.framework/Support/com.apple.deviceinterfaced.plist"
)
SUDO_PATH = "/usr/bin/sudo"
LAUNCHCTL_PATH = "/bin/launchctl"
SUDO_PROMPT = f"[sudo] password to manage {DEVICEINTERFACED_LABEL}: "
KILL_INTERVAL = 0.1
UNLOAD_POLL_INTERVAL = 0.05
UNLOAD_POLL_COUNT = 100


def run_launchctl(args: Sequence[str], privileged: bool) -> int:
    """Run ``launchctl args`` (through sudo when ``privileged``) and return its exit status."""
    argv = [LAUNCHCTL_PATH, *args]
    if privileged:
        argv = [SUDO_PATH, "-p", SUDO_PROMPT, "--", *argv]
    # sudo prompts on the controlling terminal; keep its own diagnostics visible for privileged calls
    stderr = None if privileged else subprocess.DEVNULL
    return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=stderr, check=False).returncode


class _State(enum.Enum):
    INACTIVE = enum.auto()
    BOOTED_OUT = enum.auto()
    KILLING = enum.auto()


class DeviceInterfacedControl:
    """Context manager holding ``deviceinterfaced`` off while it is entered."""

    def __init__(self, run: Callable[[Sequence[str], bool], int] = run_launchctl) -> None:
        self._run = run
        self._state = _State.INACTIVE
        self._stop_killer = threading.Event()
        self._killer: Optional[threading.Thread] = None

    def _is_loaded(self) -> bool:
        return self._run(["print", DEVICEINTERFACED_TARGET], False) == 0

    def start(self) -> None:
        if self._state != _State.INACTIVE:
            return
        if not self._is_loaded():
            logger.info(f"{DEVICEINTERFACED_LABEL} is not loaded")
            return

        status = self._run(["bootout", DEVICEINTERFACED_TARGET], True)
        if status == 0:
            self._state = _State.BOOTED_OUT
            for _ in range(UNLOAD_POLL_COUNT):
                if not self._is_loaded():
                    logger.info(f"Booted out {DEVICEINTERFACED_LABEL} for the duration of the restore")
                    return
                time.sleep(UNLOAD_POLL_INTERVAL)
            raise TimeoutError(f"Timed out waiting for {DEVICEINTERFACED_LABEL} to stop.")

        logger.warning(
            f"Could not boot out {DEVICEINTERFACED_LABEL} (launchctl exit status {status}); "
            "terminating it while the restore runs"
        )
        self._stop_killer.clear()
        self._killer = threading.Thread(target=self._kill_loop, name="deviceinterfaced-killer", daemon=True)
        self._killer.start()
        self._state = _State.KILLING

    def _kill_loop(self) -> None:
        while not self._stop_killer.is_set():
            self._run(["kill", "SIGKILL", DEVICEINTERFACED_TARGET], True)
            self._stop_killer.wait(KILL_INTERVAL)

    def stop(self) -> None:
        state, self._state = self._state, _State.INACTIVE
        if state == _State.INACTIVE:
            return
        if state == _State.KILLING:
            self._stop_killer.set()
            assert self._killer is not None
            self._killer.join()
            self._killer = None
        elif self._run(["bootstrap", "system", DEVICEINTERFACED_PLIST], True) != 0:
            logger.error(
                f"Could not bootstrap {DEVICEINTERFACED_LABEL}. "
                f"Run 'sudo launchctl bootstrap system {DEVICEINTERFACED_PLIST}' to load it."
            )
            return
        if self._run(["kickstart", DEVICEINTERFACED_TARGET], True) != 0:
            logger.error(
                f"Could not kickstart {DEVICEINTERFACED_LABEL}. "
                f"Run 'sudo launchctl kickstart {DEVICEINTERFACED_TARGET}' to start it."
            )
            return
        logger.info(f"Restored {DEVICEINTERFACED_LABEL}")

    def __enter__(self) -> "DeviceInterfacedControl":
        try:
            self.start()
        except BaseException:
            self.stop()
            raise
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.stop()
