"""
Walk a user through the button sequence that puts a device into DFU mode, confirming each stage from what the
device turns into on USB.

Buttons cannot be observed, but their effect can: the device leaves usbmux when its screen goes black, then
comes back over USB in DFU (classic, or KIS on A16 and later), in Recovery, or booted normally. That is enough to
tell the user whether it worked and, if not, what to do differently.

Apple documents only the Recovery mode sequences; the DFU sequences below are the widely used ones.
"""

import asyncio
import sys
import time
from collections.abc import Awaitable
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, cast

from rich.console import Console
from rich.live import Live
from rich.text import Text

from pymobiledevice3 import usbmux
from pymobiledevice3.irecv._usb import APPLE_VENDOR_ID, Mode, UsbDevice, find

if sys.platform == "darwin":
    from ioregistry.ioentry import get_io_services_by_type
else:
    get_io_services_by_type = None

KIS_PRODUCT_ID = 0x1881  # A16 and later in DFU mode (libirecovery 4472436)
POLL_INTERVAL = 0.25


class UsbState(Enum):
    """What the device currently is on USB."""

    NORMAL = "booted normally"
    RECOVERY = "Recovery mode"
    DFU = "DFU mode"
    KIS = "DFU mode (Debug USB / KIS)"
    GONE = "not on USB"


def _usb_product_ids() -> list[tuple[int, int]]:
    """``(idVendor, idProduct)`` of every USB device on the host.

    On macOS this asks IOKit: libusb does not list a device in KIS mode there (Apple's KIS driver claims it), so
    an A16-or-later device in DFU mode would look absent.
    """
    if get_io_services_by_type is not None:
        return [
            (cast(int, entry.properties.get("idVendor", 0)), cast(int, entry.properties.get("idProduct", 0)))
            for entry in get_io_services_by_type("IOUSBHostDevice")
        ]
    return [(device.idVendor, device.idProduct) for device in cast(list[UsbDevice], list(find(find_all=True)))]


def special_mode_states() -> set[UsbState]:
    """The Recovery/DFU/KIS devices currently on USB, by their USB product IDs (no device is opened)."""
    states: set[UsbState] = set()
    for vendor_id, product_id in _usb_product_ids():
        if vendor_id != APPLE_VENDOR_ID:
            continue
        if product_id == KIS_PRODUCT_ID:
            states.add(UsbState.KIS)
            continue
        mode = Mode.get_mode_from_value(product_id)
        if mode is None:
            continue
        states.add(UsbState.RECOVERY if mode.is_recovery else UsbState.DFU)
    return states


async def current_state(udid: Optional[str]) -> UsbState:
    """
    Where the device is: a special mode wins (it is what the guide waits for), then normal mode for ``udid``.
    """
    states = special_mode_states()
    for state in (UsbState.KIS, UsbState.DFU, UsbState.RECOVERY):
        if state in states:
            return state
    if udid is not None:
        for device in await usbmux.list_devices():
            if device.is_usb and device.matches_udid(udid):
                return UsbState.NORMAL
    return UsbState.GONE


@dataclass(frozen=True)
class Step:
    """One instruction, shown with a countdown while the device is watched."""

    instruction: str
    seconds: float
    # stop the countdown early once the device reaches one of these
    until: frozenset[UsbState] = frozenset()


@dataclass(frozen=True)
class ButtonSequence:
    name: str
    buttons: str
    steps: tuple[Step, ...]


_SCREEN_BLACK = frozenset({UsbState.GONE, UsbState.RECOVERY, UsbState.DFU, UsbState.KIS})
_IN_DFU = frozenset({UsbState.DFU, UsbState.KIS})

# iPhone 8 and later, including iPhone SE (2nd generation and later)
FACE_ID_IPHONE = ButtonSequence(
    name="iPhone 8 or later",
    buttons="VOLUME UP, VOLUME DOWN and the SIDE button",
    steps=(
        Step("Press and quickly release [b]VOLUME UP[/b], then [b]VOLUME DOWN[/b]", 2),
        Step("Press and [b]hold the SIDE button[/b] until the screen goes black", 12, until=_SCREEN_BLACK),
        Step("Keep holding SIDE, and also press and [b]hold VOLUME DOWN[/b]", 5),
        Step("[b]Release SIDE[/b], keep holding VOLUME DOWN", 10, until=_IN_DFU),
    ),
)

# iPhone 7 and 7 Plus
IPHONE_7 = ButtonSequence(
    name="iPhone 7",
    buttons="the SIDE and VOLUME DOWN buttons",
    steps=(
        Step("Press and [b]hold SIDE and VOLUME DOWN[/b] together", 8, until=_SCREEN_BLACK),
        Step("Keep holding both", 2),
        Step("[b]Release SIDE[/b], keep holding VOLUME DOWN", 10, until=_IN_DFU),
    ),
)

# iPhone 6s and earlier, and iPads with a Home button
HOME_BUTTON = ButtonSequence(
    name="device with a Home button",
    buttons="the HOME and the SIDE (or TOP) buttons",
    steps=(
        Step("Press and [b]hold HOME and SIDE/TOP[/b] together", 8, until=_SCREEN_BLACK),
        Step("Keep holding both", 2),
        Step("[b]Release SIDE/TOP[/b], keep holding HOME", 10, until=_IN_DFU),
    ),
)

# iPads without a Home button
IPAD_WITHOUT_HOME_BUTTON = ButtonSequence(
    name="iPad without a Home button",
    buttons="both VOLUME buttons and the TOP button",
    steps=(
        Step(
            "Press and quickly release the [b]VOLUME button nearest the TOP button[/b], then the [b]other VOLUME[/b]",
            2,
        ),
        Step("Press and [b]hold the TOP button[/b] until the screen goes black", 12, until=_SCREEN_BLACK),
        Step("Keep holding TOP, and also press and [b]hold VOLUME DOWN[/b]", 5),
        Step("[b]Release TOP[/b], keep holding VOLUME DOWN", 10, until=_IN_DFU),
    ),
)


def iphone_sequence(product_type: str) -> Optional[ButtonSequence]:
    """The sequence for an iPhone ``product_type`` (e.g. ``iPhone18,4``), or None for anything else."""
    if not product_type.startswith("iPhone"):
        return None
    major = int(product_type[len("iPhone") :].split(",")[0])
    if major >= 10:
        return FACE_ID_IPHONE
    if major == 9:
        return IPHONE_7
    return HOME_BUTTON


@dataclass(frozen=True)
class GuideResult:
    state: UsbState
    hint: Optional[str] = None

    @property
    def in_dfu(self) -> bool:
        return self.state in _IN_DFU


_HINTS = {
    UsbState.NORMAL: "It booted normally: SIDE was probably released too early, or VOLUME DOWN too soon.",
    UsbState.RECOVERY: "It went into Recovery mode: SIDE was probably held too long before releasing it.",
    UsbState.GONE: "It never showed up in DFU mode: try the timing again, or another cable/port.",
}


async def _countdown(
    console: Console, step: Step, index: int, total: int, state: Callable[[], Awaitable[UsbState]]
) -> UsbState:
    deadline = time.monotonic() + step.seconds
    current = await state()
    with Live(console=console, refresh_per_second=8, transient=True) as live:
        while True:
            remaining = deadline - time.monotonic()
            live.update(
                Text.from_markup(
                    f"[cyan]Step {index}/{total}[/cyan]  {step.instruction}   [bold yellow]{max(remaining, 0):4.1f}s[/]"
                    f"   [dim](device: {current.value})[/dim]"
                )
            )
            if current in step.until or remaining <= 0:
                break
            await asyncio.sleep(POLL_INTERVAL)
            current = await state()
    console.print(f"[green]✓[/green] Step {index}/{total}: {step.instruction}  [dim]({current.value})[/dim]")
    return current


async def run_sequence(console: Console, sequence: ButtonSequence, udid: Optional[str]) -> GuideResult:
    """Show each step with its countdown and report where the device ended up."""

    async def state() -> UsbState:
        return await current_state(udid)

    total = len(sequence.steps)
    current = await state()
    for index, step in enumerate(sequence.steps, start=1):
        current = await _countdown(console, step, index, total, state)
    # the device may need a moment to enumerate after the last release
    deadline = time.monotonic() + 3
    while current not in _IN_DFU and time.monotonic() < deadline:
        await asyncio.sleep(POLL_INTERVAL)
        current = await state()
    return GuideResult(current, None if current in _IN_DFU else _HINTS.get(current))
