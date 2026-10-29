import io
from types import SimpleNamespace
from typing import Optional

import pytest
from rich.console import Console

from pymobiledevice3.irecv import APPLE_VENDOR_ID, Mode
from pymobiledevice3.restore import dfu_guide
from pymobiledevice3.restore.dfu_guide import ButtonSequence, Step, UsbState


@pytest.mark.parametrize(
    ("product_type", "expected"),
    [
        ("iPhone18,4", dfu_guide.FACE_ID_IPHONE),
        ("iPhone12,8", dfu_guide.FACE_ID_IPHONE),  # iPhone SE (2nd generation)
        ("iPhone10,1", dfu_guide.FACE_ID_IPHONE),  # iPhone 8
        ("iPhone9,3", dfu_guide.IPHONE_7),
        ("iPhone8,1", dfu_guide.HOME_BUTTON),  # iPhone 6s
        ("iPad13,1", None),
        ("Watch6,1", None),
    ],
)
def test_iphone_sequence(product_type: str, expected: Optional[ButtonSequence]) -> None:
    assert dfu_guide.iphone_sequence(product_type) is expected


def test_special_mode_states_go_by_product_id() -> None:
    devices = [
        dfu_guide._UsbEntry(APPLE_VENDOR_ID, dfu_guide.KIS_PRODUCT_ID),
        dfu_guide._UsbEntry(APPLE_VENDOR_ID, Mode.RECOVERY_MODE_2.value),
        dfu_guide._UsbEntry(APPLE_VENDOR_ID, 0x12A8),  # a booted iPhone
        dfu_guide._UsbEntry(0x1234, Mode.DFU_MODE.value),  # not Apple
    ]
    assert dfu_guide.special_mode_states(devices) == {UsbState.KIS, UsbState.RECOVERY}


def _iokit(monkeypatch: pytest.MonkeyPatch, *devices: tuple[int, Optional[str]]) -> None:
    entries = [
        SimpleNamespace(idVendor=APPLE_VENDOR_ID, idProduct=product_id, serial_number=serial, close=lambda: None)
        for product_id, serial in devices
    ]
    monkeypatch.setattr(dfu_guide, "uses_iokit", lambda: True)
    monkeypatch.setattr(dfu_guide, "list_devices", lambda: entries)


@pytest.mark.asyncio
async def test_iokit_sees_kis_and_the_booted_device(monkeypatch: pytest.MonkeyPatch) -> None:
    # libusb does not list a KIS device on macOS; IOKit does, and has the booted device's UDID too
    _iokit(monkeypatch, (0x12A8, "00008150001074523440401C"))
    assert await dfu_guide.current_state("00008150-001074523440401C") == UsbState.NORMAL
    assert await dfu_guide.current_state("00008150-0000000000000000") == UsbState.GONE
    _iokit(monkeypatch, (dfu_guide.KIS_PRODUCT_ID, None))
    assert await dfu_guide.current_state("00008150-001074523440401C") == UsbState.KIS


_QUICK = ButtonSequence(
    name="test",
    buttons="test buttons",
    steps=(
        Step("hold", 5, until=frozenset({UsbState.GONE})),
        Step("release", 5, until=frozenset({UsbState.DFU, UsbState.KIS})),
    ),
)


async def _run(monkeypatch: pytest.MonkeyPatch, states: list[UsbState]) -> dfu_guide.GuideResult:
    remaining = list(states)

    async def current_state(udid: Optional[str]) -> UsbState:
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]

    monkeypatch.setattr(dfu_guide, "current_state", current_state)
    monkeypatch.setattr(dfu_guide, "POLL_INTERVAL", 0)
    return await dfu_guide.run_sequence(Console(file=io.StringIO()), _QUICK, "udid")


@pytest.mark.asyncio
async def test_guide_reports_dfu_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    result = await _run(monkeypatch, [UsbState.NORMAL, UsbState.NORMAL, UsbState.GONE, UsbState.GONE, UsbState.KIS])
    assert result.in_dfu
    assert result.state == UsbState.KIS
    assert result.hint is None


@pytest.mark.asyncio
async def test_guide_explains_landing_in_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dfu_guide.time, "monotonic", _fake_clock())
    result = await _run(monkeypatch, [UsbState.NORMAL, UsbState.GONE, UsbState.RECOVERY])
    assert not result.in_dfu
    assert result.hint is not None and "Recovery" in result.hint


def _fake_clock():
    now = [0.0]

    def monotonic() -> float:
        now[0] += 1
        return now[0]

    return monotonic


@pytest.mark.asyncio
async def test_assisted_guide_restarts_the_device_after_its_step(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    states = [UsbState.NORMAL]

    async def current_state(udid: Optional[str]) -> UsbState:
        return states[0]

    async def restart() -> None:
        events.append("restart")
        # the phone goes down, then comes up in DFU mode behind KIS
        states[0] = UsbState.KIS

    monkeypatch.setattr(dfu_guide, "current_state", current_state)
    monkeypatch.setattr(dfu_guide, "POLL_INTERVAL", 0)
    monkeypatch.setattr(dfu_guide.time, "monotonic", _fake_clock())
    monkeypatch.setattr(dfu_guide.asyncio, "sleep", _no_sleep)
    sequence = dfu_guide.FACE_ID_IPHONE_ASSISTED

    result = await dfu_guide.run_sequence(Console(file=io.StringIO()), sequence, "udid", restart)

    assert events == ["restart"]
    assert result.state == UsbState.KIS


async def _no_sleep(seconds: float) -> None:
    pass


@pytest.mark.asyncio
async def test_a_restarting_step_needs_a_way_to_restart(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dfu_guide, "current_state", lambda udid: _state(UsbState.NORMAL))
    monkeypatch.setattr(dfu_guide.time, "monotonic", _fake_clock())
    with pytest.raises(ValueError, match="restart"):
        await dfu_guide.run_sequence(Console(file=io.StringIO()), dfu_guide.FACE_ID_IPHONE_ASSISTED, "udid")


async def _state(state: UsbState) -> UsbState:
    return state


def test_assisted_sequence_only_for_face_id_iphones() -> None:
    assert dfu_guide.iphone_sequence("iPhone18,4", assisted=True) is dfu_guide.FACE_ID_IPHONE_ASSISTED
    assert dfu_guide.iphone_sequence("iPhone18,4") is dfu_guide.FACE_ID_IPHONE
    assert dfu_guide.iphone_sequence("iPhone9,1", assisted=True) is dfu_guide.IPHONE_7
