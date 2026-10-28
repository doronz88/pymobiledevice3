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


def test_special_mode_states_go_by_product_id(monkeypatch: pytest.MonkeyPatch) -> None:
    product_ids = [
        (APPLE_VENDOR_ID, dfu_guide.KIS_PRODUCT_ID),
        (APPLE_VENDOR_ID, Mode.RECOVERY_MODE_2.value),
        (APPLE_VENDOR_ID, 0x12A8),  # a booted iPhone
        (0x1234, Mode.DFU_MODE.value),  # not Apple
    ]
    monkeypatch.setattr(dfu_guide, "_usb_product_ids", lambda: product_ids)
    assert dfu_guide.special_mode_states() == {UsbState.KIS, UsbState.RECOVERY}


def test_usb_product_ids_come_from_iokit_where_available(monkeypatch: pytest.MonkeyPatch) -> None:
    # libusb does not list a KIS device on macOS; IOKit does
    entries = [SimpleNamespace(properties={"idVendor": APPLE_VENDOR_ID, "idProduct": dfu_guide.KIS_PRODUCT_ID})]
    monkeypatch.setattr(dfu_guide, "get_io_services_by_type", lambda service_type: entries)
    monkeypatch.setattr(dfu_guide, "find", lambda find_all=False: [])
    assert dfu_guide._usb_product_ids() == [(APPLE_VENDOR_ID, dfu_guide.KIS_PRODUCT_ID)]


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
