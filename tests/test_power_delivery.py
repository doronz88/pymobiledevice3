import struct
from typing import Optional

import pytest
import typer

from pymobiledevice3.cli import restore as restore_cli
from pymobiledevice3.usb import power_delivery
from pymobiledevice3.usb.power_delivery import ApplePort, PortController, PowerDeliveryError, VdmReply

APPLE = power_delivery.APPLE_VENDOR_ID


@pytest.mark.parametrize(
    ("serial", "ecid"),
    [
        ("00008150001074523440401C", 0x001074523440401C),
        ("SDOM:01 CPID:8150 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:001074523440401C IBFL:3C", 0x001074523440401C),
        ("000000001", None),
        (None, None),
    ],
)
def test_ecid_from_usb_serial(serial: Optional[str], ecid: Optional[int]) -> None:
    assert power_delivery.ecid_from_usb_serial(serial) == ecid


def test_apple_ports_pair_pd_partner_with_usb_device() -> None:
    ports = [{"PortNumber": 1}, {"PortNumber": 2}, {"PortNumber": 3}]
    sops = [{"ParentPortNumber": 1, "Vendor ID": APPLE}, {"ParentPortNumber": 3, "Vendor ID": 0x2109}]
    usb2 = [
        {
            "ParentPortNumber": 1,
            "Metadata": {"Product": "iPhone", "Product ID": 0x12A8, "Serial Number": "00008150001074523440401C"},
        },
        {"ParentPortNumber": 3, "Metadata": {"Product": "USB2.0 Hub", "Product ID": 0x2822}},
    ]
    # port 2 has no PD partner and port 3's is a hub: only port 1 is an Apple device that can be messaged
    assert power_delivery.apple_ports_from_registry(ports, sops, usb2) == [
        ApplePort(1, "iPhone", 0x12A8, "00008150001074523440401C")
    ]


@pytest.mark.parametrize(
    ("product", "product_id", "description"),
    [
        ("iPhone", 0x12A8, "iPhone in normal mode on Port-USB-C@1, ECID 0x1"),
        ("Apple Mobile Device (Recovery Mode)", 0x1281, "Apple device in Recovery mode on Port-USB-C@1, ECID 0x1"),
        ("Apple Mobile Device (DFU Mode)", 0x1227, "Apple device in DFU mode on Port-USB-C@1, ECID 0x1"),
        (None, power_delivery.KIS_PRODUCT_ID, "Apple device in DFU mode on Port-USB-C@1, ECID 0x1"),
    ],
)
def test_describe(product: Optional[str], product_id: int, description: str) -> None:
    serial = "00008150" + "0000000000000001" if product_id == 0x12A8 else "CPID:8150 ECID:0000000000000001"
    assert ApplePort(1, product, product_id, serial).describe() == description


class _FakeController(PortController):
    """The controller's register/command protocol, answered by a device that replies with ``reply_type``."""

    def __init__(self, reply_type: int, answers: bool = True) -> None:
        self.port = 1
        self._closed = True
        self._reply_type = reply_type
        self._answers = answers
        self._rx_count = 0
        self.sent: list[bytes] = []

    def read(self, register: int) -> bytes:
        if register == power_delivery._REG_RX_VDM:
            header = power_delivery._APPLE_VDM_HEADER | self._reply_type
            return bytes([self._rx_count]) + struct.pack("<I", header) + bytes(59)
        return bytes(64)

    def command(self, command: str, args: bytes = b"") -> bool:
        self.sent.append(command.encode() + args)
        if command == "VDMs" and self._answers:
            self._rx_count += 1
        return True


@pytest.mark.parametrize("reply", list(VdmReply))
def test_send_vdm_reports_the_reply_type(reply: VdmReply) -> None:
    controller = _FakeController(reply)
    assert controller.send_vdm(power_delivery._APPLE_VDM_HEADER, power_delivery._REBOOT_VDOS) == reply
    # count/SOP byte, then the header and VDOs little-endian
    assert controller.sent[-1] == b"VDMs" + bytes([0x33]) + struct.pack(
        "<3I", power_delivery._APPLE_VDM_HEADER, *power_delivery._REBOOT_VDOS
    )


def test_send_vdm_without_an_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(power_delivery, "_VDM_REPLY_INTERVAL", 0)
    with pytest.raises(PowerDeliveryError, match="did not answer"):
        _FakeController(VdmReply.ACK, answers=False).send_vdm(power_delivery._APPLE_VDM_HEADER, ())


_PHONE = ApplePort(1, "iPhone", 0x12A8, "000081500000000000000001")
_PAD = ApplePort(2, "iPad", 0x12AB, "000081300000000000000002")


def test_choose_port_by_ecid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(power_delivery, "list_apple_ports", lambda: [_PHONE, _PAD])
    assert restore_cli._choose_vdm_port("0x2") == _PAD


def test_choose_port_asks_when_several(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(power_delivery, "list_apple_ports", lambda: [_PHONE, _PAD])
    # without a terminal the prompt lists the candidates instead of picking one
    with pytest.raises(typer.Exit):
        restore_cli._choose_vdm_port(None)
    err = capsys.readouterr().err
    assert _PHONE.describe() in err and _PAD.describe() in err
    assert "--ecid" in err


def test_choose_port_explains_when_none(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(power_delivery, "list_apple_ports", lambda: [])
    with pytest.raises(typer.Exit):
        restore_cli._choose_vdm_port(None)
    assert "no hub" in capsys.readouterr().err
