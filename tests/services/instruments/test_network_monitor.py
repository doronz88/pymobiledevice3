import ipaddress
import struct

import pytest

from pymobiledevice3.exceptions import TruncatedDataError
from pymobiledevice3.services.dvt.instruments.network_monitor import AddressV4, AddressV6, SocketAddress


def test_parse_ipv4_socket_address() -> None:
    raw = struct.pack(">BBH", 0x10, 2, 443) + bytes([17, 0, 0, 1]) + bytes(8)
    assert SocketAddress.parse(raw) == SocketAddress(
        length=0x10, family=2, port=443, data=AddressV4(address=ipaddress.IPv4Address("17.0.0.1"), _zero=bytes(8))
    )
    assert SocketAddress.parse(raw).address == ipaddress.IPv4Address("17.0.0.1")


def test_parse_ipv6_socket_address() -> None:
    address = ipaddress.IPv6Address("fe80::1")
    raw = struct.pack(">BBH", 0x1C, 30, 5353) + struct.pack("<I16sI", 7, address.packed, 4)
    assert SocketAddress.parse(raw) == SocketAddress(
        length=0x1C, family=30, port=5353, data=AddressV6(flow_info=7, address=address, scope_id=4)
    )


def test_parse_socket_address_of_unknown_length_has_no_payload() -> None:
    address = SocketAddress.parse(struct.pack(">BBH", 8, 0, 0))
    assert address.data is None and address.address is None


def test_parse_truncated_socket_address() -> None:
    with pytest.raises(TruncatedDataError):
        SocketAddress.parse(struct.pack(">BBH", 0x10, 2, 443) + bytes(5))


def test_address_payloads_build_round_trip() -> None:
    v6 = AddressV6(flow_info=7, address=ipaddress.IPv6Address("fe80::1"), scope_id=4)
    assert v6.build() == struct.pack("<I16sI", 7, v6.address.packed, 4)
    assert AddressV6.parse(v6.build()) == v6
    v4 = AddressV4(address=ipaddress.IPv4Address("17.0.0.1"), _zero=bytes(8))
    assert v4.build() == bytes([17, 0, 0, 1]) + bytes(8)
    assert AddressV4.parse(v4.build()) == v4
