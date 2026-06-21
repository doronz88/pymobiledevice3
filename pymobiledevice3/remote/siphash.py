"""
Pure-python SipHash-2-4 and the ``authTag`` derivation used by the
``_remotepairing-pairable-host._tcp`` mDNS advertisement.

Starting with iOS 27 a device may initiate pairing to a computer. The computer
advertises itself over mDNS and publishes an ``authTag`` derived from its
``altIRK`` so an already-paired device can recognize it. The tag is
``SipHash-2-4(key=altIRK, msg=service_identifier)``: the 8-byte little-endian
output, first 6 bytes reversed.
"""

import base64
import struct

__all__ = ["compute_auth_tag", "siphash24", "validate_auth_tag"]

_MASK = (1 << 64) - 1


def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & _MASK


def siphash24(key: bytes, data: bytes) -> int:
    """Compute SipHash-2-4 of ``data`` under the 16-byte ``key`` (returns a u64)."""
    if len(key) != 16:
        raise ValueError("SipHash key must be 16 bytes")
    k0, k1 = struct.unpack("<QQ", key)
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    def sip_round() -> None:
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & _MASK
        v1 = _rotl(v1, 13)
        v1 ^= v0
        v0 = _rotl(v0, 32)
        v2 = (v2 + v3) & _MASK
        v3 = _rotl(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & _MASK
        v3 = _rotl(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & _MASK
        v1 = _rotl(v1, 17)
        v1 ^= v2
        v2 = _rotl(v2, 32)

    length = len(data)
    end = length - (length % 8)
    for off in range(0, end, 8):
        m = struct.unpack_from("<Q", data, off)[0]
        v3 ^= m
        sip_round()
        sip_round()
        v0 ^= m

    last = (length & 0xFF) << 56
    for i in range(length - end):
        last |= data[end + i] << (8 * i)
    v3 ^= last
    sip_round()
    sip_round()
    v0 ^= last

    v2 ^= 0xFF
    sip_round()
    sip_round()
    sip_round()
    sip_round()
    return (v0 ^ v1 ^ v2 ^ v3) & _MASK


def compute_auth_tag(alt_irk: bytes, service_identifier: str) -> bytes:
    """
    Compute the 6-byte mDNS ``authTag`` for the given ``altIRK`` and identifier.

    Algorithm: ``SipHash-2-4(key=altIRK, msg=service_identifier)``, take the 8-byte
    little-endian output, return its first 6 bytes in reverse order.
    """
    output = struct.pack("<Q", siphash24(alt_irk, service_identifier.encode()))
    return bytes(output[5 - i] for i in range(6))


def validate_auth_tag(alt_irk: bytes, service_identifier: str, auth_tag: str) -> bool:
    """Validate a base64-encoded 6-byte ``authTag`` against ``altIRK``/identifier."""
    try:
        decoded = base64.b64decode(auth_tag)
    except (ValueError, TypeError):
        return False
    if len(decoded) != 6 or len(alt_irk) != 16:
        return False
    return compute_auth_tag(alt_irk, service_identifier) == decoded
