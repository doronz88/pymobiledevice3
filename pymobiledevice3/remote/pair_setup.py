"""Pair-Setup primitives shared by the pairing flows: TLV8 components, their error codes and OPACK.

Kept free of first-party imports so that both `pymobiledevice3.lockdown` and the RemotePairing code in
`pymobiledevice3.remote.tunnel_service` can use it.
"""

import contextlib
import dataclasses
from collections.abc import Mapping
from typing import Annotated, Any, Callable, cast

import opack2
from bytestruct import (
    GREEDY_BYTES,
    U8,
    BinaryStruct,
    ByteReader,
    BytesLike,
    OpenIntEnum,
    Prefixed,
    TruncatedDataError,
    u8,
)

# opack2 ships only partial type information (Unknown-typed parameters/returns); re-expose it through
# casts so call sites stay typed.
opack_dumps = cast(Callable[[Any], bytes], cast(Any, opack2).dumps)
opack_loads = cast(Callable[[bytes], Mapping[Any, Any]], cast(Any, opack2).loads)


class PairingDataComponentType(OpenIntEnum):
    METHOD = 0x00
    IDENTIFIER = 0x01
    SALT = 0x02
    PUBLIC_KEY = 0x03
    PROOF = 0x04
    ENCRYPTED_DATA = 0x05
    STATE = 0x06
    ERROR = 0x07
    RETRY_DELAY = 0x08
    CERTIFICATE = 0x09
    SIGNATURE = 0x0A
    PERMISSIONS = 0x0B
    FRAGMENT_DATA = 0x0C
    FRAGMENT_LAST = 0x0D
    SESSION_ID = 0x0E
    TTL = 0x0F
    EXTRA_DATA = 0x10
    INFO = 0x11
    ACL = 0x12
    FLAGS = 0x13
    VALIDATION_DATA = 0x14
    MFI_AUTH_TOKEN = 0x15
    MFI_PRODUCT_TYPE = 0x16
    SERIAL_NUMBER = 0x17
    MFI_AUTH_TOKEN_UUID = 0x18
    APP_FLAGS = 0x19
    OWNERSHIP_PROOF = 0x1A
    SETUP_CODE_TYPE = 0x1B
    PRODUCTION_DATA = 0x1C
    APP_INFO = 0x1D
    SEPARATOR = 0xFF


@dataclasses.dataclass
class PairingDataComponentTLV8(BinaryStruct):
    """One TLV8 item: 1-byte type, 1-byte length, ``length`` bytes of data."""

    type: Annotated[PairingDataComponentType, u8]
    data: Annotated[bytes, Prefixed(U8, GREEDY_BYTES)]


class PairingDataComponentTLVBuf:
    """A buffer of consecutive TLV8 items."""

    @staticmethod
    def parse(data: BytesLike) -> list[PairingDataComponentTLV8]:
        """Parse as many complete items as possible; an incomplete trailing item is ignored."""
        reader = ByteReader(data)
        result: list[PairingDataComponentTLV8] = []
        with contextlib.suppress(TruncatedDataError):
            while reader.remaining:
                result.append(PairingDataComponentTLV8.read(reader))
        return result

    @staticmethod
    def build(items: list[PairingDataComponentTLV8]) -> bytes:
        return b"".join(item.build() for item in items)


# Values of the ERROR component, as CoreUtils' pair-setup maps them to/from its OSStatus codes (noted per value).
# HomeKit's published kTLVError_* table only agrees up to BACKOFF.
class PairingErrorCode(OpenIntEnum):
    UNKNOWN = 0x01  # kUnknownErr
    AUTHENTICATION = 0x02  # kAuthenticationErr
    BACKOFF = 0x03  # kBackoffErr, sent along with RETRY_DELAY
    UNKNOWN_PEER = 0x04  # kNotFoundErr
    MAX_PEERS = 0x05  # kNoSpaceErr
    MAX_TRIES = 0x06  # kCountErr, pair-setup disabled after too many attempts
    PERMISSION = 0x07  # kPermissionErr
    OWNERSHIP_FAILURE = 0x08  # kOwnershipFailureErr
    ACCESS = 0x09  # kAccessErr
    UNSUPPORTED = 0x0A  # kUnsupportedErr


def describe_pairing_error(tlv: dict[int, bytes]) -> str:
    """Describe the ERROR component of a decoded pairing TLV."""
    code = PairingErrorCode(ByteReader(tlv[PairingDataComponentType.ERROR]).read(1)[0])
    message = f"The device rejected pairing: {code.name}"
    retry_delay = tlv.get(PairingDataComponentType.RETRY_DELAY)
    if retry_delay:
        # little-endian seconds until the device accepts another attempt
        message += f"; retry in {int.from_bytes(retry_delay, 'little')} seconds."
    return message


def build_pairing_tlv(components: dict[int, bytes]) -> bytes:
    """Encode Pair-Setup components as TLV8, splitting values longer than 255 bytes into fragments."""
    result = b""
    for component, data in components.items():
        for offset in range(0, max(len(data), 1), 255):
            fragment = data[offset : offset + 255]
            result += bytes([component, len(fragment)]) + fragment
    return result
