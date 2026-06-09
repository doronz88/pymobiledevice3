"""
Helpers to construct the ``negotiatorOffer`` bplist that
``com.apple.coredevice.action.mediastreamstart`` requires.

The offer carries four keys::

    {
        'avcMediaStreamOptionRemoteEndpointInfo': <protobuf describing the host>,
        'avcMediaStreamNegotiatorMode': <int — 5 video / 6 audio>,
        'avcMediaStreamNegotiatorMediaBlob': <zlib-compressed protobuf with
                                              codec params and feature strings>,
        'avcMediaStreamOptionCallID': <UUID string>,
    }

Protobuf schemas were recovered by walking captured devicectl traffic. The
``mediaBlob`` describes the decoder ("Viceroy 1.7.0"), supported codecs,
audio/video payload types and acceptable bitrate ranges. The numeric values
embedded here come straight from the sniff — they're a known-good baseline that
the iOS side accepts. Adjust if you need a different codec profile.
"""

import plistlib
import uuid
import zlib

# Decoder name embedded in the mediaBlob. The iOS daemon matches against this
# string to pick a compatible decoder on its side.
DEFAULT_DECODER_NAME = "Viceroy 1.7.0"

# avcMediaStreamNegotiatorMode values seen on the wire.
NEGOTIATOR_MODE_VIDEO = 5
NEGOTIATOR_MODE_AUDIO = 6


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _string_field(field: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _tag(field, 2) + _varint(len(encoded)) + encoded


def _varint_field(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def build_remote_endpoint_info(
    model: str,
    os_version: str,
    build: str,
    field1: int = 0,
    field2: int = 1,
) -> bytes:
    """Build the ``avcMediaStreamOptionRemoteEndpointInfo`` protobuf.

    Captured macOS host sends: ``{0, 1, "Mac16,11", "2205.3.1", "25F80"}``.
    """
    return (
        _varint_field(1, field1)
        + _varint_field(2, field2)
        + _string_field(3, model)
        + _string_field(4, os_version)
        + _string_field(5, build)
    )


def build_media_blob_video(
    session_id: int,
    decoder_name: str = DEFAULT_DECODER_NAME,
) -> bytes:
    """Build the video mediaBlob protobuf matching Xcode's Mirror offer
    byte-for-byte, with the session_id varint substituted.

    Built from a verbatim capture of Xcode's video ``mediastreamstart`` call.
    A previous hand-rolled version produced an *almost* identical protobuf
    that the device accepted, but with subtle differences (bitrate-entry
    order, codec-capability fields) that flipped ``IsltrpEnabled`` to True
    in the response -- which enabled Long-Term Reference Pictures and made
    the stream impossible to decode cleanly mid-session. Copying the bytes
    verbatim avoids re-introducing such gremlins.

    The 5-byte session_id varint near the start (currently 0xF3 0x97 0xC1
    0x85 0x0E in the template) is the only per-session value; we replace
    it. Everything else -- codec descriptors, bitrate-cap entries, the
    field-13 host identifier -- is copied as-is.
    """
    _ = decoder_name  # encoded in the template; argument kept for API symmetry
    template = bytes.fromhex(
        "080110012a7f088182bae90810001a3f087b120a0801100118c387032000120a"
        "0801100218c387032000120a0801100118c387032000120a0801100218c38703"
        "20001a09464c533b53573a313b20011a2e0864120a0801100118c38703200012"
        "0a0801100218c3870320001a10464c533b565241453a303b53573a313b200e38"
        "01403f6001320d56696365726f7920312e372e3040004a0908ea1f1000188080"
        "014a0b080010c0d1e123188080204a0a08001080b489131880604a0508101084"
        "204a0b08001080dac409188080064a05080410e4324a0b080010809bee021880"
        "80084a0b08001080c2d72f188080404a0b080010808ece1c188080104a050801"
        "10ab026880c0dd87d2a0c0e9ed017002800100900101"
    )
    sid_old = bytes.fromhex("8182bae908")  # session_id varint in the template
    sid_new = _encode_varint(session_id)
    # The captured varint is 5 bytes; pad ours to match so we don't shift
    # the rest of the structure. A varint can use redundant continuation
    # bytes (``0x80``) as long as the encoded value is unchanged.
    while len(sid_new) < 5:
        sid_new = sid_new[:-1] + bytes([sid_new[-1] | 0x80]) + b"\x00"
    if len(sid_new) > 5:
        session_id &= (1 << 35) - 1
        sid_new = _encode_varint(session_id)
        while len(sid_new) < 5:
            sid_new = sid_new[:-1] + bytes([sid_new[-1] | 0x80]) + b"\x00"
    return template.replace(sid_old, sid_new, 1)


# Alias kept for the in-template session_id substitution loop above.
_encode_varint = _varint


def build_negotiator_offer_video(
    call_id: str,
    session_id: int,
    # Default to the same identity Xcode uses (Mac15,9 = M2 Air, macOS 25F80).
    # The device may pick encoder parameters based on this — under our
    # original Mac16,11 identity we saw frequent encoder stalls; under
    # Mac15,9 Xcode's mirror is rock-solid.
    host_model: str = "Mac15,9",
    host_os_version: str = "2205.3.1",
    host_build: str = "25F80",
) -> bytes:
    """Build the full ``negotiatorOffer`` bplist for a video stream.

    :param call_id: Unique UUID string for this call (``avcMediaStreamOptionCallID``).
    :param session_id: Random uint32 used inside the mediaBlob to identify this session.
    :param host_model: Host hardware model string (e.g. ``"Mac16,11"``).
    :param host_os_version: Host OS version (e.g. ``"2205.3.1"``).
    :param host_build: Host OS build (e.g. ``"25F80"``).
    """
    endpoint_info = build_remote_endpoint_info(host_model, host_os_version, host_build)
    media_blob = build_media_blob_video(session_id)
    # Match Apple's compression level (9 = best). Default Python level (6)
    # produces a different byte stream and the device rejects it with
    # "Invalid Parameter".
    compressed_blob = zlib.compress(media_blob, level=9)
    return plistlib.dumps(
        {
            "avcMediaStreamOptionRemoteEndpointInfo": endpoint_info,
            "avcMediaStreamNegotiatorMode": NEGOTIATOR_MODE_VIDEO,
            "avcMediaStreamNegotiatorMediaBlob": compressed_blob,
            "avcMediaStreamOptionCallID": call_id,
        },
        fmt=plistlib.FMT_BINARY,
    )


def new_call_id() -> str:
    """Generate a fresh ``avcMediaStreamOptionCallID`` UUID string."""
    return str(uuid.uuid4()).upper()
