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


def _bytes_field(field: int, value: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(value)) + value


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


def _codec_capability(c1: int, c2: int, c3: int = 50115, c4: int = 0) -> bytes:
    return _varint_field(1, c1) + _varint_field(2, c2) + _varint_field(3, c3) + _varint_field(4, c4)


def _codec_descriptor(payload_type: int, capabilities: list[bytes], features: str, f4: int) -> bytes:
    body = _varint_field(1, payload_type)
    for cap in capabilities:
        body += _bytes_field(2, cap)
    body += _string_field(3, features)
    body += _varint_field(4, f4)
    return body


def _bitrate_entry(f1: int, f2: int, f3: int = 0) -> bytes:
    body = _varint_field(1, f1) + _varint_field(2, f2)
    if f3:
        body += _varint_field(3, f3)
    return body


def build_media_blob_video(
    session_id: int,
    decoder_name: str = DEFAULT_DECODER_NAME,
) -> bytes:
    """Build a known-good video mediaBlob protobuf (matches captured Mac→iOS offer).

    ``session_id`` is a random uint32 chosen per session.
    """
    video_caps = [
        _codec_capability(1, 1),
        _codec_capability(1, 2),
        _codec_capability(1, 1),
        _codec_capability(1, 2),
    ]
    audio_caps = [_codec_capability(1, 1), _codec_capability(1, 2)]
    inner = (
        _varint_field(1, session_id)
        + _varint_field(2, 0)
        + _bytes_field(3, _codec_descriptor(123, video_caps, "FLS;SW:1;", 1))
        + _bytes_field(3, _codec_descriptor(100, audio_caps, "FLS;VRAE:0;SW:1;", 14))
        + _varint_field(7, 1)
        + _varint_field(8, 63)
        + _varint_field(12, 1)
    )
    bitrate_entries = [
        _bitrate_entry(0, 40000000, 12288),
        _bitrate_entry(0, 75000000, 524288),
        _bitrate_entry(4074, 0, 16384),
        _bitrate_entry(16, 4100),
        _bitrate_entry(0, 20000000, 98304),
        _bitrate_entry(0, 6000000, 131072),
        _bitrate_entry(1, 299),
        _bitrate_entry(0, 60000000, 262144),
        _bitrate_entry(4, 6500),
        _bitrate_entry(0, 100000000, 1048576),
    ]
    body = (
        _varint_field(1, 1)
        + _varint_field(2, 1)
        + _bytes_field(5, inner)
        + _string_field(6, decoder_name)
        + _varint_field(8, 0)
    )
    for entry in bitrate_entries:
        body += _bytes_field(9, entry)
    body += _varint_field(13, 17136796984055379968)
    body += _varint_field(14, 2)
    body += _varint_field(16, 0)
    body += _varint_field(18, 1)
    return body


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
    compressed_blob = zlib.compress(media_blob)
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
