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

``mediaBlob`` protobuf schema (reverse-engineered from
``-[AVCMediaStreamNegotiator createOffer]`` + cross-referenced against
iShareScreen's offers.py)::

    MediaBlob (top-level) {
        1: int    = 1           // constant
        2: int    = 1           // constant
        5: VideoSettings (video) OR 3: AudioSettings (audio)
        6: string                 // decoder identity (e.g. "Viceroy 1.7.0")
        8: int    = 0
        9: BitrateTier[]          // repeated tier descriptors
        13: int                   // timestamp (host clock; Apple doesn't seem to check)
        14: int   = 2
        16: int   = 0
        18: int   = 1
    }

    VideoSettings {
        1: int      // session_id (5-byte padded varint)
        2: int      // allowRTCPFB         (0=off, 1=on)
        3: CodecBank[]              // HEVC, AVC (one of each)
        7: int      // ltrpEnabled         (0=off, 1=on) -- protobuf-level
                                    //  switch. The outer options-dict
                                    //  equivalent is ignored by the daemon;
                                    //  this is the one that actually flows
                                    //  into the encoder config.
        8: int      = 63
        12: int     = 1
    }

    AudioSettings {
        1: int      // session_id (5-byte padded varint)
        2: int      = 0
        3: int      = 0
        4: int      = 24191         // constant from Apple captures
        5: int      = 0
        6: int      = 0
    }

    CodecBank {
        1: int                      // payload type (HEVC=123, AVC=100)
        2: ResEntry[]               // 4 entries for HEVC, 2 for AVC
        3: string                   // feature-list string ("FLS;...;")
        4: int                      // HEVC=1, AVC=14
    }

    ResEntry {                      // codec-capability tier
        1: int = 1
        2: int                      // 1 or 2 -- pair index inside the bank
        3: int = 50115              // fixed AVConference codec-cap ID
        4: int = 0
    }

    BitrateTier {                   // f9 in the top-level message
        1: int                      // tier kind: 0 = bps cap, 4074 = header,
                                    //  16=CELT-NB, 4=SILK, 1=opus(?)
        2: int                      // bps (when f1=0)
        3: int? (optional)          // buffer cap (only present for f1=0/4074)
    }

The byte-for-byte equivalence between this builder (with default args) and
the prior verbatim hex template is locked in by the doctest at the bottom.
"""

import plistlib
import time
import uuid
import zlib

# Decoder name embedded in the mediaBlob. The iOS daemon matches against this
# string to pick a compatible decoder on its side.
DEFAULT_DECODER_NAME = "Viceroy 1.7.0"

# avcMediaStreamNegotiatorMode values seen on the wire.
NEGOTIATOR_MODE_VIDEO = 5
NEGOTIATOR_MODE_AUDIO = 6

# Apple's canonical bitrate-tier table (f9 entries). f1 = entry kind:
#   0       primary tier with a network bitrate cap (f2 = bps, f3 = buffer cap)
#   16/4/1  codec-specific markers (CELT-NB, SILK, ...)
#   4074    header marker
# The two orderings differ between video and audio (Apple captured them in
# different orders); kept verbatim so the byte-equivalence check passes.
_DEFAULT_VIDEO_BITRATE_TIERS: tuple[tuple[int, int, int | None], ...] = (
    (4074, 0, 16384),
    (0, 75_000_000, 524288),
    (0, 40_000_000, 12288),
    (16, 4100, None),
    (0, 20_000_000, 98304),
    (4, 6500, None),
    (0, 6_000_000, 131072),
    (0, 100_000_000, 1048576),
    (0, 60_000_000, 262144),
    (1, 299, None),
)
_DEFAULT_AUDIO_BITRATE_TIERS: tuple[tuple[int, int, int | None], ...] = (
    (4074, 0, 16384),
    (1, 299, None),
    (0, 60_000_000, 262144),
    (4, 6500, None),
    (0, 20_000_000, 98304),
    (0, 100_000_000, 1048576),
    (0, 40_000_000, 12288),
    (0, 6_000_000, 131072),
    (16, 4100, None),
    (0, 75_000_000, 524288),
)

# Feature strings declared inside each codec bank. ``FLS;`` is the
# AVConference framing marker; what follows is a semicolon-list of capability
# flags (LTR = long-term reference, CABAC, AR/XR = aspect-ratio constraints,
# etc.). Apple's capture only declared ``SW:1;`` for HEVC and ``VRAE:0;SW:1;``
# for AVC, but iShareScreen demonstrates the device accepts a richer set.
_DEFAULT_HEVC_FEATURES = "FLS;SW:1;"
_DEFAULT_AVC_FEATURES = "FLS;VRAE:0;SW:1;"

# Fixed AVConference codec-capability ID baked into every ResEntry inside the
# HEVC/AVC banks. Doesn't appear to encode resolution -- iShareScreen uses the
# same value and it shows up unchanged across Apple captures.
_RES_ENTRY_CODEC_CAP_ID = 50115

# Timestamp baked into the captured templates -- kept as default so the
# builder remains byte-identical to the prior hex literals. Pass
# ``timestamp=time.time_ns()`` if you'd rather send a fresh clock value
# (iShareScreen does; Apple's daemon hasn't shown any sign of validating it).
_CAPTURED_VIDEO_TIMESTAMP = 17137042128614416384
_CAPTURED_AUDIO_TIMESTAMP = 17137179377605574656


# ----- protobuf helpers ----------------------------------------------------


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


def _varint_padded(value: int, width: int) -> bytes:
    """Encode ``value`` as a varint padded out to exactly ``width`` bytes.

    Protobuf tolerates redundant continuation bytes (low 7 bits zero,
    continuation flag set) without changing the decoded value -- Apple's
    captured offers use this for the 5-byte session_id slot, presumably so
    the encoder can rewrite the field in place without shifting the
    surrounding bytes.
    """
    raw = bytearray(_varint(value))
    if len(raw) > width:
        # Truncating the value into ``width`` bytes wraps around silently.
        # Use modulo to make the wrap-around explicit; callers typically pass
        # a uint32 here so it's a no-op.
        return _varint_padded(value & ((1 << (7 * width)) - 1), width)
    while len(raw) < width:
        raw[-1] |= 0x80
        raw.append(0x00)
    return bytes(raw)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _f_varint(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def _f_bytes(field: int, value: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(value)) + value


def _f_string(field: int, value: str) -> bytes:
    return _f_bytes(field, value.encode("utf-8"))


# ----- mediaBlob piece builders -------------------------------------------


def _res_entry(pair_index: int) -> bytes:
    """One ResEntry inside a CodecBank's f2-repeated list."""
    return _f_varint(1, 1) + _f_varint(2, pair_index) + _f_varint(3, _RES_ENTRY_CODEC_CAP_ID) + _f_varint(4, 0)


def _codec_bank(payload_type: int, features: str, f4: int, *, res_pair_count: int) -> bytes:
    """A CodecBank body (the value going into VideoSettings.f3).

    ``res_pair_count`` is 2 for AVC, 4 for HEVC -- the bank carries alternating
    pair indices 1, 2 repeated that many times.
    """
    body = _f_varint(1, payload_type)
    for i in range(res_pair_count):
        body += _f_bytes(2, _res_entry(1 + (i % 2)))
    body += _f_string(3, features)
    body += _f_varint(4, f4)
    return body


def build_media_blob_video(
    session_id: int,
    *,
    allow_rtcp_fb: bool = False,
    ltrp_enabled: bool = False,
    hevc_payload_type: int = 123,
    avc_payload_type: int = 100,
    hevc_features: str = _DEFAULT_HEVC_FEATURES,
    avc_features: str = _DEFAULT_AVC_FEATURES,
    decoder_name: str = DEFAULT_DECODER_NAME,
    timestamp: int = _CAPTURED_VIDEO_TIMESTAMP,
    bitrate_tiers: tuple[tuple[int, int, int | None], ...] = _DEFAULT_VIDEO_BITRATE_TIERS,
) -> bytes:
    """Build the video mediaBlob protobuf programmatically.

    Defaults are tuned to be byte-identical to the previously-shipped verbatim
    Xcode capture; tweak the kwargs to experiment with negotiation knobs.
    The kwargs we know matter for screen-tear / latency on iPhone:

    * ``ltrp_enabled=False`` -- the protobuf-level LTRP switch. The outer
      options-dict equivalent (memory: ``project_displayservice_resolution_locked``)
      was confirmed ignored, but this one feeds straight into the encoder
      config and hasn't been probed yet.
    * ``allow_rtcp_fb=True`` -- enables the RTCP feedback path. The device's
      AVCRC is open-loop today (memory: ``project_avcrc_ignores_rr``); flipping
      this is the first step in seeing whether the encoder will start honouring
      our RR / REMB / TWCC.
    """
    video_settings = (
        _tag(1, 0)
        + _varint_padded(session_id, 5)
        + _f_varint(2, 1 if allow_rtcp_fb else 0)
        + _f_bytes(3, _codec_bank(hevc_payload_type, hevc_features, 1, res_pair_count=4))
        + _f_bytes(3, _codec_bank(avc_payload_type, avc_features, 14, res_pair_count=2))
        + _f_varint(7, 1 if ltrp_enabled else 0)
        + _f_varint(8, 63)
        + _f_varint(12, 1)
    )
    return _build_top_level(
        settings_field=5,
        settings_body=video_settings,
        decoder_name=decoder_name,
        timestamp=timestamp,
        bitrate_tiers=bitrate_tiers,
    )


def build_media_blob_audio(
    session_id: int,
    *,
    decoder_name: str = DEFAULT_DECODER_NAME,
    timestamp: int = _CAPTURED_AUDIO_TIMESTAMP,
    bitrate_tiers: tuple[tuple[int, int, int | None], ...] = _DEFAULT_AUDIO_BITRATE_TIERS,
) -> bytes:
    """Build the audio mediaBlob protobuf programmatically. Byte-identical to
    Apple's captured audio template by default."""
    audio_settings = (
        _tag(1, 0)
        + _varint_padded(session_id, 5)
        + _f_varint(2, 0)
        + _f_varint(3, 0)
        + _f_varint(4, 24191)
        + _f_varint(5, 0)
        + _f_varint(6, 0)
    )
    return _build_top_level(
        settings_field=3,
        settings_body=audio_settings,
        decoder_name=decoder_name,
        timestamp=timestamp,
        bitrate_tiers=bitrate_tiers,
    )


def _build_top_level(
    *,
    settings_field: int,
    settings_body: bytes,
    decoder_name: str,
    timestamp: int,
    bitrate_tiers: tuple[tuple[int, int, int | None], ...],
) -> bytes:
    """Wrap a Video/AudioSettings body in the surrounding MediaBlob fields."""
    f9s = b""
    for f1, f2, f3 in bitrate_tiers:
        body = _f_varint(1, f1) + _f_varint(2, f2)
        if f3 is not None:
            body += _f_varint(3, f3)
        f9s += _f_bytes(9, body)
    return (
        _f_varint(1, 1)
        + _f_varint(2, 1)
        + _f_bytes(settings_field, settings_body)
        + _f_string(6, decoder_name)
        + _f_varint(8, 0)
        + f9s
        + _f_varint(13, timestamp)
        + _f_varint(14, 2)
        + _f_varint(16, 0)
        + _f_varint(18, 1)
    )


# ----- RemoteEndpointInfo --------------------------------------------------


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
        _f_varint(1, field1)
        + _f_varint(2, field2)
        + _f_string(3, model)
        + _f_string(4, os_version)
        + _f_string(5, build)
    )


# ----- outer negotiatorOffer bplist ---------------------------------------


def build_negotiator_offer_audio(
    call_id: str,
    session_id: int,
    host_model: str = "Mac16,11",
    host_os_version: str = "2205.3.1",
    host_build: str = "25F80",
) -> bytes:
    """Audio counterpart of :func:`build_negotiator_offer_video`. Uses mode 6
    and the audio mediaBlob; the device's response confirms the audio session
    via ``source: {audioSystemOutput: {}}`` and ``RxPayloadType=101``."""
    endpoint_info = build_remote_endpoint_info(host_model, host_os_version, host_build)
    media_blob = build_media_blob_audio(session_id)
    compressed_blob = zlib.compress(media_blob, level=9)
    return plistlib.dumps(
        {
            "avcMediaStreamOptionRemoteEndpointInfo": endpoint_info,
            "avcMediaStreamNegotiatorMode": NEGOTIATOR_MODE_AUDIO,
            "avcMediaStreamNegotiatorMediaBlob": compressed_blob,
            "avcMediaStreamOptionCallID": call_id,
        },
        fmt=plistlib.FMT_BINARY,
    )


def build_negotiator_offer_video(
    call_id: str,
    session_id: int,
    # Default to the same identity Xcode uses (Mac15,9 = M2 Air, macOS 25F80).
    # The device may pick encoder parameters based on this -- under our
    # original Mac16,11 identity we saw frequent encoder stalls; under
    # Mac15,9 Xcode's mirror is rock-solid.
    host_model: str = "Mac15,9",
    host_os_version: str = "2205.3.1",
    host_build: str = "25F80",
    *,
    allow_rtcp_fb: bool = False,
    ltrp_enabled: bool = False,
    hevc_features: str = _DEFAULT_HEVC_FEATURES,
    avc_features: str = _DEFAULT_AVC_FEATURES,
) -> bytes:
    """Build the full ``negotiatorOffer`` bplist for a video stream.

    :param call_id: Unique UUID string for this call (``avcMediaStreamOptionCallID``).
    :param session_id: Random uint32 used inside the mediaBlob to identify this session.
    :param host_model: Host hardware model string (e.g. ``"Mac16,11"``).
    :param host_os_version: Host OS version (e.g. ``"2205.3.1"``).
    :param host_build: Host OS build (e.g. ``"25F80"``).
    :param allow_rtcp_fb: Pass through to :func:`build_media_blob_video`.
    :param ltrp_enabled: Pass through to :func:`build_media_blob_video`.
    :param hevc_features: HEVC capability string declared inside the bank.
    :param avc_features: AVC capability string declared inside the bank.
    """
    endpoint_info = build_remote_endpoint_info(host_model, host_os_version, host_build)
    media_blob = build_media_blob_video(
        session_id,
        allow_rtcp_fb=allow_rtcp_fb,
        ltrp_enabled=ltrp_enabled,
        hevc_features=hevc_features,
        avc_features=avc_features,
    )
    # Apple uses zlib level 9 (best). Default Python level (6) produces a
    # different byte stream and the device rejects it with "Invalid Parameter".
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


# ----- byte-equivalence regression test -----------------------------------
# Run with ``python -m pymobiledevice3.remote.core_device.media_stream_offer``
# to confirm the programmatic builder still matches the captured templates.

_CAPTURED_VIDEO_TEMPLATE = bytes.fromhex(
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
_CAPTURED_VIDEO_SESSION_ID = 2368635137

_CAPTURED_AUDIO_TEMPLATE = bytes.fromhex(
    "080110011a1208b4a1a5f70a1000180020ffbc0128003000320d56696365726f79"
    "20312e372e3040004a0908ea1f1000188080014a05080110ab024a0b080010808e"
    "ce1c188080104a05080410e4324a0b08001080dac409188080064a0b08001080c2"
    "d72f188080404a0a08001080b489131880604a0b080010809bee02188080084a05"
    "08101084204a0b080010c0d1e12318808020688080d2b28ebbdfe9ed0170028001"
    "00900101"
)
_CAPTURED_AUDIO_SESSION_ID = 2934526132


def _self_check() -> None:
    """Assert the builders can still reproduce the captured Xcode templates.

    The captured template had ``ltrp_enabled=True``; the default flipped to
    ``False`` after on-device probing showed the device honours the
    protobuf-level switch and LTRP-off eliminates mid-stream tearing under
    UDP loss. Pass ``ltrp_enabled=True`` here to keep the byte-equivalence
    regression check meaningful.
    """
    vid = build_media_blob_video(_CAPTURED_VIDEO_SESSION_ID, ltrp_enabled=True)
    assert vid == _CAPTURED_VIDEO_TEMPLATE, (
        f"video builder drifted from Xcode capture: "
        f"len(built)={len(vid)} vs len(captured)={len(_CAPTURED_VIDEO_TEMPLATE)}"
    )
    aud = build_media_blob_audio(_CAPTURED_AUDIO_SESSION_ID)
    assert aud == _CAPTURED_AUDIO_TEMPLATE, (
        f"audio builder drifted from Xcode capture: "
        f"len(built)={len(aud)} vs len(captured)={len(_CAPTURED_AUDIO_TEMPLATE)}"
    )


if __name__ == "__main__":
    _self_check()
    print("media_stream_offer: video + audio templates match Xcode capture")
    _ = time  # quiet "unused import" lint when only used by experimental callers
