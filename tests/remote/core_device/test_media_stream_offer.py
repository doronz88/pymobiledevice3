import re
import zlib

from pymobiledevice3.remote.core_device import media_stream_offer
from pymobiledevice3.remote.core_device.media_stream_offer import (
    build_media_blob_video,
    build_negotiator_offer_video,
)


def _codec_bank_features(blob: bytes) -> list[str]:
    """Return the ``FLS;...`` feature strings in codec-bank order."""
    return [m.group(0).decode() for m in re.finditer(rb"FLS;[A-Za-z0-9:;,/-]*", blob)]


def test_default_offer_does_not_forbid_resolution_adaptation() -> None:
    # ``VRAE:0`` makes the device encoder drop frames under motion (the browser
    # "smear"); the default offer must not declare it in either bank.
    blob = build_media_blob_video(0x12345678)
    assert _codec_bank_features(blob) == ["FLS;SW:1;", "FLS;SW:1;"]
    assert b"VRAE" not in blob


def test_feature_override_reaches_the_pt100_bank() -> None:
    blob = build_media_blob_video(0x12345678, avc_features="FLS;VRAE:0;SW:1;")
    assert _codec_bank_features(blob) == ["FLS;SW:1;", "FLS;VRAE:0;SW:1;"]


def test_video_blob_still_matches_xcode_capture() -> None:
    # The byte-equivalence regression check pins the builder to the captured
    # Xcode offer when asked for the capture's own knobs.
    media_stream_offer._self_check()


def test_negotiator_offer_embeds_default_blob() -> None:
    import plistlib

    offer = plistlib.loads(build_negotiator_offer_video("CALL-ID", 0x12345678))
    blob = zlib.decompress(offer["avcMediaStreamNegotiatorMediaBlob"])
    assert blob == build_media_blob_video(0x12345678)
    assert offer["avcMediaStreamNegotiatorMode"] == media_stream_offer.NEGOTIATOR_MODE_VIDEO
