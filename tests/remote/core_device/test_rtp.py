import pytest

from pymobiledevice3.remote.core_device.rtp import (
    extend_sequence,
    rtcp_pli,
    rtcp_receiver_report,
    rtcp_sdes,
    rtp_payload,
)

RTP_HEADER = bytes.fromhex("80600001000000000000002a")  # V=2, PT=96, seq 1, no CSRC, no extension


@pytest.mark.parametrize(
    ("packet", "payload"),
    [
        (RTP_HEADER + b"payload", b"payload"),
        (RTP_HEADER, b""),
        # two CSRCs
        (b"\x82" + RTP_HEADER[1:] + bytes(8) + b"payload", b"payload"),
        # an extension of one word
        (b"\x90" + RTP_HEADER[1:] + b"\xbe\xde\x00\x01" + bytes(4) + b"payload", b"payload"),
        # cut short inside the extension header
        (b"\x90" + RTP_HEADER[1:] + b"\xbe\xde", b""),
        # shorter than the fixed header
        (RTP_HEADER[:11], None),
        # RTCP receiver and sender reports (PT 200 and 201) on the RTP socket
        (b"\x80\xc8" + RTP_HEADER[2:] + b"report", None),
        (b"\x81\xc9" + RTP_HEADER[2:] + b"report", None),
    ],
)
def test_rtp_payload(packet: bytes, payload: bytes) -> None:
    assert rtp_payload(packet) == payload


def test_extend_sequence_counts_the_wraps() -> None:
    highest = 0
    for seq, expected in [(0xFFFE, 0xFFFE), (0xFFFF, 0xFFFF), (0, 0x10000), (1, 0x10001)]:
        highest = extend_sequence(highest, seq)
        assert highest == expected


def test_extend_sequence_is_not_moved_back_by_a_late_packet() -> None:
    assert extend_sequence(0x10005, 3) == 0x10005
    assert extend_sequence(0x10005, 6) == 0x10006


def test_rtcp_packets_are_what_the_device_was_sent_before() -> None:
    """Recorded from the builders both servers had, each with a copy of its own."""
    assert rtcp_pli(0x11223344, 0xAABBCCDD).hex() == "81ce000211223344aabbccdd"
    assert rtcp_sdes(0x11223344).hex() == "81ca00021122334401000000"
    assert (
        rtcp_receiver_report(0x11223344, 0xAABBCCDD, 0x0001FFFE).hex()
        == "81c9000711223344aabbccdd000000000001fffe000000000000000000000000"
    )


def test_rtcp_packets_keep_32_bits_of_an_ssrc() -> None:
    assert rtcp_pli(0x1_0000_0001, 0).hex() == "81ce00020000000100000000"
    assert rtcp_sdes(0x1_0000_0001).hex() == "81ca00020000000101000000"
