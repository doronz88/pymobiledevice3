import os

import pytest

from pymobiledevice3.remote.core_device.pro_mode_relay import (
    MEDIA_KEY_LEN,
    ProModeSrpServer,
    SrtpContext,
    generate_media_key,
    sasl_decode,
    sasl_encode,
    srp_verifier,
)


def test_sasl_roundtrip_step1_and_step2() -> None:
    salt = bytes(range(32))
    step1 = ("%c%m%m%o%m%q%s", 1, 0xEEAF0AB9, 5, salt, 0x1234567890ABCDEF, 0xAABBCCDD11223344,
             "SRP-RFC5054-4096-SHA512-PBKDF2")
    fmt, *args = step1
    buf = sasl_encode(fmt, *args)
    assert sasl_decode(fmt, buf) == list(args)
    # payload length prefix excludes itself
    assert int.from_bytes(buf[:4], "big") == len(buf) - 4

    ev, siv = bytes(range(64)), bytes(range(16))
    buf2 = sasl_encode("%o%o%s%u", ev, siv, "opts", 64)
    assert sasl_decode("%o%o%s%u", buf2) == [ev, siv, "opts", 64]


def test_srtp_aes_ctr_roundtrip_and_symmetry() -> None:
    key = generate_media_key()
    assert len(key) == MEDIA_KEY_LEN == 30
    ssrc, seq = 0x11223344, 5
    payload = os.urandom(1400)
    enc = SrtpContext(key)
    dec = SrtpContext(key)
    ct = enc.transform(ssrc, seq, 0, payload)
    assert ct != payload
    assert dec.transform(ssrc, seq, 0, ct) == payload  # CTR symmetric


def test_srtp_rollover_counter_increments_on_wrap() -> None:
    ctx = SrtpContext(generate_media_key())
    ctx.encrypt_next(1, 0xFFFE, b"a")
    ctx.encrypt_next(1, 0xFFFF, b"b")
    assert ctx._roc == 0
    ctx.encrypt_next(1, 0x0000, b"c")  # wrapped
    assert ctx._roc == 1


def test_srp_verifier_and_server_public() -> None:
    salt = os.urandom(32)
    v = srp_verifier("secret", salt, iterations=19417)
    assert v.bit_length() > 4000  # 4096-bit group
    srv = ProModeSrpServer("user", "secret", salt=salt)
    assert len(srv.public_B) == 512  # 4096-bit B


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
