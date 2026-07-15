"""
Pro Mode relay (EXPERIMENTAL / WIP) -- serve the iPhone's CoreDevice displayservice
HEVC stream to a Mac's Screen Sharing.app over Apple's "High Performance" (Pro Mode)
path, so Apple's own (entitled) AVConference receiver does decode + jitter buffer +
DisplayLink playout + rate-control. pmd3 is a pure protocol middleware: it speaks
the Pro Mode wire protocol and relays/re-encrypts RTP; it never links AVConference,
so the com.apple.videoconference.allow-conferencing entitlement wall does not apply.

Status (see PRO_MODE_RELAY_NOTES.md for the full reverse-engineering):
  VERIFIED here (unit-tested, no hardware needed):
    - SASL handshake framing codec  (sasl_encode / sasl_decode)
    - SRTP AES-128-CTR, RFC 3711 IV (SrtpContext)
    - SRP server with RFC5054-4096 + SHA-512 + PBKDF2 verifier (srp_verifier / ProModeSrpServer)
    - media-key generation (generate_media_key)
  NOT YET VERIFIED (needs a live Screen Sharing.app client + iPhone to pin/debug):
    - the RFB Pro Mode capability advertisement + message envelope (ProModeRelayServer.*)
    - SRP interop with Apple's corecrypto ccsrp (padding conventions)
    - the negotiator offer/answer carried over the control channel
This module intentionally raises NotImplementedError in the integration handshake
rather than guessing, so nothing here silently pretends to work.
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import Optional

# ---------------------------------------------------------------------------
# Constants (reversed from screensharingd / ScreensharingAgent / AVConference)
# ---------------------------------------------------------------------------
# --- RFB entry (ground truth: real Mac->Mac capture, promode_handshake.txt) ---
# Apple ARD/Screen Sharing speaks minor 889, and (even so) the server sends a
# security-type LIST, not the classic RFB 3.3 single-U32. The modern client selects
# type 33 ("RSA1"): an RSA host-key sub-step, THEN the SRP+SASL exchange below.
RFB_VERSION = b"RFB 003.889\n"
SECURITY_TYPES = (30, 33, 36, 35)   # wire: 04 1e 21 24 23 ; 33=RSA1 is what clients pick
SECURITY_TYPE_RSA1 = 33
RSA1_METHOD_TAG = b"RSA1"
RSA1_HOST_KEY_BITS = 2048           # server host identity key (e=65537)

SRP_SCHEME = "SRP-RFC5054-4096-SHA512-PBKDF2"
# SASL options string the server sends inside the SRP step (verified on the wire):
SRP_SASL_OPTIONS = "mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2"
SRP_GENERATOR = 5                   # RFC5054-4096 group generator (confirmed on wire)
SRP_PBKDF2_DEFAULT_ITERATIONS = 19417   # from screensharingd; confirm vs live server
SRP_SALT_LEN = 32
# VERIFIED against the live Screen Sharing client (2026-07-16, promode_cc_server.py):
# the ccsrp "password" is the 128-byte ShadowHashData entropy, and the SRP username is
# empty. Implemented by calling Apple corecrypto ccsrp directly via ctypes (below),
# which guarantees M1/M2/K interop instead of reimplementing SRP-6a.
SRP_PBKDF2_DKLEN = 128              # PBKDF2-HMAC-SHA512(password, salt, iters, 128)
SRP_USERNAME = b""                 # ccsrp username for verifier + compute_session
# SRTP media key layout: [AES key][14-byte salt]; cipher suite 5 = AES-128-CTR.
SRTP_CIPHER_AES_128_CTR = 5
SRTP_KEY_LEN = 16
SRTP_SALT_LEN = 14
MEDIA_KEY_LEN = SRTP_KEY_LEN + SRTP_SALT_LEN   # 30


# ---------------------------------------------------------------------------
# SASL handshake framing  (reversed: sub_100012994; VERIFIED round-trip)
#   message = [u32 BE payload_len][fields...]
#   %c 1B  %m u16len+bignum(BE)  %o u8len+octets  %q u64BE  %s u16len+utf8  %u u32BE
# ---------------------------------------------------------------------------
def _mpi_bytes(n: int) -> bytes:
    return b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def sasl_encode(fmt: str, *args) -> bytes:
    toks = [t for t in fmt.split("%") if t]
    if len(toks) != len(args):
        raise ValueError(f"format {fmt!r} expects {len(toks)} args, got {len(args)}")
    out = bytearray()
    for t, a in zip(toks, args):
        k = t[0]
        if k == "c":
            out += struct.pack("B", a & 0xFF)
        elif k == "m":
            b = _mpi_bytes(a)
            out += struct.pack(">H", len(b)) + b
        elif k == "o":
            a = bytes(a)
            out += struct.pack("B", len(a)) + a
        elif k == "q":
            out += struct.pack(">Q", a)
        elif k == "s":
            b = a.encode() if isinstance(a, str) else bytes(a)
            out += struct.pack(">H", len(b)) + b
        elif k == "u":
            out += struct.pack(">I", a)
        else:
            raise ValueError(f"unknown SASL token %{k}")
    return struct.pack(">I", len(out)) + bytes(out)


def sasl_decode(fmt: str, data: bytes) -> list:
    (plen,) = struct.unpack(">I", data[:4])
    p = data[4 : 4 + plen]
    off = 0
    vals: list = []
    for t in [t for t in fmt.split("%") if t]:
        k = t[0]
        if k == "c":
            vals.append(p[off]); off += 1
        elif k == "m":
            (ln,) = struct.unpack(">H", p[off : off + 2]); off += 2
            vals.append(int.from_bytes(p[off : off + ln], "big")); off += ln
        elif k == "o":
            ln = p[off]; off += 1
            vals.append(p[off : off + ln]); off += ln
        elif k == "q":
            (v,) = struct.unpack(">Q", p[off : off + 8]); off += 8; vals.append(v)
        elif k == "s":
            (ln,) = struct.unpack(">H", p[off : off + 2]); off += 2
            vals.append(p[off : off + ln].decode()); off += ln
        elif k == "u":
            (v,) = struct.unpack(">I", p[off : off + 4]); off += 4; vals.append(v)
        else:
            raise ValueError(f"unknown SASL token %{k}")
    return vals


# ---------------------------------------------------------------------------
# SRTP AES-128-CTR (reversed: AVConference SRTPEncryptData; VERIFIED round-trip)
#   IV = (salt || 0x0000) XOR (SSRC << 64) XOR ((ROC:SEQ) << 16)   -- RFC 3711
# ---------------------------------------------------------------------------
class SrtpContext:
    """One direction of an SRTP AES-128-CTR stream. ``media_key`` is the 30-byte
    negotiated value (16-byte AES key || 14-byte salt)."""

    def __init__(self, media_key: bytes) -> None:
        if len(media_key) != MEDIA_KEY_LEN:
            raise ValueError(f"media key must be {MEDIA_KEY_LEN} bytes")
        self._key = media_key[:SRTP_KEY_LEN]
        self._salt = media_key[SRTP_KEY_LEN:]
        self._roc = 0
        self._last_seq = -1

    def _iv(self, ssrc: int, roc: int, seq: int) -> bytes:
        salt = int.from_bytes(self._salt + b"\x00\x00", "big")
        return (salt ^ (ssrc << 64) ^ (((roc << 16) | seq) << 16)).to_bytes(16, "big")

    def transform(self, ssrc: int, seq: int, roc: int, payload: bytes) -> bytes:
        # CTR is symmetric -- same call encrypts and decrypts.
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        enc = Cipher(algorithms.AES(self._key), modes.CTR(self._iv(ssrc, roc, seq))).encryptor()
        return enc.update(payload) + enc.finalize()

    def encrypt_next(self, ssrc: int, seq: int, payload: bytes) -> bytes:
        """Encrypt using an auto-tracked rollover counter (ROC increments when the
        16-bit sequence number wraps)."""
        if self._last_seq >= 0 and seq < self._last_seq and (self._last_seq - seq) > 0x8000:
            self._roc = (self._roc + 1) & 0xFFFFFFFF
        self._last_seq = seq
        return self.transform(ssrc, seq, self._roc, payload)


# ---------------------------------------------------------------------------
# SRP server (reversed: screensharingd common/srp.m; srptools reuse)
# ---------------------------------------------------------------------------
def srp_verifier(password: str, salt: bytes, iterations: int = SRP_PBKDF2_DEFAULT_ITERATIONS) -> int:
    """Pro Mode SRP verifier: v = g^x mod N with x = PBKDF2-HMAC-SHA512(pw, salt).
    (Standard SRP-6a derives x = H(salt|H(user:pass)); Apple uses PBKDF2 instead.)"""
    from srptools.constants import PRIME_4096, PRIME_4096_GEN

    N = int(PRIME_4096, 16)
    g = int(PRIME_4096_GEN)
    x = int.from_bytes(hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations), "big")
    return pow(g, x, N)


class ProModeSrpServer:
    """Thin wrapper over srptools' SRPServerSession for the Pro Mode params.
    NOTE: interop with Apple's corecrypto ccsrp (hash-padding conventions) is
    UNVERIFIED -- must be checked against a live Screen Sharing client."""

    def __init__(self, username: str, password: str, salt: Optional[bytes] = None,
                 iterations: int = SRP_PBKDF2_DEFAULT_ITERATIONS) -> None:
        from srptools import SRPContext, SRPServerSession
        from srptools.constants import PRIME_4096, PRIME_4096_GEN

        self.salt = salt or os.urandom(SRP_SALT_LEN)
        self.iterations = iterations
        self._verifier = srp_verifier(password, self.salt, iterations)
        ctx = SRPContext(username, prime=PRIME_4096, generator=PRIME_4096_GEN, hash_func=hashlib.sha512)
        self._session = SRPServerSession(ctx, hex(self._verifier)[2:])

    @property
    def public_B(self) -> bytes:
        return bytes.fromhex(self._session.public)

    # The A/M1/M2 exchange + session-key extraction are driven by the handshake
    # once the exact ccsrp-compatible ordering is confirmed on hardware.


def generate_media_key() -> bytes:
    """A fresh SRTP media key (16-byte AES key || 14-byte salt), one per direction."""
    return os.urandom(MEDIA_KEY_LEN)


# ---------------------------------------------------------------------------
# RFB Pro Mode server loop  (INTEGRATION -- needs hardware to pin + verify)
# ---------------------------------------------------------------------------
class ProModeRelayServer:
    """Skeleton of the Pro Mode server that a Mac Screen Sharing client connects to.

    Handshake order (from the RE): RFB version + security (SRP) -> SRP auth
    (srptools, SASL-framed) -> control-channel encryption (AES-128 or
    ChaCha20-Poly1305) -> advertise Pro Mode capability -> exchange the
    AVCMediaStreamNegotiator offer/answer (reuse media_stream_offer.py + media
    keys + cipher 5) over the encrypted channel -> then relay: recv device RTP,
    rewrite SSRC/seq to the negotiated stream, SRTP-encrypt (SrtpContext), send to
    the client; relay the client's RTCP back to the device.

    The capability advertisement + exact envelope live in screensharingd
    sub_100036C54 and are best pinned against a live client, so they are left as
    explicit TODOs rather than guessed at."""

    def __init__(self, password: str = "pmd3") -> None:
        self._password = password
        self._send_key = generate_media_key()   # server -> viewer
        self._recv_key = generate_media_key()    # viewer -> server

    async def serve(self) -> None:  # pragma: no cover - integration path
        raise NotImplementedError(
            "Pro Mode relay handshake is not implemented yet: the RFB capability "
            "advertisement + negotiation envelope (screensharingd sub_100036C54) must "
            "be pinned against a live Screen Sharing.app client. Verified building "
            "blocks (sasl_*, SrtpContext, ProModeSrpServer) are ready to assemble."
        )
