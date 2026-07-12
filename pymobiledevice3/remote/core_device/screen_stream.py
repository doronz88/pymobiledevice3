"""
Live screen-stream server and helpers, sitting on top of :class:`DisplayService`.

Layering::

    DisplayService.start_video_stream()   ← device interaction (see display_service.py)
              ↓ produces UDP RTP/HEVC packets
    ─────────────────────────────────────  ← this module starts here
    asyncio UDP receive → RFC 7798 RTP/HEVC depacketize → access units
    cache initial VPS/SPS/PPS+IDR + parse SPS for WebCodecs codec string
    HTTP chunked broadcast to subscribers
    Built-in HTML viewer page using WebCodecs (OS hardware decoder)
"""

import asyncio
import base64
import contextlib
import datetime
import errno
import importlib.resources
import ipaddress
import json
import logging
import os
import socket
import ssl
import tempfile
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Optional, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pymobiledevice3.resources
from pymobiledevice3.remote.core_device.aac_eld import AAC_ELD_ASC_48K_STEREO_480, AACELDDecoder
from pymobiledevice3.remote.core_device.configuration_service import ConfigurationService
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.hid_service import (
    DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
    HID_BUTTON_STATE_DOWN,
    HID_BUTTON_STATE_UP,
    TOUCHSCREEN_STATE_CONTACT,
    TOUCHSCREEN_STATE_RELEASE,
    IndigoHIDService,
    UniversalHIDServiceService,
)
from pymobiledevice3.remote.core_device.orientation_service import OrientationService
from pymobiledevice3.remote.core_device.pasteboard_service import PasteboardService, snapshot_text
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.power_assertion import PowerAssertionService
from pymobiledevice3.tunneld.api import get_tunneld_device_by_udid

_TUNNEL_DEAD_ERRNOS = {
    errno.EHOSTUNREACH,
    errno.EHOSTDOWN,
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.ECONNABORTED,
    errno.ENETUNREACH,
    errno.ENETDOWN,
    errno.ETIMEDOUT,
    errno.EPIPE,
}


def _is_tunnel_dead_error(exc: BaseException) -> bool:
    """Return True if *exc* (or any of its causes) is a "tunnel went away"
    failure — i.e. the device-side QUIC endpoint is unreachable and no
    amount of stream-level restart can recover. The caller should hand
    off to the reconnect loop, which waits for tunneld to surface the
    same UDID again."""
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return True
        if isinstance(cur, asyncio.IncompleteReadError):
            return True
        if isinstance(cur, OSError) and cur.errno in _TUNNEL_DEAD_ERRNOS:
            return True
        cur = cur.__cause__ or cur.__context__
    return False


# Named iOS hardware buttons → (usage_page, usage_code, hold_seconds).
# Mirrors the table in cli/developer/core_device.py so the browser viewer
# can offer a friendly UI.
#
# ``hold_seconds`` is how long to keep the button "pressed" between the
# DOWN and UP IndigoButtonEvents. Most buttons want a near-instant tap
# (0.05 s -- long enough that iOS doesn't reject it as a debounce
# bounce, short enough to feel like a tap). Lock and Siri are explicit
# press-and-holds: iOS won't sleep / start Siri on a microsecond-long
# tap, because the same usage on real hardware is "side button held for
# N ms". Empirically, 0.5 s sleeps the device, 1.0 s starts Siri.
_NAMED_BUTTONS: dict[str, tuple[int, int, float]] = {
    "home": (0x0C, 0x40, 0.05),
    "lock": (0x0C, 0x30, 0.5),
    "volume-up": (0x0C, 0xE9, 0.05),
    "volume-down": (0x0C, 0xEA, 0.05),
    "mute": (0x0C, 0xE2, 0.05),
    "siri": (0x0C, 0xCF, 1.0),
}

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HEVC NAL helpers (RFC 7798 RTP/HEVC + ISO/IEC 14496-15 §A.3.3.1)
# ---------------------------------------------------------------------------
_HEVC_NAL_IDR_W_RADL = 19
_HEVC_NAL_IDR_N_LP = 20
_HEVC_NAL_CRA = 21
_HEVC_NAL_VPS = 32
_HEVC_NAL_SPS = 33
_HEVC_NAL_PPS = 34
_HEVC_NAL_AP = 48  # Aggregation Packet
_HEVC_NAL_FU = 49  # Fragmentation Unit


def _is_key_nal(nal_type: int) -> bool:
    return nal_type in (_HEVC_NAL_IDR_W_RADL, _HEVC_NAL_IDR_N_LP, _HEVC_NAL_CRA)


def depacketize_hevc(payload: bytes, fu_buffer: bytearray, nal_out: list[bytes]) -> None:
    """Process one RTP/HEVC payload (RFC 7798) — emit complete NAL units."""
    if len(payload) < 2:
        return
    nal_type = (payload[0] >> 1) & 0x3F
    if nal_type == _HEVC_NAL_AP:
        i = 2
        while i + 2 <= len(payload):
            size = int.from_bytes(payload[i : i + 2], "big")
            i += 2
            nal_out.append(payload[i : i + size])
            i += size
    elif nal_type == _HEVC_NAL_FU:
        fu_header = payload[2]
        start = fu_header & 0x80
        end = fu_header & 0x40
        original_nal_type = fu_header & 0x3F
        if start:
            orig_byte0 = (payload[0] & 0x81) | (original_nal_type << 1)
            orig_byte1 = payload[1]
            fu_buffer[:] = bytes([orig_byte0, orig_byte1]) + payload[3:]
        else:
            fu_buffer.extend(payload[3:])
        if end and fu_buffer:
            nal_out.append(bytes(fu_buffer))
            fu_buffer.clear()
    else:
        nal_out.append(payload)


def hevc_codec_string_from_sps(sps_nal: bytes) -> str:
    """Parse the HEVC SPS NAL unit and return the WebCodecs codec string.

    Format: ``hev1.<profile_space><profile_idc>.<reversed_pcf>.<tier><level>.<constraint_indicator>``
    per ISO/IEC 14496-15 §A.3.3.1.
    """
    # remove emulation prevention bytes (00 00 03 → 00 00)
    rb = bytearray()
    i = 2  # skip 2-byte NAL header
    while i < len(sps_nal):
        if i + 2 < len(sps_nal) and sps_nal[i] == 0 and sps_nal[i + 1] == 0 and sps_nal[i + 2] == 3:
            rb.extend(sps_nal[i : i + 2])
            i += 3
        else:
            rb.append(sps_nal[i])
            i += 1

    pos = 0

    def read_bits(n: int) -> int:
        nonlocal pos
        v = 0
        for _ in range(n):
            v = (v << 1) | ((rb[pos >> 3] >> (7 - (pos & 7))) & 1)
            pos += 1
        return v

    read_bits(4)  # sps_video_parameter_set_id
    read_bits(3)  # sps_max_sub_layers_minus1
    read_bits(1)  # sps_temporal_id_nesting_flag
    profile_space = read_bits(2)
    tier_flag = read_bits(1)
    profile_idc = read_bits(5)
    pcf = read_bits(32)
    cif = read_bits(48)
    level_idc = read_bits(8)

    rev = 0
    x = pcf
    for _ in range(32):
        rev = (rev << 1) | (x & 1)
        x >>= 1
    ps_char = "ABCD"[profile_space] if profile_space else ""
    tier_char = "H" if tier_flag else "L"
    cif_hex = f"{cif:012X}"
    while len(cif_hex) > 2 and cif_hex.endswith("00"):
        cif_hex = cif_hex[:-2]
    return f"hev1.{ps_char}{profile_idc}.{rev:X}.{tier_char}{level_idc}.{cif_hex}"


def _hevc_rbsp(nal: bytes) -> bytes:
    """Strip the 2-byte NAL header and emulation-prevention bytes (00 00 03 → 00 00)."""
    out = bytearray()
    i = 2
    while i < len(nal):
        if i + 2 < len(nal) and nal[i] == 0 and nal[i + 1] == 0 and nal[i + 2] == 3:
            out.extend(nal[i : i + 2])
            i += 3
        else:
            out.append(nal[i])
            i += 1
    return bytes(out)


def hevc_decoder_configuration_record(vps: bytes, sps: bytes, pps: bytes) -> bytes:
    """Build an ISO/IEC 14496-15 §8.3.3.1 ``HEVCDecoderConfigurationRecord`` (hvcC).

    This is the WebCodecs ``description`` for hvcC-mode HEVC decoding: it routes
    Chrome's ``VideoDecoder`` through VideoToolbox's native hvcC path (parameter
    sets supplied out-of-band, 4-byte-length-prefixed NALUs per chunk) instead
    of the Annex-B start-code path, which re-converts every chunk and visibly
    tears under rapid motion (Safari, which uses VideoToolbox directly, does not
    tear — confirming the Annex-B path as the culprit).

    The 12-byte general ``profile_tier_level`` lives at RBSP bytes 1..12 of the
    SPS (right after the 1-byte vps_id/max_sub_layers/nesting field) with the
    exact byte layout hvcC wants, so we copy it verbatim rather than re-parsing.
    """
    ptl = _hevc_rbsp(sps)[1:13]
    if len(ptl) != 12:
        raise ValueError("SPS too short to contain profile_tier_level")
    rec = bytearray()
    rec.append(1)  # configurationVersion
    rec.append(ptl[0])  # general_profile_space(2) | general_tier_flag(1) | general_profile_idc(5)
    rec.extend(ptl[1:5])  # general_profile_compatibility_flags (32b)
    rec.extend(ptl[5:11])  # general_constraint_indicator_flags (48b)
    rec.append(ptl[11])  # general_level_idc
    rec.extend((0xF000).to_bytes(2, "big"))  # reserved(4)=1111 + min_spatial_segmentation_idc=0
    rec.append(0xFC)  # reserved(6)=1 + parallelismType=0
    rec.append(0xFC | 0x01)  # reserved(6)=1 + chroma_format_idc=1 (4:2:0)
    rec.append(0xF8)  # reserved(5)=1 + bit_depth_luma_minus8=0
    rec.append(0xF8)  # reserved(5)=1 + bit_depth_chroma_minus8=0
    rec.extend((0).to_bytes(2, "big"))  # avgFrameRate=0 (unspecified)
    # constantFrameRate(2)=0 | numTemporalLayers(3)=1 | temporalIdNested(1)=0 | lengthSizeMinusOne(2)=3
    rec.append((0 << 6) | (1 << 3) | (0 << 2) | 0x03)
    rec.append(3)  # numOfArrays: VPS, SPS, PPS
    for nal_type, nal in ((32, vps), (33, sps), (34, pps)):
        # array_completeness(1)=0 | reserved(1)=0 | NAL_unit_type(6). hev1 => in-band PS allowed.
        rec.append(nal_type)
        rec.extend((1).to_bytes(2, "big"))  # numNalus
        rec.extend(len(nal).to_bytes(2, "big"))  # nalUnitLength
        rec.extend(nal)
    return bytes(rec)


# ---------------------------------------------------------------------------
# Built-in HTML viewer (Canvas + WebCodecs decoder)
# ---------------------------------------------------------------------------
# The viewer is three files under ``pymobiledevice3/resources/serve_web/`` --
# ``viewer.html`` (markup), ``viewer.css`` (styling), ``viewer.js`` (the
# WebCodecs decoder + input/audio wiring). The HTTP server below serves
# each at ``/``, ``/viewer.css`` and ``/viewer.js``. Edit the files
# directly; this module just hands them out.
_VIEWER_DIR = importlib.resources.files(pymobiledevice3.resources) / "serve_web"
VIEWER_HTML = (_VIEWER_DIR / "viewer.html").read_bytes()
VIEWER_CSS = (_VIEWER_DIR / "viewer.css").read_bytes()
VIEWER_JS_TEMPLATE = (_VIEWER_DIR / "viewer.js").read_bytes()


# ---------------------------------------------------------------------------
# Self-signed HTTPS for the WebCodecs secure-context requirement
# ---------------------------------------------------------------------------
# Browsers refuse to expose WebCodecs on plain http:// from any origin that
# isn't a loopback address. To make the viewer reachable from another machine
# on the LAN we need TLS. Generate an ephemeral RSA-2048 self-signed cert
# covering the bind address + common SANs; the browser will warn on first
# visit and remember the override after the user accepts it. (ed25519 was
# tried first and produced "connection unexpectedly closed" errors in some
# Chrome/Safari builds -- ed25519 server certs are still spotty in 2026.)
def _build_self_signed_ssl_context(bind: str) -> ssl.SSLContext:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pymobiledevice3 serve-web")])
    san_entries: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    # If bind is a concrete address, include it; if it's the 0.0.0.0 wildcard,
    # enumerate every local interface IP so the cert SAN covers whatever LAN
    # address the user types in their browser. Without this Chrome shows a
    # "Not private" warning for the typed IP even when the cert would otherwise
    # be acceptable, and Safari may refuse the connection outright.
    extra: set[str] = set()
    if bind and bind not in ("0.0.0.0", "::"):
        extra.add(bind)
    else:
        with contextlib.suppress(OSError):
            for info in socket.getaddrinfo(socket.gethostname(), None):
                extra.add(info[4][0])
        # Probe the routable outbound IP via a UDP socket (no packets actually
        # sent -- `connect` on UDP just fills the local address from routing).
        with contextlib.suppress(OSError):
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect(("8.8.8.8", 80))
                extra.add(probe.getsockname()[0])
            finally:
                probe.close()
    for ip in extra:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            san_entries.append(x509.DNSName(ip))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509
        .CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, algorithm=hashes.SHA256())
    )
    # ssl.SSLContext.load_cert_chain only accepts file paths, not bytes. Drop
    # the PEM into a closed-then-unlinked tempfile and load before deleting.
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(cert_pem + key_pem)
        path = f.name
    try:
        ctx.load_cert_chain(certfile=path, keyfile=path)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)
    return ctx


# ---------------------------------------------------------------------------
# Live RTP/HEVC capture (no transcoding) — used by ``start-video-stream``
# ---------------------------------------------------------------------------
async def capture_rtp_to_file(
    rsd: RemoteServiceDiscoveryService,
    output_path: Path,
    *,
    display_id: int = 1,
    duration: float = 5.0,
    receiver_port: int = 0,
) -> int:
    """Capture raw RTP packets from the device's screen-stream into a file.

    Each packet is written as ``[4-byte BE length][packet bytes]``. Returns the
    number of captured packets.
    """
    sender_ip = rsd.service.address[0]
    captured = 0
    async with DisplayService(rsd) as service:
        # Bind the RTP receiver on the right transport (pytcp stack over the userspace tunnel,
        # host kernel socket otherwise) and advertise the matching address to the device.
        transport, receiver_ip = open_media_receiver(
            service, (4 * 1024 * 1024, 1 * 1024 * 1024), bind_port=receiver_port
        )
        logger.info(f"Listening for RTP on [{receiver_ip}]:{transport.port}")
        try:
            answer = await service.start_video_stream(
                receiver_ip=receiver_ip,
                receiver_port=transport.port,
                sender_ip=sender_ip,
                display_id=display_id,
            )
            logger.info("Stream started; dumping RTP for %.1fs", duration)
            loop = asyncio.get_running_loop()
            with open(output_path, "wb") as fp:
                deadline = loop.time() + duration
                while loop.time() < deadline:
                    remaining = deadline - loop.time()
                    try:
                        data = await asyncio.wait_for(transport.recv(), timeout=remaining)
                    except asyncio.TimeoutError:
                        break
                    fp.write(len(data).to_bytes(4, "big") + data)
                    captured += 1
            logger.info(f"Captured {captured} packets to {output_path}")
            client_session_id = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
            if not isinstance(client_session_id, uuid.UUID):
                client_session_id = uuid.UUID(client_session_id)
            with contextlib.suppress(Exception):
                await service.stop_media_stream(client_session_id)
        finally:
            transport.close()
    return captured


async def capture_audio_rtp_to_file(
    rsd: RemoteServiceDiscoveryService,
    output_path: Path,
    *,
    duration: float = 10.0,
    receiver_port: int = 0,
) -> int:
    """Audio counterpart of :func:`capture_rtp_to_file`. Saves the raw RTP
    packets (length-prefixed) the device pushes for ``type='audio'``.

    The streamConfig the device returns advertises ``RxPayloadType=101`` and
    ``AudioStreamMode=8`` -- Apple AAC-ELD at 48 kHz stereo, 480 samples/frame
    (10 ms). Used by ``pymobiledevice3 ... display start-audio-stream``.
    """
    sender_ip = rsd.service.address[0]
    captured = 0
    async with DisplayService(rsd) as service:
        transport, receiver_ip = open_media_receiver(
            service, (4 * 1024 * 1024, 1 * 1024 * 1024), bind_port=receiver_port
        )
        logger.info(f"Listening for AUDIO RTP on [{receiver_ip}]:{transport.port}")
        try:
            answer = await service.start_audio_stream(
                receiver_ip=receiver_ip,
                receiver_port=transport.port,
                sender_ip=sender_ip,
            )
            cfg = answer["connection"].get("streamConfig", {})
            logger.info(
                "Audio stream started: PT=%s mode=%s sender_port=%s",
                cfg.get("RxPayloadType"),
                cfg.get("AudioStreamMode"),
                cfg.get("SourcePort"),
            )
            loop = asyncio.get_running_loop()
            with open(output_path, "wb") as fp:
                deadline = loop.time() + duration
                while loop.time() < deadline:
                    remaining = deadline - loop.time()
                    try:
                        data = await asyncio.wait_for(transport.recv(), timeout=remaining)
                    except asyncio.TimeoutError:
                        break
                    fp.write(len(data).to_bytes(4, "big") + data)
                    captured += 1
            logger.info(f"Captured {captured} audio packets to {output_path}")
            client_session_id = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
            if not isinstance(client_session_id, uuid.UUID):
                client_session_id = uuid.UUID(client_session_id)
            with contextlib.suppress(Exception):
                await service.stop_media_stream(client_session_id)
        finally:
            transport.close()
    return captured


class UdpMediaTransport(Protocol):
    """The UDP transport the device-initiated AV media streams (RTP) flow over.

    Two implementations: :class:`_KernelUdp` (host kernel socket, the default kernel-tunnel
    path) and ``userspace_tunnel.UserspaceUdp`` (a socket on the pytcp stack, for the no-root
    userspace tunnel). The media receive / RTCP loops are written against this interface so
    they are transport-agnostic.
    """

    @property
    def local_ip(self) -> str: ...

    @property
    def port(self) -> int: ...

    async def recv(self, bufsize: int = 65535) -> bytes: ...

    async def sendto(self, data: bytes, ip: str, port: int) -> None: ...

    def close(self) -> None: ...


class _KernelUdp:
    """:class:`UdpMediaTransport` over a host kernel UDP socket — the default kernel-tunnel path."""

    def __init__(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        self._sock = sock
        self._loop = asyncio.get_event_loop()

    @property
    def local_ip(self) -> str:
        return self._sock.getsockname()[0]

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    async def recv(self, bufsize: int = 65535) -> bytes:
        return await self._loop.sock_recv(self._sock, bufsize)

    async def sendto(self, data: bytes, ip: str, port: int) -> None:
        await self._loop.sock_sendto(self._sock, data, (ip, port, 0, 0))

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._sock.close()


def open_media_receiver(
    svc: DisplayService, rcvbuf_sizes: tuple[int, ...], bind_port: int = 0
) -> tuple[UdpMediaTransport, str]:
    """Open the UDP receiver the device streams RTP to, plus the address to advertise to it.

    Over the userspace tunnel the device-initiated RTP must terminate on the pytcp stack — a
    host kernel socket is unreachable from the device — so bind a socket on the stack and
    advertise the stack address. Otherwise bind a host kernel socket (sized from
    ``rcvbuf_sizes``, trying each until one is accepted) and advertise the RSD connection's
    local address.

    ``bind_port`` requests a specific host port on the kernel path; it is ignored over the
    userspace tunnel, where the stack socket always picks its own port (read it from
    ``transport.port``). Shared by every device-initiated media path (screen serve, RTP/audio
    capture, the HID auth-gate stream, VNC) so they are transport-agnostic and userspace-safe.
    """
    try:
        from pymobiledevice3.remote import userspace_tunnel

        if userspace_tunnel.USERSPACE_ACTIVE:
            if bind_port:
                logger.debug("userspace tunnel: ignoring requested receiver port %s (stack picks its own)", bind_port)
            transport = userspace_tunnel.UserspaceUdp()
            return transport, transport.local_ip
    except Exception:
        logger.debug("userspace UDP receiver unavailable; using a host kernel socket", exc_info=True)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(("::", bind_port))
    # Pump SO_RCVBUF as high as the kernel allows (capped by kern.ipc.maxsockbuf, ~8 MB on
    # macOS); a larger buffer tolerates longer event-loop stalls without kernel UDP drops.
    for size in rcvbuf_sizes:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
            break
        except OSError:
            continue
    return _KernelUdp(sock), svc.service.local_address[0]


# ---------------------------------------------------------------------------
# HTTP webserver that decodes in-browser via WebCodecs
# ---------------------------------------------------------------------------
class _SubState:
    """Per-subscriber broadcast state — set ``needs_key`` after a queue drop
    so we don't feed the decoder a delta without its reference keyframe.

    ``reset_on_key`` picks how the recovery keyframe is delivered once it
    arrives: True → type=2 (browser rebuilds its decoder first; used for
    fresh subscribers whose decoder started from a stale cached IDR), False
    → plain type=0 (the IDR is absorbed as a fresh DPB anchor; used after
    an upstream AU drop, where the browser's decoder never saw broken data
    and a rebuild would only add a visible hitch).

    ``needs_key_since`` is the loop-time of the last False→True
    transition; the stall watchdog uses it to spot a subscriber whose
    key request the encoder is ignoring and escalate to a session
    restart.
    """

    __slots__ = ("needs_key", "needs_key_since", "reset_on_key")

    def __init__(self) -> None:
        self.needs_key = False
        self.reset_on_key = False
        self.needs_key_since = 0.0

    def mark_needs_key(self, now: float) -> None:
        if not self.needs_key:
            self.needs_key = True
            self.needs_key_since = now


# Watchdog tuning. We learned the hard way that restarts are expensive --
# they churn the device's coredeviced and, if fired too frequently, wedge it
# into a state where new RemoteXPC handshakes time out and only a reboot
# recovers. So we err on the side of patience:
#
# - ``_STALL_RESTART_SECS``: only restart after a sustained gap, not a blip.
# - ``_STALL_RESTART_COOLDOWN_SECS``: long enough that legitimate idles
#   (locked device, no on-screen activity) don't loop us into a hot restart.
# - ``_MAX_STALL_RESTARTS``: an absolute backstop -- if this many restarts
#   in a row don't fix things, the device daemon is wedged and another
#   restart will just make it worse. Bail and require a manual page reload.
_STALL_RESTART_SECS = 5.0
_STALL_RESTART_COOLDOWN_SECS = 15.0
_MAX_STALL_RESTARTS = 3


class ScreenStreamServer:
    """Pure-stdlib HTTP server that broadcasts the device's screen stream to
    browsers using WebCodecs for in-browser HEVC decode.

    Pipeline::

        device → DisplayService.start_video_stream() → UDP RTP packets
        → asyncio.sock_recv → RFC 7798 RTP/HEVC depacketize
        → cache VPS/SPS/PPS+IDR as init sequence
        → parse SPS for WebCodecs codec string (``hev1.*``)
        → HTTP chunked stream of framed access units
        → browser fetch().getReader() → VideoDecoder → canvas
    """

    def __init__(
        self,
        rsd: RemoteServiceDiscoveryService,
        *,
        bind: str = "0.0.0.0",
        http_port: int = 8080,
        display_id: int = 1,
        audio_default_on: bool = True,
        allow_rtcp_fb: bool = False,
        ltrp_enabled: bool = False,
        https: bool = False,
        rctl_enabled: bool = False,
        max_bitrate_kbps: int = 60000,
        motion_idr: bool = True,
        compensate: bool = True,
    ) -> None:
        self._rsd = rsd
        # Viewer-side resolution-collapse compensation (--compensate, default
        # on): injected into viewer.js; the browser detects the shrunk content
        # rectangle and stretches it to fill the canvas. Server-side flag only
        # selects the viewer default.
        self._compensate = compensate
        # Mid-motion IDR refresh (--motion-idr/--no-motion-idr, ON by default).
        # Fires a keyframe ~1x/s while the screen is moving, so the device's
        # resolution collapse snaps back to full res fast (preemptive; faster
        # than any client-side detect-then-request loop). The viewer hides the
        # brief shrink until the IDR lands (viewer.js detectContentCrop). Trade
        # off: keyframe pressure can stall the ~6 Mbps-capped encoder under
        # sustained motion; --no-motion-idr drops it for a stall-free but
        # slower-recovering stream. See _decoder_refresh_loop.
        self._motion_idr = motion_idr
        # AVConference RCTL receiver feedback (see _rctl_feedback_loop): the
        # closed-loop rate-control channel Xcode's mirror uses, reversed from a
        # live capture. ``max_bitrate_kbps`` is the cap advertised to the
        # device, which honours it (confirmed on-device: dropping it collapses
        # the encoder bitrate). The uncapped encoder can ramp past ~5.5 Mbps
        # under sustained motion and stall; lowering this (e.g. 5000) trades
        # peak quality for a steadier stream.
        self._rctl_enabled = rctl_enabled
        self._rctl_maxk = max_bitrate_kbps
        self._bind = bind
        self._http_port = http_port
        self._display_id = display_id
        self._audio_default_on = audio_default_on
        self._https = https
        # Protobuf-level negotiation knobs forwarded to every
        # ``DisplayService.start_video_stream`` we issue. ``ltrp_enabled=False``
        # default came out of on-device probing: the device honours the
        # request and LTRP-off eliminates mid-stream tearing under UDP loss.
        # See media_stream_offer.py for the full schema notes.
        self._allow_rtcp_fb = allow_rtcp_fb
        self._ltrp_enabled = ltrp_enabled
        self._sender_ip = rsd.service.address[0]

        # Broadcast state — each subscriber gets framed access units written as:
        #   [4-byte BE length] [1-byte type: 0=key, 1=delta] [Annex-B HEVC bytes]
        # A subscriber that falls behind has its queue cleared and its
        # ``needs_key`` flag set; we then hold further frames until the next
        # keyframe arrives so the decoder never sees a delta without a key.
        self._subscribers: dict[asyncio.Queue[bytes], _SubState] = {}
        self._init_sequence: Optional[bytes] = None
        self._codec_string: Optional[str] = None
        # Cached parameter-set NALs for the hvcC decoder-configuration record
        # (WebCodecs ``description``). Latest VPS/SPS/PPS seen on the stream.
        self._vps_nal: Optional[bytes] = None
        self._sps_nal: Optional[bytes] = None
        self._pps_nal: Optional[bytes] = None
        self._saw_first_key = False
        self._stream_ready = asyncio.Event()

        # Active device-stream session.
        self._active_service: Optional[DisplayService] = None
        self._active_session_id: Optional[uuid.UUID] = None
        self._active_sock: Optional[UdpMediaTransport] = None
        self._active_recv_task: Optional[asyncio.Task] = None
        self._active_rtcp_task: Optional[asyncio.Task] = None
        self._stream_lock = asyncio.Lock()
        self._stream_dirty = True  # True → next request must restart the stream

        # Audio stream session (parallel to video, started lazily when a
        # browser tab subscribes to /audio.bin). Each AAC-ELD AU is
        # broadcast as a length-prefixed chunk.
        self._audio_service: Optional[DisplayService] = None
        self._audio_session_id: Optional[uuid.UUID] = None
        self._audio_sock: Optional[UdpMediaTransport] = None
        self._audio_recv_task: Optional[asyncio.Task] = None
        self._audio_subscribers: dict[asyncio.Queue[bytes], None] = {}
        self._audio_lock = asyncio.Lock()
        # Audio RTCP bookkeeping -- parallel to the video fields below.
        # The device's audio streamConfig has the same RTCPTimeoutEnabled
        # + RTCPTimeoutInterval=20s as video; without a periodic RR the
        # audio session gets reaped after ~20 s (the encoder stops
        # emitting RTP audio and mediastreamstatus drops the session).
        self._audio_rtcp_dest: Optional[tuple[str, int]] = None
        self._audio_local_ssrc: int = 0
        self._audio_remote_ssrc: int = 0
        self._audio_rtp_highest_seq: int = 0
        self._audio_rtp_packets_received: int = 0
        self._audio_rtcp_task: Optional[asyncio.Task] = None
        # Xcode's Mirror uses ONE client_session_id for both the audio
        # and video mediastreamstart calls (confirmed verbatim in the
        # remotexpc-sniff4 capture: same UUID in both 'CoreDevice.input'
        # payloads). Pairing them on the device's media-session manager
        # is what marks us as a real Mirror client rather than two
        # unrelated callers; without it iOS may treat the lone video
        # session as a second-class consumer and throttle the encoder.
        self._shared_session_id: uuid.UUID = uuid.uuid4()

        # RTCP feedback bookkeeping. The streamConfig the device returns sets
        # ``RTCPTimeoutEnabled=True`` -- without periodic Receiver Reports the
        # encoder stalls after a few tens of seconds. Filled in when the
        # stream starts; the RTCP task reads them.
        self._rtcp_dest: Optional[tuple[str, int]] = None  # (ipv6, port)
        self._local_ssrc: int = 0
        self._remote_ssrc: int = 0
        self._rtp_highest_seq: int = 0  # extended (cycles<<16 | seq16)
        self._rtp_packets_received: int = 0
        self._rtp_last_ts: int = 0
        self._rtp_frames_received: int = 0
        self._rctl_start_t: float = 0.0
        # Per-frame packet count (RCTL w3) + RFC 3550 interarrival jitter in
        # 24 kHz RTP-ts units (RCTL w4-lo), decoded byte-exact from Xcode's
        # mirror. Feeding the device real values (vs our old 0/constant) is what
        # keeps its rate controller from throttling framerate / collapsing res.
        self._rtp_cur_frame_pkts: int = 0
        self._rtp_last_frame_pkts: int = 0
        self._rtp_jitter: float = 0.0
        self._rtp_prev_transit: Optional[float] = None
        self._rctl_task: Optional[asyncio.Task] = None
        # PLI tasks in flight -- keep a reference so the GC doesn't drop
        # them while awaiting the sendto (and ruff is happy with create_task).
        self._pli_tasks: set[asyncio.Task] = set()
        # Timestamp of the last PLI we sent. The refresh loop paces its
        # triggers on it, and the recovery paths rate-limit on it so a
        # loss burst / slow subscriber / stuck client can't turn into a
        # PLI storm.
        self._last_refresh_t: float = 0.0
        # (timestamp, AU bytes) entries pruned to the last 1 s -- the
        # refresh loop's motion detector, also logged with every PLI so
        # post-mortems can tell a quiet-screen PLI from a mid-motion one.
        self._au_byte_window: deque = deque()

        # Lazy-opened HID services for browser-driven touch / buttons. The
        # auth gate is already held open by the active media stream above,
        # so we don't need :func:`hid_service.touch_session`.
        self._uhs: Optional[UniversalHIDServiceService] = None
        self._indigo: Optional[IndigoHIDService] = None
        self._hid_lock = asyncio.Lock()
        # _ServiceID dtuhidd assigned to our host-registered virtual
        # keyboard. Lazily filled on the first /key POST.
        self._kb_service_id: Optional[int] = None

        # HID input queue. We accept /touch /button /key POSTs into this
        # queue and return 200 immediately, then a single worker task
        # dispatches them via the XPC connection. This decouples HTTP
        # handling latency from device-write latency so a touch flood
        # can't starve the stream-broadcast loop.
        self._hid_queue: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()
        self._hid_worker_task: Optional[asyncio.Task] = None

        # Stall-detection bookkeeping. Updated whenever an AU is forwarded;
        # the watchdog restarts the stream (forcing a fresh IDR) if no AU
        # has progressed within :data:`_STALL_RESTART_SECS` while we have
        # at least one subscriber attached.
        self._last_good_au_t: float = 0.0
        self._last_restart_t: float = 0.0
        self._consecutive_restarts: int = 0

        # Last value pushed for write-only knobs (deviceincreasecontrast
        # has no getter on the device). Lets /accessibility report the
        # value the user just set instead of going stale on reload.
        self._increase_contrast_last: bool = False
        # Serializes /accessibility reads/writes so the CoreDevice service
        # connections don't trample each other when the panel refreshes
        # mid-write.
        self._accessibility_lock = asyncio.Lock()

        # Background task that holds an IOPMAssertion on the device so
        # iOS auto-lock doesn't kick in mid-session. Without this the
        # display sleeps after the user's auto-lock timeout (typically
        # 30 s -- 2 min) and the encoder stops emitting AUs; restarts
        # also can't recover because a locked device won't start a
        # fresh DisplayService session cleanly.
        self._keep_awake_task: Optional[asyncio.Task] = None

        # Disconnect-recovery state. The stall watchdog sets
        # ``_reconnect_signal`` when it detects "tunnel is dead" errors
        # (e.g. the device left Wi-Fi or the upstream VPN dropped);
        # _reconnect_loop then tears the existing streams down, polls
        # tunneld for the same UDID, and rebinds ``self._rsd`` once the
        # device returns. Existing HTTP connections (viewer, /stream.bin)
        # keep running through the gap -- the browser's offline overlay
        # masks the freeze, and AUs resume after rebind.
        self._reconnect_signal = asyncio.Event()
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_poll_interval = 2.0

    # ----- per-session UDP receiver -----------------------------------------
    async def _udp_recv_and_depacketize(self, transport: UdpMediaTransport) -> None:
        loop = asyncio.get_running_loop()
        fu_buffer = bytearray()
        current_au: list[bytes] = []
        au_is_key = False
        nals: list[bytes] = []
        # Track RTP sequence numbers and drop the entire AU on any gap. We
        # learned the hard way that Apple's VideoToolbox is lenient about
        # missing slices — it renders the partial frame as a visible artifact
        # rather than throwing, so the browser-side resync never fires and
        # the corruption propagates through every subsequent delta until the
        # encoder happens to send a fresh IDR (which, on a busy stream, may
        # never happen).
        #
        # Dropping AUs means a brief picture freeze on each loss, recovered
        # at the encoder's next IDR. To bound the freeze when the encoder
        # is slow to emit a fresh key (or stops entirely), the dispatch loop
        # also restarts the whole media stream once we've held the picture
        # for more than ``_STALL_RESTART_SECS`` — see ``_stall_watchdog``.
        last_seq: Optional[int] = None
        au_corrupt = False
        # Stats for diagnosing the corruption pattern. Sampled into the log
        # every ~5 s — if forward_gaps >> reorders, it's true UDP loss; if
        # they're comparable, the QUIC carrier is reordering packets and we
        # need a small jitter buffer to recover them.
        stats_packets = 0
        stats_forward_gaps = 0
        stats_reorders = 0
        stats_corrupt_aus = 0
        stats_last_log = asyncio.get_running_loop().time()
        while True:
            try:
                data = await transport.recv(65535)
            except (OSError, asyncio.CancelledError):
                return
            except Exception:
                logger.exception("recv task crashed")
                return
            if len(data) < 12:
                continue
            pt = data[1] & 0x7F
            if 64 <= pt <= 95:  # RTCP
                continue
            marker = (data[1] >> 7) & 1
            cc = data[0] & 0x0F
            header_len = 12 + cc * 4
            if data[0] & 0x10:  # extension
                ext_len = int.from_bytes(data[header_len + 2 : header_len + 4], "big")
                header_len += 4 + ext_len * 4
            payload = data[header_len:]

            # Any RTP gap → discard the in-flight FU buffer (don't stitch
            # non-contiguous payloads into a single NAL) AND mark the whole
            # AU corrupt so we drop it at the next marker.
            seq = int.from_bytes(data[2:4], "big")
            stats_packets += 1
            # Maintain the extended highest-seq counter for RTCP RR.
            self._rtp_packets_received += 1
            # Latest received video RTP timestamp (24 kHz media clock) + frame
            # count -- echoed back in RCTL feedback so the device's rate
            # controller can track receiver progress. See _build_rctl_packet.
            self._rtp_last_ts = int.from_bytes(data[4:8], "big")
            # RFC 3550 interarrival jitter in the 24 kHz media clock (RCTL
            # w4-lo). transit = arrival(in ts units) - packet RTP ts; jitter is
            # the smoothed |delta transit|. Origin-independent (delta cancels).
            arrival_ts = time.monotonic() * 24000.0
            transit = arrival_ts - self._rtp_last_ts
            if self._rtp_prev_transit is not None:
                d = abs(transit - self._rtp_prev_transit)
                self._rtp_jitter += (d - self._rtp_jitter) / 16.0
            self._rtp_prev_transit = transit
            # Per-frame packet count (RCTL w3): packets since the last marker.
            self._rtp_cur_frame_pkts += 1
            if marker:
                self._rtp_frames_received += 1
                self._rtp_last_frame_pkts = self._rtp_cur_frame_pkts
                self._rtp_cur_frame_pkts = 0
                # Per-frame receipt (RTCP APP name=5): Xcode emits EXACTLY one
                # per frame (measured: receipt rate == frame rate), and the
                # device paces its output framerate to these acks. Our old
                # 40/s timer receipts desync from the real frame cadence, so the
                # device's congestion control reads it as delay and throttles
                # framerate under motion. Fire one here, on the frame boundary,
                # carrying this frame's ts.
                # Send it INLINE (awaited), NOT via create_task: a deferred send
                # piles up under motion and reaches the device after it has aged
                # the frame out of its sent-history window, so the device can't
                # map the receipt's ts to the frame's packet span -> credits ~1
                # of ~8 packets -> false ~87% uplink loss -> loss-defensive
                # encoder (the collapse). Prompt delivery is the whole point.
                if (
                    self._rctl_enabled
                    and self._active_sock is not None
                    and self._rtcp_dest is not None
                    and self._local_ssrc
                ):
                    with contextlib.suppress(OSError):
                        await self._active_sock.sendto(self._build_rctl_companion_packet(), *self._rtcp_dest)
            cur_ext = self._rtp_highest_seq
            cycles = (cur_ext >> 16) & 0xFFFF
            last_seq16 = cur_ext & 0xFFFF
            if seq < last_seq16 and (last_seq16 - seq) > 0x8000:
                cycles = (cycles + 1) & 0xFFFF  # seq number wrapped
            new_ext = (cycles << 16) | seq
            if cur_ext == 0 or ((new_ext - cur_ext) & 0xFFFFFFFF) < 0x80000000:
                self._rtp_highest_seq = new_ext
            if last_seq is not None and seq != ((last_seq + 1) & 0xFFFF):
                forward = ((seq - last_seq) & 0xFFFF) < 0x8000  # heuristic for "ahead"
                if forward:
                    stats_forward_gaps += 1
                else:
                    stats_reorders += 1
                logger.debug(
                    "RTP %s: expected %d, got %d",
                    "gap" if forward else "reorder",
                    (last_seq + 1) & 0xFFFF,
                    seq,
                )
                fu_buffer.clear()
                au_corrupt = True
            # Only advance last_seq forward (drop late stragglers) so a single
            # out-of-order packet doesn't reset our notion of "newest seen".
            if last_seq is None or ((seq - last_seq) & 0xFFFF) < 0x8000:
                last_seq = seq

            now = loop.time()
            if now - stats_last_log > 5.0:
                if stats_forward_gaps or stats_reorders or stats_corrupt_aus:
                    logger.debug(
                        "RTP stats (last %.1fs): packets=%d forward_gaps=%d reorders=%d dropped_AUs=%d",
                        now - stats_last_log,
                        stats_packets,
                        stats_forward_gaps,
                        stats_reorders,
                        stats_corrupt_aus,
                    )
                stats_packets = 0
                stats_forward_gaps = 0
                stats_reorders = 0
                stats_corrupt_aus = 0
                stats_last_log = now

            nals.clear()
            depacketize_hevc(payload, fu_buffer, nals)
            for nal in nals:
                if not nal:
                    continue
                nt = (nal[0] >> 1) & 0x3F
                if nt == _HEVC_NAL_VPS:
                    self._vps_nal = nal
                elif nt == _HEVC_NAL_PPS:
                    self._pps_nal = nal
                elif nt == _HEVC_NAL_SPS:
                    self._sps_nal = nal
                    if self._codec_string is None:
                        try:
                            self._codec_string = hevc_codec_string_from_sps(nal)
                            logger.info(f"WebCodecs codec string: {self._codec_string}")
                        except Exception as exc:
                            logger.warning(f"failed to parse SPS: {exc}")
                if _is_key_nal(nt):
                    au_is_key = True
                current_au.append(nal)

            if marker:
                if au_corrupt:
                    stats_corrupt_aus += 1
                    # Ask the device's encoder to emit a fresh IDR. Without
                    # this, every subsequent delta references slices we
                    # never delivered, the browser decoder errors and gets
                    # stuck waiting for a keyframe that on a long-GOP
                    # stream may never come naturally.
                    self._request_recovery_idr(reason="au-drop")
                    # Hold every subscriber's deltas until that IDR lands.
                    # The deltas that follow a dropped AU reference the
                    # frame we never delivered, and VideoToolbox doesn't
                    # throw on a missing reference — it silently renders
                    # the mispredicted blocks as a mosaic tear. A short
                    # freeze (one PLI round-trip, ~100-300 ms) is the
                    # better trade. ``reset_on_key`` stays False: the
                    # browser's decoder never sees the broken deltas, so
                    # the recovery IDR can be absorbed as a plain type=0
                    # DPB anchor without a decoder rebuild (rebuild-per-gap
                    # is what used to read as chop under motion).
                    for state in self._subscribers.values():
                        state.mark_needs_key(loop.time())
                if current_au and not au_corrupt:
                    # Broadcast as 4-byte-length-prefixed NALUs (hvcC / ISO
                    # 14496-15 sample format, lengthSizeMinusOne=3) rather than
                    # Annex-B start codes. Paired with the hvcC ``description``
                    # from /codec, this drives Chrome's WebCodecs down
                    # VideoToolbox's native hvcC path instead of the Annex-B
                    # start-code path, which re-converts every chunk and tears
                    # under rapid motion (Safari, which uses VideoToolbox
                    # directly, does not tear -- proving the Annex-B path).
                    au_data = b"".join(len(nal).to_bytes(4, "big") + nal for nal in current_au)
                    # Three framing types:
                    #   0 = key (IDR) - decode normally
                    #   1 = delta
                    #   2 = key WITH RESET - browser must rebuild the decoder
                    #       before decoding this AU. Used when a prior drop
                    #       left the decoder's reference state stale.
                    type_byte = b"\x00" if au_is_key else b"\x01"
                    msg = (len(au_data) + 1).to_bytes(4, "big") + type_byte + au_data
                    msg_reset = (len(au_data) + 1).to_bytes(4, "big") + b"\x02" + au_data if au_is_key else msg
                    if au_is_key:
                        self._init_sequence = msg
                        self._saw_first_key = True
                        if self._codec_string is not None:
                            self._stream_ready.set()
                    self._last_good_au_t = loop.time()
                    # Debug hook: tee the AU stream as Annex-B, so it can be
                    # decoded offline (e.g. ``ffmpeg -i dump.hevc``) to tell
                    # device-side encode artifacts apart from browser-side
                    # decode bugs. Built only when the env var is set.
                    dump_path = os.environ.get("PMD3_SERVE_WEB_DUMP")
                    if dump_path:
                        annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in current_au)
                        with open(dump_path, "ab") as _f:
                            _f.write(annexb)
                    # Feed the byte-rate window used by the decoder-refresh
                    # motion detector. Count DELTA AUs only: a forced IDR is
                    # ~200-300 KB and alone exceeds motion_threshold_bps, so
                    # counting keyframes would make a single refresh IDR read
                    # as "motion" and fire the next refresh, which is another
                    # IDR — a self-reinforcing PLI storm on a static screen
                    # that eventually stalls the device encoder (confirmed via
                    # syslog: 23 forced keyframes in 44 s with zero motion
                    # input -> "no AU progress" stall). Genuine motion shows up
                    # as a high *delta* byte rate, so excluding keyframes keeps
                    # real-motion refreshes while killing the static-screen
                    # storm. Always prune so stale entries expire even across
                    # a run of keyframes.
                    if not au_is_key:
                        self._au_byte_window.append((self._last_good_au_t, len(au_data)))
                    while self._au_byte_window and self._au_byte_window[0][0] < self._last_good_au_t - 1.0:
                        self._au_byte_window.popleft()
                    if self._saw_first_key:
                        for q, state in list(self._subscribers.items()):
                            if q.full():
                                while not q.empty():
                                    with contextlib.suppress(asyncio.QueueEmpty):
                                        q.get_nowait()
                                # This subscriber lost queued (unsent) AUs;
                                # hold its deltas until the next key. The
                                # browser decoder never saw the flushed
                                # AUs, so a plain type=0 key is enough to
                                # re-anchor it — no rebuild required.
                                # Without a periodic refresh loop that key
                                # must be requested explicitly, or the
                                # subscriber freezes for the rest of the
                                # (unbounded) GOP.
                                state.mark_needs_key(loop.time())
                                self._request_recovery_idr(reason="queue-overflow")
                            if state.needs_key:
                                if not au_is_key:
                                    continue
                                state.needs_key = False
                                if state.reset_on_key:
                                    # Fresh subscriber bootstrapping off a
                                    # stale cached IDR: rebuild the decoder
                                    # before this key.
                                    state.reset_on_key = False
                                    q.put_nowait(msg_reset)
                                else:
                                    q.put_nowait(msg)
                                continue
                            q.put_nowait(msg)
                current_au = []
                au_is_key = False
                au_corrupt = False

    # ----- RTCP feedback ----------------------------------------------------
    def _build_rtcp_pli(self) -> bytes:
        """Build an RTCP Picture Loss Indication (RFC 4585 §6.3.1).

        Sent when we detect dropped AUs so the device-side encoder emits a
        fresh IDR. Without this the browser's decoder gets stuck waiting
        for a keyframe that, on a long-GOP stream, may never come.

        Format (12 bytes total)::

            byte 0  : V=2 P=0 FMT=1   (0x81)
            byte 1  : PT=206 PSFB     (0xCE)
            bytes 2-3: length=2 (3 words)
            bytes 4-7: sender SSRC (ours)
            bytes 8-11: media source SSRC (device's)
        """
        import struct as _struct

        return _struct.pack(
            "!BBHII",
            0x81,
            0xCE,
            2,
            self._local_ssrc & 0xFFFFFFFF,
            self._remote_ssrc & 0xFFFFFFFF,
        )

    async def _send_rtcp_pli(self) -> None:
        transport = self._active_sock
        if transport is None or self._rtcp_dest is None:
            return
        if not (self._local_ssrc and self._remote_ssrc):
            return
        try:
            await transport.sendto(self._build_rtcp_pli(), *self._rtcp_dest)
            logger.info("sent RTCP PLI (requested fresh keyframe)")
        except OSError as exc:
            logger.debug("PLI send failed (%s)", exc)

    # ----- AVConference RCTL receiver feedback ------------------------------
    # Reversed from a live Xcode-mirror capture; field values decoded exactly
    # from it. The receiver streams two RTCP APP packets (PT=204):
    #   "RCTL" (32 B, ~20/s): tag 0x85000004 then 8x u16:
    #     [0]=received RTP ts>>8, [1..2]=0, [3]=jitter/loss(0),
    #     [4]=1024 Hz receiver wall clock, [5]=reception quality, [6]=frames,
    #     [7]=accepted max bitrate (kbps).
    #   name 0x00000005 (16 B, ~35/s): the received video RTP timestamp.
    # Echoing the *received* RTP timestamp is what makes the device act on the
    # feedback (a synthetic clock was ignored). Xcode sends this and no PLIs.
    def _rctl_wall_ms(self) -> int:
        loop = asyncio.get_running_loop()
        elapsed = max(0.0, loop.time() - self._rctl_start_t) if self._rctl_start_t else 0.0
        return int(elapsed * 1000) & 0xFFFF

    def _build_rctl_packet(self) -> bytes:
        """RTCP APP "RCTL" (PT=204), byte-exact to Xcode's mirror. After the
        0x85000004 tag, four u32 words (decoded from a live capture):
          w2 = (RTP ts >> 8) << 16
          w3 = packet_count of the last frame
          w4 = (arrival-clock ms << 16) | interarrival jitter (24 kHz units)
          w5 = (received-packet counter << 16) | 0xEA61 (constant)
        Our old packet sent w3=0, w4=1024Hz-clock|98, w5=frames|maxk -- garbage
        the device's rate controller reacted to by throttling framerate."""
        import struct as _struct

        ts = self._rtp_last_ts & 0xFFFFFFFF
        w2 = ((ts >> 8) & 0xFFFF) << 16
        w3 = self._rtp_last_frame_pkts & 0xFFFFFFFF
        # w4 = (arrival-clock ms << 16) | interarrival jitter (24 kHz units).
        # The device derives OWRD from the arrival clock vs the packet's own send
        # time; our old arrival clock was elapsed-since-start ms, a DIFFERENT epoch
        # from the RTP media clock, so the device computed a bogus 14-50 ms OWRD
        # (seen in VCRC) on what is really a ~1 ms kernel tunnel -> read as
        # congestion -> framerate throttle. Report the arrival time on the SAME
        # 24 kHz base as the packet (arrival == send -> OWRD ~= 0) and jitter 0.
        # Truthful for a local tunnel; stops the phantom-congestion throttle.
        arrival_ms = (ts // 24) & 0xFFFF
        w4 = (arrival_ms << 16) | 0
        w5 = ((self._rtp_packets_received & 0xFFFF) << 16) | 0xEA61
        return _struct.pack(
            "!BBHI4sI IIII", 0x80, 0xCC, 7, self._local_ssrc & 0xFFFFFFFF, b"RCTL", 0x85000004, w2, w3, w4, w5
        )

    def _build_rctl_companion_packet(self) -> bytes:
        import struct as _struct

        return _struct.pack(
            "!BBHI I I", 0x80, 0xCC, 3, self._local_ssrc & 0xFFFFFFFF, 5, self._rtp_last_ts & 0xFFFFFFFF
        )

    async def _rctl_feedback_loop(self) -> None:
        """Stream RCTL + companion APP feedback while a video stream is up:
        companion every tick (~40/s), RCTL every other tick (~20/s)."""
        tick = 0
        while True:
            try:
                await asyncio.sleep(0.025)
            except asyncio.CancelledError:
                return
            transport = self._active_sock
            if (
                not self._rctl_enabled
                or transport is None
                or self._rtcp_dest is None
                or not self._local_ssrc
                or self._rtp_packets_received == 0
            ):
                continue
            if self._rctl_start_t == 0.0:
                self._rctl_start_t = asyncio.get_running_loop().time()
            try:
                # Receipts (name=5) are now sent per-frame from the RTP receive
                # loop (Xcode-exact 1-per-frame). This loop only paces the
                # periodic RCTL report (~20/s, matching Xcode's 407/20s).
                if tick % 2 == 0:
                    await transport.sendto(self._build_rctl_packet(), *self._rtcp_dest)
            except OSError:
                continue
            tick += 1

    def _build_rtcp_rr(self) -> bytes:
        """Build a minimal RTCP Receiver Report for the active stream.

        The device's ``streamConfig`` says ``RTCPTimeoutEnabled=True`` -- if we
        never send RTs the encoder stalls within ~25 s. A single Receiver
        Report (32 bytes) every second is enough to keep it producing frames.

        Format (RFC 3550 §6.4.2): one RR with one report block, followed by an
        SDES/CNAME chunk to form a proper compound packet::

            byte 0  : V=2 P=0 RC=1     (0x81)
            byte 1  : PT=201 (RR)      (0xC9)
            bytes 2-3: length=7 (8 words total)
            bytes 4-7: sender SSRC      (our LocalSSRC)
            bytes 8-11: SSRC_1          (device's SSRC = RemoteSSRC)
            byte 12 : fraction lost (0)
            13-15   : cumulative packets lost (0)
            16-19   : extended highest seq received
            20-23   : interarrival jitter (0)
            24-27   : last SR timestamp (0 -- we never received SR)
            28-31   : delay since last SR (0)

        The trailing SDES matches Xcode's mirror exactly (confirmed by device
        syslog: Xcode always sends ``RR`` + ``SDES`` compounds, never a bare RR)
        and satisfies RFC 3550 §6.1, which requires every compound RTCP packet
        to carry an SDES with a CNAME.
        """
        import struct as _struct

        rr = _struct.pack(
            "!BBHII BBBB IIII",
            0x81,
            0xC9,
            7,
            self._local_ssrc & 0xFFFFFFFF,
            self._remote_ssrc & 0xFFFFFFFF,
            0,  # fraction lost
            0,
            0,
            0,  # cumulative loss (3 bytes — packed as 3x B)
            self._rtp_highest_seq & 0xFFFFFFFF,
            0,
            0,
            0,
        )
        return rr + self._build_rtcp_sdes(self._local_ssrc)

    @staticmethod
    def _build_rtcp_sdes(ssrc: int) -> bytes:
        """Minimal RTCP SDES chunk (RFC 3550 §6.5) with an empty CNAME,
        byte-identical to Xcode's mirror (``81 ca 0002 <ssrc> 01 00 00 00``):
        V=2 SC=1, PT=202, one source chunk = SSRC + a zero-length CNAME item
        (type 1, len 0) + null terminator + padding to a 32-bit boundary."""
        import struct as _struct

        return _struct.pack(
            "!BBHI BBBB",
            0x81,  # V=2, P=0, SC=1
            0xCA,  # PT=202 (SDES)
            2,  # length = 3 words
            ssrc & 0xFFFFFFFF,
            0x01,  # SDES item type 1 = CNAME
            0x00,  # CNAME length 0 (empty, as Xcode sends)
            0x00,  # item type 0 = END of items
            0x00,  # padding to 32-bit boundary
        )

    async def _rtcp_send_loop(self, transport: UdpMediaTransport) -> None:
        """Periodically send RTCP RR to the device so the encoder doesn't time out."""
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            if self._rtcp_dest is None or self._rtp_packets_received == 0:
                continue
            packet = self._build_rtcp_rr()
            try:
                await transport.sendto(packet, *self._rtcp_dest)
            except OSError as exc:
                logger.debug("RTCP send failed (%s); the socket may be torn down", exc)
                return

    def _build_audio_rtcp_rr(self) -> bytes:
        """Audio-side counterpart of :meth:`_build_rtcp_rr` (RFC 3550 §6.4.2).
        Same RR + SDES/CNAME compound shape (Xcode sends SDES on the audio
        stream too); just uses the audio session's SSRCs and highest-seq."""
        import struct as _struct

        rr = _struct.pack(
            "!BBHII BBBB IIII",
            0x81,
            0xC9,
            7,
            self._audio_local_ssrc & 0xFFFFFFFF,
            self._audio_remote_ssrc & 0xFFFFFFFF,
            0,
            0,
            0,
            0,
            self._audio_rtp_highest_seq & 0xFFFFFFFF,
            0,
            0,
            0,
        )
        return rr + self._build_rtcp_sdes(self._audio_local_ssrc)

    async def _audio_rtcp_send_loop(self, transport: UdpMediaTransport) -> None:
        """Periodically send RTCP RR for the audio stream. Without this
        the device reaps the audio session after ~20 s (RTCPTimeoutInterval)
        and the encoder silently stops emitting RTP audio packets --
        mediastreamstatus confirmed the audio session disappears from the
        sessions list when we don't RR."""
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            # Send the keepalive RR as soon as the loop is up -- do NOT wait for
            # the first audio packet. The screen usually starts SILENT (lock
            # screen, static UI), so no audio RTP arrives for a while; gating the
            # RR on packets-received meant we sent nothing, the device reaped the
            # audio session at ~20 s (RTCPTimeoutInterval), and audio was dead
            # before the user ever played anything (0 bytes on /audio.bin). The
            # audio SSRCs are known from negotiation, so a highest-seq=0 RR is a
            # valid keepalive that holds the session open through the silence.
            # (Video never hit this: the screen always emits video immediately.)
            if self._audio_rtcp_dest is None:
                continue
            packet = self._build_audio_rtcp_rr()
            try:
                await transport.sendto(packet, *self._audio_rtcp_dest)
            except OSError as exc:
                logger.debug("audio RTCP send failed (%s); the socket may be torn down", exc)
                return

    @staticmethod
    def _missing_audio_deps() -> list[str]:
        """Audio decode uses macOS's AudioToolbox via ctypes -- no pip
        dependencies required. Kept as a method so /audio.bin can return
        a clear error on non-macOS hosts."""
        import sys

        return [] if sys.platform == "darwin" else ["macOS (AudioToolbox)"]

    # ----- audio-stream lifecycle (parallel to video) ----------------------
    # AAC-ELD decode lives in :mod:`aac_eld`; see that module for the
    # AudioToolbox-via-ctypes plumbing. Output here is s16le 48 kHz
    # stereo interleaved PCM, broadcast in length-prefixed chunks to
    # /audio.bin subscribers (~192 KB/s).
    async def _audio_udp_recv(self, transport: UdpMediaTransport) -> None:
        """Receive RTP audio packets, strip the RTP header, decode the
        AAC-ELD AU via AudioToolbox, and broadcast the interleaved s16le
        PCM to /audio.bin subscribers."""
        try:
            decoder = AACELDDecoder(AAC_ELD_ASC_48K_STEREO_480)
        except Exception:
            logger.exception("AudioToolbox AAC-ELD decoder failed to open")
            return
        logger.info("audio decoder ready: AudioToolbox AAC-ELD -> s16le 48k stereo")

        # Volume changes on the device side can land us with a packet
        # the decoder rejects -- and once AudioConverter has errored, all
        # subsequent FillComplexBuffer calls fail too. Track consecutive
        # failures and recreate the decoder from scratch when we cross
        # the threshold so a single hiccup doesn't permanently kill the
        # audio stream.
        consecutive_errors = 0
        _ERR_RECREATE_THRESHOLD = 5

        while True:
            try:
                data = await transport.recv(65535)
            except (OSError, asyncio.CancelledError):
                return
            except Exception:
                logger.exception("audio recv task crashed")
                return
            if len(data) < 12:
                continue
            pt = data[1] & 0x7F
            if 64 <= pt <= 95:  # RTCP -- ignore
                continue
            # Track sequence + receive count so our RR reports a sensible
            # extended-highest-seq field. Without this the encoder reaps
            # the audio session after 20 s (RTCPTimeoutInterval).
            self._audio_rtp_packets_received += 1
            seq = int.from_bytes(data[2:4], "big")
            cur_ext = self._audio_rtp_highest_seq
            cycles = (cur_ext >> 16) & 0xFFFF
            last_seq16 = cur_ext & 0xFFFF
            if seq < last_seq16 and (last_seq16 - seq) > 0x8000:
                cycles = (cycles + 1) & 0xFFFF
            new_ext = (cycles << 16) | seq
            if cur_ext == 0 or ((new_ext - cur_ext) & 0xFFFFFFFF) < 0x80000000:
                self._audio_rtp_highest_seq = new_ext
            cc = data[0] & 0x0F
            header_len = 12 + cc * 4
            if data[0] & 0x10:  # extension
                if header_len + 4 > len(data):
                    continue
                ext_len = int.from_bytes(data[header_len + 2 : header_len + 4], "big")
                header_len += 4 + ext_len * 4
            payload = data[header_len:]
            if not payload:
                continue
            try:
                pcm = decoder.decode(payload)
                consecutive_errors = 0
            except Exception as exc:
                consecutive_errors += 1
                logger.debug("audio decode failed (%s) -- dropping packet", exc)
                if consecutive_errors >= _ERR_RECREATE_THRESHOLD:
                    logger.warning(
                        "audio decoder stuck after %d consecutive errors -- recreating",
                        consecutive_errors,
                    )
                    try:
                        decoder = AACELDDecoder(AAC_ELD_ASC_48K_STEREO_480)
                        consecutive_errors = 0
                    except Exception:
                        logger.exception("audio decoder recreation failed")
                continue
            if not pcm:
                continue
            msg = len(pcm).to_bytes(4, "big") + pcm
            for q in list(self._audio_subscribers.keys()):
                if q.full():
                    with contextlib.suppress(asyncio.QueueEmpty):
                        q.get_nowait()
                q.put_nowait(msg)

    async def _stop_audio_stream(self) -> None:
        svc = self._audio_service
        sid = self._audio_session_id
        sock = self._audio_sock
        task = self._audio_recv_task
        rtcp_task = self._audio_rtcp_task
        self._audio_service = None
        self._audio_session_id = None
        self._audio_sock = None
        self._audio_recv_task = None
        self._audio_rtcp_task = None
        self._audio_rtcp_dest = None
        if rtcp_task is not None:
            rtcp_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await rtcp_task
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        if svc is not None:
            # Bound the device-side RPCs. A wedged CoreDevice daemon
            # can hang the XPC response wait indefinitely, holding
            # _audio_lock and preventing recovery.
            if sid is not None:
                with contextlib.suppress(asyncio.TimeoutError, Exception):
                    await asyncio.wait_for(svc.stop_media_stream(sid), timeout=2.0)
            with contextlib.suppress(asyncio.TimeoutError, Exception):
                await asyncio.wait_for(svc.close(), timeout=2.0)

    async def _ensure_audio_stream(self) -> None:
        async with self._audio_lock:
            if (
                self._audio_service is not None
                and self._audio_recv_task is not None
                and not self._audio_recv_task.done()
            ):
                return
            await self._stop_audio_stream()
            svc = DisplayService(self._rsd)
            await svc.connect()
            transport, receiver_ip = open_media_receiver(svc, (4 * 1024 * 1024, 1 * 1024 * 1024))
            port = transport.port
            # Same shared client_session_id as the video stream so the
            # device pairs them on its media-session manager (Xcode's
            # Mirror does this -- confirmed in the remotexpc sniff).
            answer = await svc.start_audio_stream(
                receiver_ip=receiver_ip,
                receiver_port=port,
                sender_ip=self._sender_ip,
                client_session_id=self._shared_session_id,
            )
            sid = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
            if not isinstance(sid, uuid.UUID):
                sid = uuid.UUID(sid)
            cfg = answer["connection"].get("streamConfig", {})
            logger.info(
                "audio stream started: PT=%s mode=%s sender_port=%s",
                cfg.get("RxPayloadType"),
                cfg.get("AudioStreamMode"),
                cfg.get("SourcePort"),
            )
            # Same SSRC-naming convention as video: device's streamConfig
            # uses its perspective, so LocalSSRC is the device's, RemoteSSRC
            # is ours. Source-port + sender-IP is where we send RTCP.
            source_port = int(cfg.get("SourcePort", 0))
            self._audio_local_ssrc = int(cfg.get("RemoteSSRC", 0))  # ours
            self._audio_remote_ssrc = int(cfg.get("LocalSSRC", 0))  # device's
            self._audio_rtp_highest_seq = 0
            self._audio_rtp_packets_received = 0
            self._audio_rtcp_dest = (self._sender_ip, source_port) if source_port else None
            self._audio_service = svc
            self._audio_session_id = sid
            self._audio_sock = transport
            self._audio_recv_task = asyncio.create_task(self._audio_udp_recv(transport))
            # Keep the audio session alive by RR'ing every second.
            # RTCPTimeoutInterval=20 s by default; without this the
            # device reaps the audio session, mediastreamstatus drops it,
            # and the encoder stops emitting (silently).
            if self._audio_rtcp_dest is not None and self._audio_local_ssrc and self._audio_remote_ssrc:
                self._audio_rtcp_task = asyncio.create_task(self._audio_rtcp_send_loop(transport))
            else:
                logger.warning(
                    "audio RTCP disabled (missing fields: SourcePort=%s LocalSSRC=%s RemoteSSRC=%s)",
                    source_port,
                    self._audio_local_ssrc,
                    self._audio_remote_ssrc,
                )

    # ----- device-stream lifecycle ------------------------------------------
    async def _stop_active_stream(self) -> None:
        svc = self._active_service
        sid = self._active_session_id
        sock_to_close = self._active_sock
        task_to_cancel = self._active_recv_task
        rtcp_task = self._active_rtcp_task
        self._active_service = None
        self._active_session_id = None
        self._active_sock = None
        self._active_recv_task = None
        self._active_rtcp_task = None
        if rtcp_task is not None:
            rtcp_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await rtcp_task
        if task_to_cancel is not None:
            task_to_cancel.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task_to_cancel
        if sock_to_close is not None:
            with contextlib.suppress(Exception):
                sock_to_close.close()
        if svc is not None:
            # Bound the device-side RPCs. The stall watchdog calls us
            # precisely when the CoreDevice daemon has stopped feeding
            # AUs -- i.e. the state in which stop_media_stream / close
            # are most likely to hang on their XPC response wait. An
            # unbounded await here holds _stream_lock forever and
            # leaves /codec and /stream.bin replying 503 with no path
            # to recovery short of restarting the server.
            if sid is not None:
                with contextlib.suppress(asyncio.TimeoutError, Exception):
                    await asyncio.wait_for(svc.stop_media_stream(sid), timeout=2.0)
            with contextlib.suppress(asyncio.TimeoutError, Exception):
                await asyncio.wait_for(svc.close(), timeout=2.0)

    async def _ensure_fresh_stream(self, force: bool = False) -> None:
        async with self._stream_lock:
            if self._active_service is not None and not self._stream_dirty and not force:
                return
            had_active_stream = self._active_service is not None
            await self._stop_active_stream()
            if had_active_stream:
                # The new device-side media stream re-publishes its
                # IOHIDService surfaces under fresh IDs; backboardd
                # re-matches the auth flags only for surfaces attached
                # AFTER the new stream is up. Drop our HID handles so the
                # next /touch or /button opens fresh ones against the new
                # context. On a *cold* first start we skip this so the
                # worker we just spawned in serve() isn't killed before it
                # processes its first request.
                await self._stop_hid()
            self._init_sequence = None
            self._codec_string = None
            self._vps_nal = self._sps_nal = self._pps_nal = None
            self._saw_first_key = False
            self._stream_ready.clear()
            # Preserve any connected subscribers across the restart — flush
            # their queues and flag them needs_key so they'll lock onto the
            # first IDR from the new stream instead of seeing the connection
            # break. (On a fresh /stream.bin request there are no subscribers
            # yet, so this is a no-op for cold starts.)
            for q, state in self._subscribers.items():
                while not q.empty():
                    with contextlib.suppress(asyncio.QueueEmpty):
                        q.get_nowait()
                # Unconditionally restamp the needs_key clock: the new
                # session gets a full watchdog window to deliver its
                # opening IDR before another escalation can fire.
                state.needs_key = True
                state.needs_key_since = asyncio.get_running_loop().time()

            svc = DisplayService(self._rsd)
            await svc.connect()

            # Fresh media receiver — no buffered packets from a previous session can corrupt
            # the new session's FU reassembly.
            transport, receiver_ip = open_media_receiver(svc, (8 * 1024 * 1024, 4 * 1024 * 1024))
            port = transport.port
            # Pass the shared client_session_id so the device sees us as
            # one Mirror client across audio + video, matching Xcode.
            answer = await svc.start_video_stream(
                receiver_ip=receiver_ip,
                receiver_port=port,
                sender_ip=self._sender_ip,
                display_id=self._display_id,
                client_session_id=self._shared_session_id,
                allow_rtcp_fb=self._allow_rtcp_fb,
                ltrp_enabled=self._ltrp_enabled,
            )
            sid = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
            if not isinstance(sid, uuid.UUID):
                sid = uuid.UUID(sid)
            # Extract RTCP destination + SSRCs from the streamConfig the device
            # returned. Without this the encoder stalls every ~25 s waiting
            # for Receiver Reports (RTCPTimeoutEnabled=True in the config).
            # The names in streamConfig are from the device's perspective, so
            # ``LocalSSRC`` is the device's SSRC and ``RemoteSSRC`` is ours.
            # In an RR we send, the sender SSRC is OURS (RemoteSSRC) and the
            # SSRC being reported on is the device's (LocalSSRC).
            stream_cfg = answer["connection"].get("streamConfig", {})
            source_port = int(stream_cfg.get("SourcePort", 0))
            self._local_ssrc = int(stream_cfg.get("RemoteSSRC", 0))  # ours
            self._remote_ssrc = int(stream_cfg.get("LocalSSRC", 0))  # device's
            self._rtp_highest_seq = 0
            self._rtp_packets_received = 0
            self._rtp_last_ts = 0
            self._rtp_frames_received = 0
            self._rctl_start_t = 0.0
            self._rtp_cur_frame_pkts = 0
            self._rtp_last_frame_pkts = 0
            self._rtp_jitter = 0.0
            self._rtp_prev_transit = None
            self._rtcp_dest = (self._sender_ip, source_port) if source_port else None
            self._active_service = svc
            self._active_session_id = sid
            self._active_sock = transport
            self._active_recv_task = asyncio.create_task(self._udp_recv_and_depacketize(transport))
            if self._rtcp_dest is not None and self._local_ssrc and self._remote_ssrc:
                self._active_rtcp_task = asyncio.create_task(self._rtcp_send_loop(transport))
            else:
                logger.warning(
                    "RTCP feedback disabled (missing fields in streamConfig: SourcePort=%s LocalSSRC=%s RemoteSSRC=%s)",
                    source_port,
                    self._local_ssrc,
                    self._remote_ssrc,
                )
            # Seed the stall timer to "now" so the watchdog gives the new
            # stream ``_STALL_RESTART_SECS`` to produce its first AU instead
            # of firing immediately on its zero-initialised value.
            self._last_good_au_t = asyncio.get_running_loop().time()
            self._stream_dirty = False

    # ----- HID (touch + buttons) -------------------------------------------
    # ----- Accessibility settings (lockdown / DTX) --------------------------
    # The /accessibility panel is backed by ConfigurationService
    # (com.apple.coredevice.configuration) — every knob is one
    # ``com.apple.coredevice.action.*`` invocation. This replaces the
    # earlier AccessibilityAudit-over-DTX path, which only worked when
    # usbmuxd could reach the device (i.e. not for remote-tunneld use)
    # AND went silent on iOS 27's RSD shim. CoreDevice actions ride the
    # same RSD as the rest of serve-web and Just Work.
    _TEXT_SIZE_OPTIONS = (
        "extraSmall",
        "small",
        "medium",
        "large",
        "extraLarge",
        "extraExtraLarge",
        "extraExtraExtraLarge",
        "accessibilityMedium",
        "accessibilityLarge",
        "accessibilityExtraLarge",
        "accessibilityExtraExtraLarge",
        "accessibilityExtraExtraExtraLarge",
    )

    async def _accessibility_list(self) -> list[dict]:
        """Read every supported knob and return a viewer-friendly list.

        Each entry is ``{key, value, type, options?}`` where ``type`` is
        one of ``bool``, ``float``, or ``enum``. The viewer renders bools
        as checkboxes, floats as 0..1 sliders, and enums as dropdowns.
        """
        async with self._accessibility_lock:
            results: list[dict] = []

            async def _read(meth):
                async with ConfigurationService(self._rsd) as cfg:
                    return await getattr(cfg, meth)()

            try:
                results.append({
                    "key": "ui_style",
                    "type": "enum",
                    "value": await _read("get_user_interface_style"),
                    "options": ["light", "dark"],
                })
            except Exception:
                logger.debug("get_user_interface_style failed", exc_info=True)
            try:
                results.append({
                    "key": "text_size",
                    "type": "enum",
                    "value": await _read("get_device_text_size"),
                    "options": list(self._TEXT_SIZE_OPTIONS),
                })
            except Exception:
                logger.debug("get_device_text_size failed", exc_info=True)
            try:
                cf = await _read("get_color_filter")
                results.append({"key": "color_filter", "type": "bool", "value": bool(cf.get("enabled", False))})
            except Exception:
                logger.debug("get_color_filter failed", exc_info=True)
            for key, meth in (
                ("reduce_motion", "get_reduce_motion"),
                ("show_borders", "get_show_borders"),
                ("reduce_transparency", "get_reduce_transparency"),
            ):
                try:
                    results.append({"key": key, "type": "bool", "value": await _read(meth)})
                except Exception:
                    logger.debug("%s failed", meth, exc_info=True)
            # write-only knobs (no getter on the device)
            results.append({"key": "increase_contrast", "type": "bool", "value": self._increase_contrast_last})
            results.append({"key": "liquid_glass_opacity", "type": "float", "value": 1.0})
            return results

    async def _accessibility_set(self, key: str, value) -> None:
        """Apply one knob change. Raises ValueError for unknown keys so
        the HTTP layer can return 400 instead of swallowing typos."""
        async with self._accessibility_lock, ConfigurationService(self._rsd) as cfg:
            if key == "ui_style":
                await cfg.set_user_interface_style(str(value))
            elif key == "text_size":
                await cfg.set_device_text_size(str(value))
            elif key == "color_filter":
                # Boolean toggle: enable forces a sensible default
                # filter type (Protanopia matches the captured Xcode
                # default); disable clears.
                if bool(value):
                    await cfg.set_color_filter(True, "Protanopia", 1.0)
                else:
                    await cfg.set_color_filter(False)
            elif key == "reduce_motion":
                await cfg.set_reduce_motion(bool(value))
            elif key == "show_borders":
                await cfg.set_show_borders(bool(value))
            elif key == "reduce_transparency":
                await cfg.set_reduce_transparency(bool(value))
            elif key == "increase_contrast":
                await cfg.set_increase_contrast(bool(value))
                self._increase_contrast_last = bool(value)
            elif key == "liquid_glass_opacity":
                await cfg.set_liquid_glass_opacity(float(value))
            else:
                raise ValueError(f"unknown accessibility key: {key!r}")

    async def _stop_accessibility(self) -> None:
        """No-op now that we open a fresh CoreDevice service per call.
        Kept so :meth:`serve` shutdown can call it unconditionally."""
        return None

    async def _ensure_hid(self) -> None:
        """Lazily open the HID services + worker on first input event."""
        async with self._hid_lock:
            if self._uhs is None:
                uhs = UniversalHIDServiceService(self._rsd)
                await uhs.connect()
                self._uhs = uhs
            if self._indigo is None:
                indigo = IndigoHIDService(self._rsd)
                await indigo.connect()
                self._indigo = indigo
            if self._hid_worker_task is None or self._hid_worker_task.done():
                self._hid_worker_task = asyncio.create_task(self._hid_worker())

    async def _stop_hid(self) -> None:
        # Drain pending requests so the new stream context doesn't get
        # POSTs queued against the old one. We keep the worker task ALIVE
        # though -- on the next /touch it will lazily re-open UHS/Indigo
        # against the fresh stream via _ensure_hid. Cancelling the worker
        # here would leave us with no consumer of _hid_queue after a
        # forced restart and touches would silently stall.
        while not self._hid_queue.empty():
            with contextlib.suppress(asyncio.QueueEmpty):
                self._hid_queue.get_nowait()
        async with self._hid_lock:
            if self._uhs is not None:
                with contextlib.suppress(Exception):
                    await self._uhs.close()
                self._uhs = None
            if self._indigo is not None:
                with contextlib.suppress(Exception):
                    await self._indigo.close()
                self._indigo = None
            # The keyboard surface is host-registered against the live
            # media stream; after a stream restart that ID points at a
            # stale dtuhidd session and every report posted to it is
            # silently dropped. Forget it so _ensure_keyboard re-creates
            # one against the new stream on the next /key.
            self._kb_service_id = None

    async def _hid_worker(self) -> None:
        """Single consumer that serially dispatches queued HID requests so
        order is preserved and HTTP handlers can return 200 immediately.
        Lazily opens the HID services on the first queued request."""
        logger.info("hid worker started")
        try:
            while True:
                path, body = await self._hid_queue.get()
                try:
                    if self._uhs is None or self._indigo is None:
                        await self._ensure_hid()
                    if path == "/touch":
                        handler = self._handle_touch
                    elif path == "/button":
                        handler = self._handle_button
                    else:
                        handler = self._handle_key
                    code, msg = await handler(body)
                    if code != 200:
                        logger.warning("queued %s -> %d %s", path, code, msg.decode("utf-8", "replace"))
                except Exception:
                    logger.exception("queued HID dispatch failed: %s body=%r", path, body[:200])
        except asyncio.CancelledError:
            logger.info("hid worker cancelled")
            raise
        except Exception:
            logger.exception("hid worker crashed")
            raise

    async def _handle_touch(self, body: bytes) -> tuple[int, bytes]:
        """POST /touch — JSON ``{type, x, y}``.

        ``type`` is one of:
          - ``"contact"``  → CONTACT (in-contact sample at x, y)
          - ``"release"``  → RELEASE (lift the touch at x, y)
          - ``"tap"``      → CONTACT + brief sleep + RELEASE at the same point

        Drags are just a stream of ``"contact"`` updates ending in ``"release"``
        — the browser fires them straight from pointerdown / pointermove /
        pointerup, so the device sees the same shape as a real Xcode drag.
        """
        try:
            data = json.loads(body)
            op = str(data["type"])
            x = int(data["x"])
            y = int(data["y"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return 400, f"invalid touch request: {exc}".encode()
        await self._ensure_hid()
        assert self._uhs is not None
        if op == "contact":
            await self._uhs.send_touchscreen(
                TOUCHSCREEN_STATE_CONTACT, x, y, service_id=DIGITIZER_SURFACE_MAIN_TOUCHSCREEN
            )
        elif op == "release":
            await self._uhs.send_touchscreen(
                TOUCHSCREEN_STATE_RELEASE, x, y, service_id=DIGITIZER_SURFACE_MAIN_TOUCHSCREEN
            )
        elif op == "tap":
            await self._uhs.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x, y)
            await asyncio.sleep(0.05)
            await self._uhs.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, x, y)
        else:
            return 400, f"unknown touch type {op!r}".encode()
        return 200, b"ok"

    async def _ensure_keyboard(self) -> None:
        await self._ensure_hid()
        if self._kb_service_id is None:
            async with self._hid_lock:
                if self._kb_service_id is None:
                    assert self._uhs is not None
                    self._kb_service_id = await self._uhs.create_keyboard_service()

    async def _handle_key(self, body: bytes) -> tuple[int, bytes]:
        """POST /key — JSON ``{usages: [int, int, ...]}``.

        The browser sends the *full set* of HID Keyboard usages currently
        held down; we forward verbatim. Empty list = all keys released.
        Translating browser KeyboardEvents to HID usages happens client-side
        so the server has no per-connection state to keep in sync.
        """
        try:
            data = json.loads(body)
            usages = [int(u) for u in data.get("usages", [])]
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return 400, f"invalid key request: {exc}".encode()
        await self._ensure_keyboard()
        assert self._uhs is not None and self._kb_service_id is not None
        await self._uhs.send_keyboard(self._kb_service_id, usages)
        return 200, b"ok"

    async def _handle_button(self, body: bytes) -> tuple[int, bytes]:
        """POST /button — JSON ``{name, state}``.

        ``name`` is one of the keys in :data:`_NAMED_BUTTONS` (home, lock,
        volume-up, volume-down, mute, siri). ``state`` is one of ``"press"``
        (default — fires down then up), ``"down"``, ``"up"``.
        """
        try:
            data = json.loads(body)
            name = str(data["name"])
            state = str(data.get("state", "press"))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return 400, f"invalid button request: {exc}".encode()
        if name not in _NAMED_BUTTONS:
            return 400, f"unknown button {name!r}".encode()
        usage_page, usage_code, hold_seconds = _NAMED_BUTTONS[name]
        await self._ensure_hid()
        assert self._indigo is not None
        if state == "press":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
            # Hold matters: Home is a tap (fires on any duration), but Lock
            # wants ~0.5 s for iOS to sleep the device and Siri ~1.0 s for
            # iOS to start listening. A 70 µs DOWN→UP gap (no sleep) is
            # treated as bounce-noise for these buttons.
            await asyncio.sleep(hold_seconds)
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_UP)
        elif state == "down":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
        elif state == "up":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_UP)
        else:
            return 400, f"unknown button state {state!r}".encode()
        return 200, b"ok"

    @staticmethod
    def _send_static(writer: asyncio.StreamWriter, body: bytes, content_type: bytes) -> None:
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: " + content_type + b"\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )

    @staticmethod
    async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        # Cap the body to a sane size — touch/button/key POSTs are tens of bytes.
        return await reader.readexactly(min(length, 65536))

    # ----- HTTP request handler ---------------------------------------------
    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # POSTs to /touch /button /key support keep-alive: one TCP carries
        # many requests, which is what the browser uses for pointermove.
        # Everything else (/, /codec, /stream.bin) is one-and-done.
        while True:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b""):
                    break
                try:
                    name, _, value = line.decode("latin-1").partition(":")
                    headers[name.strip().lower()] = value.strip()
                except UnicodeDecodeError:
                    pass
            parts = request_line.split()
            method = parts[0].decode() if parts else "GET"
            target = parts[1].decode() if len(parts) >= 2 else "/"
            # Strip the query string for route matching -- viewer.js reads its
            # flags (e.g. ?compensate=0) client-side from location.search, so
            # the server must still route "/?compensate=0" to the index page.
            path = target.split("?", 1)[0]

            if method == "POST" and path in ("/touch", "/button", "/key"):
                body = await self._read_body(reader, headers)
                logger.debug("enqueue %s body=%r conn=%s", path, body[:80], headers.get("connection", "?"))
                # Fire-and-forget: drop into the queue and answer 200 NOW.
                # The single HID worker will dispatch in order without
                # blocking the HTTP-server loop or starving the stream
                # broadcast.
                self._hid_queue.put_nowait((path, body))
                keep_alive = headers.get("connection", "").lower() != "close"
                conn_hdr = b"keep-alive" if keep_alive else b"close"
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: " + conn_hdr + b"\r\n\r\nok"
                )
                await writer.drain()
                if not keep_alive:
                    writer.close()
                    return
                continue
            # Anything else falls through to the single-shot handlers below.
            break

        if path in ("/", "/index.html"):
            self._send_static(writer, VIEWER_HTML, b"text/html; charset=utf-8")
            await writer.drain()
            writer.close()
            return
        if path == "/viewer.css":
            self._send_static(writer, VIEWER_CSS, b"text/css; charset=utf-8")
            await writer.drain()
            writer.close()
            return
        if path == "/viewer.js":
            # The `__AUDIO_DEFAULT_ON__` placeholder used to be in the
            # inline <script> block; now it lives in viewer.js and gets
            # substituted per-request so the server's `_audio_default_on`
            # flag still controls the initial audio state.
            body = VIEWER_JS_TEMPLATE.replace(
                b"__AUDIO_DEFAULT_ON__",
                b"true" if self._audio_default_on else b"false",
            ).replace(
                b"__COMPENSATE_DEFAULT__",
                b"true" if self._compensate else b"false",
            )
            self._send_static(writer, body, b"application/javascript; charset=utf-8")
            await writer.drain()
            writer.close()
            return
        if path == "/codec":
            # Bounded path so the browser never sees a fetch hang: cap the
            # whole thing at ~7 s. If the device-stream isn't up by then
            # return 503 -- the JS retries with backoff, and meanwhile
            # the in-flight ensure_fresh_stream keeps running so a later
            # /codec usually succeeds. Without this bound the cold path
            # can stall for ~30 s on a stuck CoreDevice daemon and the
            # browser surfaces it as "failed to fetch".
            try:
                await asyncio.wait_for(self._ensure_fresh_stream(force=False), timeout=5.0)
            except asyncio.TimeoutError:
                writer.write(b"HTTP/1.1 503 Stream Starting\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            except Exception:
                logger.exception("failed to start device stream")
                writer.write(b"HTTP/1.1 500 Internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stream_ready.wait(), timeout=2.0)
            # Return JSON: the WebCodecs codec string + the hvcC
            # decoder-configuration record (base64) used as the decoder
            # ``description``. hvcC-mode decoding (out-of-band parameter sets +
            # length-prefixed NALUs, matching /stream.bin framing) avoids the
            # Annex-B start-code path that tears under motion in Chrome. If any
            # parameter set is missing, reply 503 so the viewer retries.
            description_b64 = ""
            if self._codec_string and self._vps_nal and self._sps_nal and self._pps_nal:
                try:
                    hvcc = hevc_decoder_configuration_record(self._vps_nal, self._sps_nal, self._pps_nal)
                    description_b64 = base64.b64encode(hvcc).decode()
                except Exception:
                    logger.exception("failed to build hvcC record")
            if self._codec_string and description_b64:
                body = json.dumps({"codec": self._codec_string, "description": description_b64}).encode()
                status = b"200 OK"
            else:
                body = b""
                status = b"503 Stream Starting"
            writer.write(
                b"HTTP/1.1 " + status + b"\r\n"
                b"Content-Type: application/json\r\n"
                b"Cache-Control: no-store\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            writer.close()
            return
        if path.startswith("/debug/"):
            # Research runtime toggles: flip RCTL / motion-IDR live within one
            # session (same device state, no restart) to A/B their effect on
            # fps and the resolution collapse -- restarts are slow and can wedge
            # the device, so live toggling is the only reliable way to compare.
            # Both flags are read live by their loops. POST (or GET) one of:
            #   /debug/rctl-on  /debug/rctl-off  /debug/idr-on  /debug/idr-off
            # (viewer-side --compensate has its own ?compensate=0/1 URL toggle).
            cmd = path[len("/debug/") :]
            if cmd == "rctl-on":
                self._rctl_enabled = True
            elif cmd == "rctl-off":
                self._rctl_enabled = False
            elif cmd == "idr-on":
                self._motion_idr = True
            elif cmd == "idr-off":
                self._motion_idr = False
            body = f"rctl={self._rctl_enabled} motion_idr={self._motion_idr}".encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
            writer.close()
            return
        if path == "/restart":
            # Respond 202 immediately and run the actual restart in the
            # background. The video restart + audio teardown takes
            # several seconds (device-side start_video_stream RPC), and
            # the caller doesn't need to wait for it -- the new IDR
            # reaches their /stream.bin connection via the type=2 reset
            # path whenever the device gets around to emitting it, and
            # the audio JS auto-reconnects /audio.bin on its own. (Also
            # avoids the "button feels slow" effect that comes from JS
            # awaiting a slow round-trip.)
            async def _restart_bg():
                # Just restart video. Leave audio alone -- audio shares
                # the client_session_id with video (Xcode-style pairing),
                # so tearing audio down between video restart and the
                # browser's /audio.bin reconnect leaves the device with
                # an unpaired lone video session, which iOS treats as a
                # second-class client and throttles. Symptom was the
                # browser sticking on "frames: 1" after a /restart
                # until the user reloaded and re-attached /audio.bin.
                with contextlib.suppress(Exception):
                    await self._ensure_fresh_stream(force=True)

            bg = asyncio.create_task(_restart_bg())
            self._pli_tasks.add(bg)  # piggy-back on the existing keep-alive set
            bg.add_done_callback(self._pli_tasks.discard)
            writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()
            return
        if path.startswith("/accessibility"):
            try:
                resp_body: bytes
                if path == "/accessibility" and method == "GET":
                    settings = await self._accessibility_list()
                    resp_body = json.dumps({"settings": settings}).encode()
                elif path == "/accessibility/set" and method == "POST":
                    body = await self._read_body(reader, headers)
                    payload = json.loads(body)
                    key = str(payload["key"])
                    value = payload["value"]
                    await self._accessibility_set(key, value)
                    resp_body = b'{"ok":true}'
                elif path == "/accessibility/reset" and method == "POST":
                    # CoreDevice has no native "reset all" action; restore
                    # the toggles we can flip back to a sensible baseline
                    # individually. The user can still override per-knob.
                    for key, value in (
                        ("reduce_motion", False),
                        ("show_borders", False),
                        ("reduce_transparency", False),
                        ("increase_contrast", False),
                        ("color_filter", False),
                        ("text_size", "large"),
                        ("liquid_glass_opacity", 1.0),
                    ):
                        with contextlib.suppress(Exception):
                            await self._accessibility_set(key, value)
                    resp_body = b'{"ok":true}'
                else:
                    writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + resp_body
                )
            except Exception as exc:
                logger.exception("accessibility endpoint failed")
                err = f"accessibility error: {exc}".encode()
                writer.write(
                    b"HTTP/1.1 500 Internal\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(err)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + err
                )
            await writer.drain()
            writer.close()
            return
        if path == "/style":
            try:
                if method == "POST":
                    body = await self._read_body(reader, headers)
                    try:
                        style = str(json.loads(body)["style"])
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        await writer.drain()
                        writer.close()
                        logger.debug("style POST: bad body %r (%s)", body, exc)
                        return
                    async with ConfigurationService(self._rsd) as cfg:
                        await cfg.set_user_interface_style(style)
                    resp_body = json.dumps({"style": style}).encode()
                else:
                    async with ConfigurationService(self._rsd) as cfg:
                        style = await cfg.get_user_interface_style()
                    resp_body = json.dumps({"style": style}).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + resp_body
                )
            except Exception as exc:
                logger.exception("style endpoint failed")
                err = f"style endpoint error: {exc}".encode()
                writer.write(
                    b"HTTP/1.1 500 Internal\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(err)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + err
                )
            await writer.drain()
            writer.close()
            return
        if path == "/clipboard":
            # GET pulls the device pasteboard ({"text": "..."|null}); POST sets
            # it from JSON body {"text": "..."}. Bytes-only text path -- non-text
            # UTIs (images, files) aren't exposed here. The service is opened
            # per-request: connection is cheap and pasteboard ops are sporadic,
            # not worth holding a long-lived RemoteXPC channel for.
            try:
                if method == "GET":
                    async with PasteboardService(self._rsd) as pb:
                        snapshot = await pb.get()
                    resp_body = json.dumps({"text": snapshot_text(snapshot)}).encode()
                elif method == "POST":
                    body = await self._read_body(reader, headers)
                    try:
                        text = str(json.loads(body)["text"])
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        await writer.drain()
                        writer.close()
                        logger.debug("clipboard POST: bad body %r (%s)", body, exc)
                        return
                    async with PasteboardService(self._rsd) as pb:
                        await pb.set_text(text)
                    resp_body = b'{"ok":true}'
                else:
                    writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + resp_body
                )
            except Exception as exc:
                logger.exception("clipboard endpoint failed")
                err = f"clipboard error: {exc}".encode()
                writer.write(
                    b"HTTP/1.1 500 Internal\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(err)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + err
                )
            await writer.drain()
            writer.close()
            return
        if path == "/rotate" and method == "POST":
            # 90 degree rotation step. JSON body: ``{"direction": "left"|"right"}``.
            # The reply is the device's resulting orientation, which the viewer
            # uses to apply a matching CSS transform to the canvas so the user
            # sees the rotated content upright in the browser too.
            body = await self._read_body(reader, headers)
            try:
                direction = str(json.loads(body)["direction"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                logger.debug("rotate POST: bad body %r (%s)", body, exc)
                return
            try:
                async with OrientationService(self._rsd) as svc:
                    state = await svc.rotate(direction)
                resp_body = json.dumps({k: v for k, v in state.items() if isinstance(v, (str, bool))}).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + resp_body
                )
            except Exception as exc:
                logger.exception("rotate endpoint failed")
                err = f"rotate error: {exc}".encode()
                writer.write(
                    b"HTTP/1.1 500 Internal\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(err)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + err
                )
            await writer.drain()
            writer.close()
            return
        if path == "/pli":
            # Lightweight recovery: ask the device for a fresh IDR via
            # RTCP PLI and mark all subscribers as needing a key, but
            # DO NOT restart the DisplayService session. ``/restart``
            # tears down + re-RPCs the whole pipeline (~several
            # seconds, several-MB IDR burst); ``/pli`` is a single
            # RTCP packet and the new IDR arrives in ~100-300 ms.
            # The browser's decode-error handler and offline-overlay
            # auto-recovery hit this when frames stop; rate-limit it
            # like the other recovery paths so a stuck client can't
            # PLI-storm the encoder. Also require a live /stream.bin
            # subscriber: an orphaned viewer tab (its server restarted
            # under it) keeps auto-recovering with /pli every few
            # seconds indefinitely, and those blind PLIs corrupt/stall
            # the encoder for the tabs that ARE connected.
            if self._active_service is not None and self._rtcp_dest is not None and self._subscribers:
                self._request_recovery_idr(reason="browser-pli")
            writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()
            return
        if path == "/audio.bin":
            # Up-front dep check so the browser doesn't silently see "0
            # samples" when av/numpy aren't installed (the old failure
            # mode -- the audio recv task would crash on the first
            # frame.to_ndarray() and /audio.bin would just hang).
            missing = self._missing_audio_deps()
            if missing:
                body = (
                    f"audio disabled: missing python package(s): {', '.join(missing)}.\n"
                    f"reinstall pymobiledevice3 (uv tool install ... --reinstall) or pip install {' '.join(missing)}."
                ).encode()
                writer.write(
                    b"HTTP/1.1 503 Audio Unavailable\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                await writer.drain()
                writer.close()
                return
            try:
                await self._ensure_audio_stream()
            except Exception:
                logger.exception("failed to start audio stream")
                writer.write(b"HTTP/1.1 500 Internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Cache-Control: no-cache\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            # ~64 packets at 10 ms each = 640 ms of headroom. Enough to
            # absorb a JS hiccup without dropping audio in the kernel.
            queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=64)
            self._audio_subscribers[queue] = None
            try:
                while True:
                    msg = await queue.get()
                    writer.write(f"{len(msg):x}\r\n".encode() + msg + b"\r\n")
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                self._audio_subscribers.pop(queue, None)
                with contextlib.suppress(Exception):
                    writer.close()
                # We DON'T tear down the iOS audio session when the last
                # subscriber leaves. Empirically iOS refuses to deliver
                # packets after a few session restarts in the same server
                # process -- start_audio_stream returns success but the
                # device sends nothing. Once started, we keep the session
                # alive for the rest of the server's lifetime so subsequent
                # /audio.bin connects always reuse the working session.
                # (Cleaned up at shutdown by serve()'s finally block.)
            return
        if path != "/stream.bin":
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Bring the stream up if it isn't already, but don't force a
        # restart when it's already running. The previous behaviour
        # (force=True on every subscriber connect) tore the device-side
        # session down and back up for every new tab; under stress that
        # left the device's DisplayService XPC channel wedged (handshake
        # timeouts) and matched nothing Xcode does in the sniff. Instead
        # we send a PLI below and mark this subscriber as ``needs_key``
        # so it sees the live stream cleanly from the next IDR onward.
        if self._active_service is None or self._init_sequence is None:
            try:
                await asyncio.wait_for(self._ensure_fresh_stream(force=False), timeout=10.0)
            except (asyncio.TimeoutError, Exception):
                logger.exception("/stream.bin: stream start failed -- replying 503")
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stream_ready.wait(), timeout=3.0)

        # Ask the device to emit a fresh IDR for this new subscriber.
        # Combined with the ``needs_key=True`` state on the subscriber
        # below, the broadcast loop will skip live deltas until the
        # IDR arrives and then send it as a RESET keyframe so the
        # browser rebuilds its decoder cleanly.
        if self._active_service is not None and self._rtcp_dest is not None:
            pli_task = asyncio.create_task(self._send_rtcp_pli())
            self._pli_tasks.add(pli_task)
            pli_task.add_done_callback(self._pli_tasks.discard)

        if self._init_sequence is None or self._active_service is None:
            body = b"stream not ready -- retry in a moment"
            writer.write(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            writer.close()
            return

        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Cache-Control: no-cache\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        # ~1 s of 60 fps headroom during bursty arrival (e.g. when the JS
        # event loop is busy posting input events) before we have to flush
        # and resync from the next keyframe. Overflow recovery costs a
        # PLI-forced IDR now (no periodic refresh loop to piggyback on),
        # so it should stay rare.
        queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=64)
        if self._init_sequence is not None:
            queue.put_nowait(self._init_sequence)
        # New subscribers start with needs_key=True so the broadcast
        # loop holds live deltas until the PLI-induced IDR arrives
        # (deltas reference frames this subscriber never saw, otherwise
        # WebCodecs renders them as silent tears). The IDR will land as
        # a RESET keyframe, prompting the browser to rebuild its decoder.
        state = _SubState()
        state.mark_needs_key(asyncio.get_running_loop().time())
        state.reset_on_key = True
        self._subscribers[queue] = state

        # Bootstrap escalation: the device's encoder occasionally ignores
        # PLIs (a semi-wedged encoder keeps emitting deltas but never an
        # IDR), which would leave this subscriber stuck on init_sequence
        # forever. Retry the PLI twice, then stop asking nicely and force
        # a session restart — a fresh session always opens with a clean
        # IDR without any PLI involved. Don't keep spamming PLIs beyond
        # that: on iOS 26/27 a PLI barrage is itself what corrupts or
        # stalls the encoder (see ``_fire_decoder_refresh``).
        async def _bootstrap_key_escalation():
            for attempt in range(3):
                await asyncio.sleep(1.0)
                if not state.needs_key:
                    return
                if self._active_service is None or self._rtcp_dest is None:
                    return
                if queue not in self._subscribers:
                    return
                if attempt < 2:
                    logger.debug("/stream.bin: subscriber still needs_key, re-PLI")
                    self._request_recovery_idr(reason="bootstrap-retry")
                else:
                    logger.warning("/stream.bin: encoder ignored bootstrap PLIs - forcing session restart")
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(self._ensure_fresh_stream(force=True), timeout=10.0)

        retry_task = asyncio.create_task(_bootstrap_key_escalation())
        self._pli_tasks.add(retry_task)
        retry_task.add_done_callback(self._pli_tasks.discard)

        try:
            while True:
                msg = await queue.get()
                writer.write(f"{len(msg):x}\r\n".encode() + msg + b"\r\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            self._subscribers.pop(queue, None)
            retry_task.cancel()
            with contextlib.suppress(Exception):
                writer.close()

    async def _decoder_refresh_loop(self) -> None:
        """IDR refresh: mid-motion recovery (default) + settle + idle heartbeat.

        Under rapid motion the DisplayService encoder, capped at ~6 Mbps, drops
        capture resolution and composites the shrunk screen top-left with gray
        padding (the "screen shrinks while swiping" tear). Recovering to full
        resolution needs a fresh full-res IDR, and forcing one *while moving*
        recovers fastest -- it's preemptive, so it beats any client-side
        detect-then-request loop (which is always a collapse-cycle behind). So
        the default (``self._motion_idr`` True, ``--motion-idr``) fires an
        **active** keyframe ~1x/s while the byte rate says the screen is moving;
        the viewer stretches the shrunk region to fill the canvas
        (``detectContentCrop``) so the brief pre-IDR window is hidden. The cost
        is keyframe pressure that can stall this encoder under very sustained
        motion; ``--no-motion-idr`` drops the active trigger for a stall-free
        but slower-recovering stream (viewer stretch + settle IDR only).

        Triggers:
          - **Active** (``--motion-idr`` only) — screen moving: one PLI every
            ``active_interval`` so the collapse snaps back fast.
          - **Settle** — byte rate stayed *continuously* below
            ``motion_threshold_bps`` for ``settle_quiet`` (a genuine pause, not
            an inter-swipe micro-dip): one PLI so the static screen is crisp.
          - **Heartbeat** — idle backstop every ``heartbeat`` s; also clears a
            subscriber stuck in ``needs_key``.
        """
        loop = asyncio.get_running_loop()
        motion_threshold_bps = 200_000
        # Active mid-motion IDR (default; gated by self._motion_idr). Settle and
        # heartbeat additionally fire only when NOT under motion load. settle
        # requires the byte rate to stay CONTINUOUSLY below threshold so an
        # inter-swipe micro-dip can't retrigger it into a storm.
        settle_quiet = 1.5  # byte rate must stay quiet CONTINUOUSLY this long
        heartbeat = 10.0  # backstop cadence when idle
        min_interval = 0.7  # don't fire more often than this
        active_interval = 1.0  # --motion-idr cadence while moving
        quiet_since: Optional[float] = None
        motion_active = False
        motion_started_t = 0.0
        while True:
            try:
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                return
            if not self._subscribers:
                continue
            if self._active_service is None or self._rtcp_dest is None:
                continue
            now = loop.time()
            # The window is pruned to the last 1 s at append time.
            window_bytes = sum(s for _, s in self._au_byte_window)
            currently_active = window_bytes >= motion_threshold_bps
            if currently_active and not motion_active:
                motion_started_t = now
            motion_active = currently_active
            if currently_active:
                quiet_since = None  # any motion resets the quiet timer
            elif quiet_since is None:
                quiet_since = now
            since_refresh = now - self._last_refresh_t
            if since_refresh < min_interval:
                continue
            # xcode-parity: with --no-motion-idr, force NO refresh IDRs at all
            # (active/settle/heartbeat). Apple's smooth session shows idr_fps=0 --
            # any forced keyframe under saturation makes the encoder drop
            # resolution to fit it (the collapse). New-subscriber bootstrap and
            # the stall-watchdog still supply keyframes when genuinely needed.
            if not self._motion_idr:
                continue
            quiet_for = None if quiet_since is None else (now - quiet_since)
            # Optional mid-motion IDR storm (off by default; --motion-idr).
            active = (
                self._motion_idr
                and currently_active
                and motion_started_t > 0
                and (now - motion_started_t) >= active_interval
                and since_refresh >= active_interval
            )
            settled = quiet_for is not None and quiet_for >= settle_quiet and self._last_refresh_t < quiet_since
            heartbeat_due = quiet_for is not None and since_refresh >= heartbeat
            if not (active or settled or heartbeat_due):
                continue
            reason = "active" if active else ("settled" if settled else "heartbeat")
            self._fire_decoder_refresh(now, reason=reason)

    def _fire_decoder_refresh(self, now: float, *, reason: str) -> None:
        """Send one PLI so the device emits a fresh IDR.

        Don't flush subscriber queues or set needs_key here — the fresh
        IDR is broadcast as a normal type=0 key, which the browser
        absorbs as a clean DPB anchor without rebuilding its decoder
        (rebuild-per-refresh is what reads as chop under motion). The
        callers that really lost data set ``needs_key`` themselves.
        """
        pli_task = asyncio.create_task(self._send_rtcp_pli())
        self._pli_tasks.add(pli_task)
        pli_task.add_done_callback(self._pli_tasks.discard)
        self._last_refresh_t = now
        window_bps = sum(s for _, s in self._au_byte_window)
        logger.info(
            "decoder-refresh (%s): %d subscriber(s), %d B/s window",
            reason,
            len(self._subscribers),
            window_bps,
        )

    def _request_recovery_idr(self, *, reason: str) -> None:
        """Rate-limited PLI for the data-loss recovery paths (dropped
        corrupt AU, subscriber queue overflow). Rate limiting matters:
        a loss burst or a persistently slow subscriber must not turn
        into a PLI storm — this encoder corrupts/stalls under one (see
        :meth:`_fire_decoder_refresh`)."""
        loop = asyncio.get_running_loop()
        now = loop.time()
        if now - self._last_refresh_t < 0.7:
            return
        self._fire_decoder_refresh(now, reason=reason)

    async def _stall_watchdog(self) -> None:
        """Restart the media stream when the encoder stops cooperating.

        Two triggers:
          1. **AU stall** — no AU progressed in :data:`_STALL_RESTART_SECS`
             (encoder stopped emitting entirely — e.g. after it choked on
             a PLI, or the display slept).
          2. **Ignored key request** — AUs keep flowing but a subscriber
             has been sitting in ``needs_key`` for longer than
             ``_NEEDS_KEY_RESTART_SECS``: the encoder is emitting deltas
             while ignoring our PLIs, so the subscriber would freeze
             forever. A session restart is the only reliable way to get
             an IDR out of a semi-wedged encoder.

        Honours :data:`_STALL_RESTART_COOLDOWN_SECS` so a legitimate idle
        (e.g. the device is locked) doesn't loop us into a hot restart cycle.
        """
        loop = asyncio.get_running_loop()
        check_interval = max(_STALL_RESTART_SECS / 4, 0.25)
        while True:
            try:
                await asyncio.sleep(check_interval)
            except asyncio.CancelledError:
                return
            if not self._subscribers:
                continue
            if self._active_service is None:
                continue
            now = loop.time()
            stalled = now - self._last_good_au_t > _STALL_RESTART_SECS
            # NOTE: master restarts ONLY on a true AU stall. The branch added a
            # second "key_starved" trigger (restart if any subscriber sat in
            # needs_key > needs_key_restart_secs) -- but under motion the browser's
            # WebCodecs decoder flags needs_key constantly, so that fired ~every
            # few seconds and hammered the stream with restarts (fps->0), a
            # regression vs master (0 restarts on the same motion). Restore
            # master's single AU-stall trigger. A genuinely wedged encoder that
            # ignores PLIs is still caught by the true AU stall.
            if not stalled:
                # Stream is making progress -- prior restarts are forgiven.
                self._consecutive_restarts = 0
                continue
            if now - self._last_restart_t < _STALL_RESTART_COOLDOWN_SECS:
                continue
            if self._consecutive_restarts >= _MAX_STALL_RESTARTS:
                # Further restarts aren't fixing things. Stop pummelling the
                # device daemon -- next time the user reloads the page the
                # cold /codec path will attempt a fresh start anyway.
                continue
            self._consecutive_restarts += 1
            logger.warning(
                "no AU progress in %.1fs (subscribers=%d, attempt %d/%d) - restarting stream",
                now - self._last_good_au_t,
                len(self._subscribers),
                self._consecutive_restarts,
                _MAX_STALL_RESTARTS,
            )
            self._last_restart_t = now
            # Bound the whole restart so a hang on the device side
            # (cleanup or start) can't hold _stream_lock forever and
            # silently block subsequent /codec and /stream.bin paths.
            # The inner _stop_active_stream already bounds its own
            # XPC calls; this is the outer safety net covering the
            # start side too (connect / start_video_stream).
            try:
                await asyncio.wait_for(self._ensure_fresh_stream(force=True), timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("stall-watchdog restart did not complete within 10s")
            except Exception as exc:
                if _is_tunnel_dead_error(exc):
                    logger.warning("device appears disconnected (%s); handing off to reconnect loop", exc)
                    self._reconnect_signal.set()
                else:
                    logger.exception("stall-watchdog restart failed")

    async def _reconnect_loop(self) -> None:
        """Wait for a disconnect signal, then poll tunneld until the
        same UDID reappears, rebind ``self._rsd``, and resume streaming.

        Triggered from the stall watchdog when restart fails with a
        tunnel-level error (No route to host, Connection reset, etc.).
        We tear down the active video/audio sessions (whose sockets and
        XPC channels are pointing at the dead tunnel), mark every
        subscriber as ``needs_key`` so the post-rebind IDR rebuilds
        their decoders, then poll tunneld every
        ``_reconnect_poll_interval`` seconds for the device. When it
        comes back we swap in the fresh RSD and kick off a new media
        stream; the browser-side offline overlay clears the moment AUs
        flow again.
        """
        udid = str(self._rsd.udid)
        while True:
            try:
                await self._reconnect_signal.wait()
            except asyncio.CancelledError:
                return
            logger.warning("device %s disconnected; waiting for tunneld to surface it again", udid)
            # Tear down anything pinned to the dead tunnel. Errors are
            # expected here (the same disconnect that triggered us will
            # make stop_media_stream raise) so suppress and move on.
            with contextlib.suppress(Exception):
                async with self._stream_lock:
                    await self._stop_active_stream()
            with contextlib.suppress(Exception):
                await self._stop_audio_stream()
            # Drop HID handles so the next /touch reopens against the
            # fresh RSD; the worker task itself stays alive.
            with contextlib.suppress(Exception):
                await self._stop_hid()
            # Force subscribers to wait for a fresh keyframe once the
            # stream comes back -- their decoder state spans the gap
            # and the post-rebind IDR is the only safe resync point.
            for state in self._subscribers.values():
                state.mark_needs_key(asyncio.get_running_loop().time())
            # Poll tunneld until the device returns. ``get_tunneld_device_by_udid``
            # returns None when it's not listed; any exception (tunneld
            # itself down, transient HTTP error) is treated the same way.
            new_rsd: Optional[RemoteServiceDiscoveryService] = None
            while new_rsd is None:
                try:
                    new_rsd = await get_tunneld_device_by_udid(udid)
                except Exception:
                    logger.debug("tunneld poll failed", exc_info=True)
                if new_rsd is not None:
                    break
                try:
                    await asyncio.sleep(self._reconnect_poll_interval)
                except asyncio.CancelledError:
                    return
            old_rsd = self._rsd
            self._rsd = new_rsd
            with contextlib.suppress(Exception):
                await old_rsd.close()
            # Clear cached codec string so /codec re-derives it from the
            # new SPS, and reset stall-restart bookkeeping so the
            # watchdog doesn't refuse to recover.
            self._codec_string = None
            self._vps_nal = self._sps_nal = self._pps_nal = None
            self._init_sequence = None
            self._saw_first_key = False
            self._stream_ready.clear()
            self._consecutive_restarts = 0
            self._last_restart_t = 0.0
            self._last_good_au_t = asyncio.get_running_loop().time()
            self._reconnect_signal.clear()
            logger.info("device %s back online via tunneld; resuming stream", udid)
            try:
                await asyncio.wait_for(self._ensure_fresh_stream(force=True), timeout=15.0)
            except Exception as exc:
                if _is_tunnel_dead_error(exc):
                    # Tunnel died again between rebind and stream start
                    # -- loop back and wait for another reappearance
                    # instead of giving up. Don't `signal.set()` here
                    # because we're already past wait(); just continue.
                    logger.warning("device flapped during resume; re-entering wait")
                    self._reconnect_signal.set()
                else:
                    logger.exception("post-reconnect stream start failed")

    async def _keep_awake_loop(self) -> None:
        """Hold a PreventUserIdleSystemSleep IOPMAssertion on the device
        so it doesn't auto-lock mid-session.

        Without this iOS sleeps the display after the user's auto-lock
        timer (often 2 minutes) and the screen-capture pipeline halts:
        AUs stop arriving, the stall watchdog fires, and the restart
        also can't complete because a locked device won't start a fresh
        DisplayService session cleanly. End result is the server going
        silently unresponsive until the user manually wakes the device.

        Renewal cadence is well under the requested timeout so a single
        slow renewal cycle can't drop the assertion."""
        assertion_timeout = 300  # 5 min — long enough that a missed renew is harmless
        refresh_interval = 120  # 2 min — well under timeout
        try:
            while True:
                try:
                    # PowerAssertionService picks its RSD shim service name
                    # (com.apple.mobile.assertion_agent.shim.remote) when
                    # handed an RSD, so this rides the same tunnel as
                    # everything else -- no usbmuxd dependency.
                    svc = PowerAssertionService(self._rsd)
                    async with svc.create_power_assertion(
                        "PreventUserIdleSystemSleep",
                        "pymobiledevice3.serve-web",
                        assertion_timeout,
                        "serve-web keeping device awake for screen mirroring",
                    ):
                        pass
                except Exception:
                    logger.debug("keep-awake renew failed; will retry", exc_info=True)
                try:
                    await asyncio.sleep(refresh_interval)
                except asyncio.CancelledError:
                    return
        except asyncio.CancelledError:
            return
        except Exception:
            logger.warning("keep-awake loop crashed (device may auto-lock)", exc_info=True)

    async def _eager_stream_start(self) -> None:
        """Bring the device-side streams up at server boot.

        Two reasons to start eagerly:
        1. The video codec string is cached by the time the browser
           opens, avoiding the ~6-10 s cold-start "failed to fetch"
           on the first /codec request.
        2. Xcode's Mirror always brings up BOTH audio and video at
           session start with a shared client_session_id (sniff4
           confirms). Without the paired audio session, iOS's media
           manager treats us as a lone video client and may throttle
           the encoder. Audio runs from boot regardless of whether a
           /audio.bin subscriber is attached -- it's a session
           liveness signal, not just a feature for the user.

        Sequence matches Xcode verbatim: audio first, then video.
        Failures in either branch are logged but don't block the HTTP
        server -- /codec and /stream.bin retry on their own."""
        try:
            await self._ensure_audio_stream()
        except Exception:
            logger.warning("eager audio start failed (will retry on /audio.bin connect)", exc_info=True)
        try:
            await self._ensure_fresh_stream(force=False)
        except Exception:
            logger.warning("eager video start failed (will retry on first /codec)", exc_info=True)

    async def serve(self) -> None:
        """Run the HTTP server until cancelled / Ctrl-C."""
        ssl_ctx = _build_self_signed_ssl_context(self._bind) if self._https else None
        http_server = await asyncio.start_server(
            self._handle_http,
            self._bind,
            self._http_port,
            ssl=ssl_ctx,
        )
        watchdog = asyncio.create_task(self._stall_watchdog())
        decoder_refresh = asyncio.create_task(self._decoder_refresh_loop())
        self._rctl_task = asyncio.create_task(self._rctl_feedback_loop())
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())
        self._keep_awake_task = asyncio.create_task(self._keep_awake_loop())
        # Eagerly start the HID worker so queued /touch requests are
        # processed even before the device-stream is fully up.
        self._hid_worker_task = asyncio.create_task(self._hid_worker())
        # Kick off the video stream in the background. We don't await it
        # here -- the HTTP server should accept connections immediately
        # so the user sees a working /index.html even if the device-side
        # handshake is slow.
        eager_start = asyncio.create_task(self._eager_stream_start())

        # Install signal handlers so Ctrl-C / SIGTERM trigger an
        # orderly, fast shutdown instead of waiting for blocked RPCs.
        # On Windows add_signal_handler isn't supported -- fall back to
        # the default KeyboardInterrupt-raising behaviour.
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _request_stop():
            if not stop_event.is_set():
                logger.info("shutting down...")
                stop_event.set()

        for signame in ("SIGINT", "SIGTERM"):
            with contextlib.suppress(NotImplementedError, AttributeError):
                import signal

                loop.add_signal_handler(getattr(signal, signame), _request_stop)

        async def _bounded(coro, label, timeout=3.0):
            """Run an async cleanup step with a hard timeout so a hung
            RPC can't keep us alive at shutdown."""
            try:
                await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("shutdown: %s timed out after %.1fs", label, timeout)
            except Exception:
                logger.exception("shutdown: %s raised", label)

        # Run the server until stop_event fires. Spawn serve_forever() as a
        # background task so we can cancel it cheaply from the signal path
        # without awaiting it -- awaiting a cancelled serve_forever() with
        # active connection handlers can wedge the shutdown indefinitely
        # (the straggler cancel at the end of this function mops it up).
        serve_task = asyncio.create_task(http_server.serve_forever(), name="serve_forever")
        try:
            scheme = "https" if self._https else "http"
            logger.info(f"Open {scheme}://{self._bind}:{self._http_port}/ in Safari/Chrome. Ctrl-C to stop.")
            await stop_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            if not serve_task.done():
                serve_task.cancel()
            logger.debug("shutdown: cancelling watchdog")
            watchdog.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await watchdog
            if self._rctl_task is not None:
                self._rctl_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._rctl_task
            decoder_refresh.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await decoder_refresh
            if self._reconnect_task is not None:
                self._reconnect_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._reconnect_task
            if self._keep_awake_task is not None:
                self._keep_awake_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._keep_awake_task
            logger.debug("shutdown: cancelling eager_start")
            eager_start.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await eager_start
            # Close the HTTP listener first so no new connections come in
            # while we tear the device-side streams down.
            logger.debug("shutdown: closing HTTP server")
            http_server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(http_server.wait_closed(), timeout=2.0)
            logger.debug("shutdown: stopping HID")
            await _bounded(self._stop_hid(), "_stop_hid")
            task = self._hid_worker_task
            self._hid_worker_task = None
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

            # _stop_active_stream / _stop_audio_stream issue
            # stop_media_stream RPCs to the device daemon -- if the
            # daemon is hung, these would block forever without a bound.
            async def _stop_video():
                async with self._stream_lock:
                    await self._stop_active_stream()

            async def _stop_audio():
                async with self._audio_lock:
                    await self._stop_audio_stream()

            logger.debug("shutdown: stopping video stream")
            await _bounded(_stop_video(), "_stop_active_stream")
            logger.debug("shutdown: stopping audio stream")
            await _bounded(_stop_audio(), "_stop_audio_stream")
            # Close the accessibility audit BEFORE cancelling stragglers --
            # otherwise its DTX reader task is one of the stragglers and
            # its cancellation logs a 'Channel reader loop cancelled'
            # ERROR-with-traceback. Closing first sets _closed=True on
            # the channel so the reader exits silently. Any in-flight
            # /accessibility request gets an exception out of its
            # await audit.* call and falls through to its try/except.
            logger.debug("shutdown: closing accessibility audit")
            await _bounded(self._stop_accessibility(), "_stop_accessibility")
            # Cancel any lingering connection-handler tasks that the
            # HTTP server's wait_closed couldn't drain (e.g. a
            # /stream.bin or /audio.bin handler blocked in queue.get()
            # because the listener was closed before they finished
            # writing). Without this they hold the asyncio loop alive
            # and the process never exits.
            current = asyncio.current_task()
            stragglers = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
            if stragglers:
                logger.debug("shutdown: cancelling %d straggler task(s)", len(stragglers))
                for t in stragglers:
                    t.cancel()
                with contextlib.suppress(Exception):
                    await asyncio.wait(stragglers, timeout=2.0)
            logger.info("shutdown complete")
