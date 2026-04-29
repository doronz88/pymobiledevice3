"""
Valeria protocol-based iOS screen capture (Linux).

Speaks Apple's internal USB screen-capture protocol directly — the same
protocol that ``iOSScreenCapture.plugin`` (the QuickTime DAL plugin) uses
under the hood.  Because we address the device by USB serial number (= UDID),
this backend supports exact device selection even for multiple identical-model
devices.

The protocol was reverse-engineered by Daniel Paulus
(https://github.com/nickaknudson/quicktime_video_hack).

Requirements:
    pip install pyusb   (already a pymobiledevice3 dependency)

For JPEG output (needed by the MJPEG WebSocket viewer):
    pip install av       (PyAV — Python bindings for FFmpeg)

Without PyAV, raw H.264 NALUs are available but cannot be served to the
browser via the existing MJPEG path.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import queue
import struct
import threading
import time
from typing import AsyncIterator, Iterator, Optional

import usb.core
import usb.util

from pymobiledevice3.services.valeria import (
    BackendUnavailableError,
    DeviceNotFoundError,
    H264Frame,
    IOSScreenCapture,
)

logger = logging.getLogger(__name__)

# On macOS 15+, libusb cannot claim Apple USB interfaces due to IOKit/DriverKit
# restrictions.  Valeria capture is only available on Linux (and potentially
# Windows).  On macOS, use AVFoundation instead.
_MACOS = platform.system() == 'Darwin'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APPLE_VENDOR_ID = 0x05AC
QUICKTIME_SUBCLASS = 0x2A

# Packet magics (little-endian uint32)
PING = 0x70696E67  # 'ping'
SYNC = 0x73796E63  # 'sync'
ASYN = 0x6173796E  # 'asyn'
RPLY = 0x72706C79  # 'rply'

# SYNC subtypes
OG = 0x676F2120    # 'go !'
CWPA = 0x63777061  # 'cwpa'
CVRP = 0x63767270  # 'cvrp'
CLOK = 0x636C6F6B  # 'clok'
TIME = 0x74696D65  # 'time'
AFMT = 0x61666D74  # 'afmt'
SKEW = 0x736B6577  # 'skew'
STOP = 0x73746F70  # 'stop'

# ASYN subtypes
FEED = 0x66656564  # 'feed'
EAT = 0x65617421   # 'eat!'
NEED = 0x6E656564  # 'need'
HPD1 = 0x68706431  # 'hpd1'
HPA1 = 0x68706131  # 'hpa1'
HPD0 = 0x68706430  # 'hpd0'
HPA0 = 0x68706130  # 'hpa0'
SPRP = 0x73707270  # 'sprp'
SRAT = 0x73726174  # 'srat'
TBAS = 0x74626173  # 'tbas'
TJMP = 0x746A6D70  # 'tjmp'
RELS = 0x72656C73  # 'rels'

# CMSampleBuffer magics
SBUF = 0x73627566  # 'sbuf'
OPTS = 0x6F707473  # 'opts'
STIA = 0x73746961  # 'stia'
SDAT = 0x73646174  # 'sdat'
NSMP = 0x6E736D70  # 'nsmp'
SSIZ = 0x7373697A  # 'ssiz'
FDSC = 0x66647363  # 'fdsc'
SATT = 0x73617474  # 'satt'
SARY = 0x73617279  # 'sary'

# FormatDescriptor sub-magics
MDIA = 0x6D646961  # 'mdia'
VDIM = 0x7664696D  # 'vdim'
CODC = 0x636F6463  # 'codc'
EXTN = 0x6578746E  # 'extn'

MEDIA_TYPE_VIDEO = 0x76696465  # 'vide'
CODEC_AVC1 = 0x61766331       # 'avc1'

# Dict magics
DICT = 0x64696374  # 'dict'
KEYV = 0x6B657976  # 'keyv'
STRK = 0x7374726B  # 'strk'
IDXK = 0x6964786B  # 'idxk'
BULV = 0x62756C76  # 'bulv'
DATV = 0x64617476  # 'datv'
STRV = 0x73747276  # 'strv'
NMBV = 0x6E6D6276  # 'nmbv'

EMPTY_CFTYPE = 1
NANOSECOND_SCALE = 1_000_000_000

LE = 'little'

# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------


def _u32(data: bytes, off: int = 0) -> int:
    return int.from_bytes(data[off:off + 4], LE)


def _u64(data: bytes, off: int = 0) -> int:
    return int.from_bytes(data[off:off + 8], LE)


def _p32(val: int) -> bytes:
    return val.to_bytes(4, LE)


def _p64(val: int) -> bytes:
    return val.to_bytes(8, LE)


def _p_f64(val: float) -> bytes:
    return struct.pack('<d', val)


# ---------------------------------------------------------------------------
# CMTime
# ---------------------------------------------------------------------------


class CMTime:
    """Minimal CMTime — 24 bytes: value(u64) + scale(u32) + flags(u32) + epoch(u64)."""

    __slots__ = ('value', 'scale', 'flags', 'epoch')
    LENGTH = 24

    def __init__(self, value: int = 0, scale: int = 0, flags: int = 0, epoch: int = 0):
        self.value = value
        self.scale = scale
        self.flags = flags
        self.epoch = epoch

    @classmethod
    def from_bytes(cls, data: bytes, off: int = 0) -> 'CMTime':
        return cls(
            value=_u64(data, off),
            scale=_u32(data, off + 8),
            flags=_u32(data, off + 12),
            epoch=_u64(data, off + 16),
        )

    def to_bytes(self) -> bytes:
        return _p64(self.value) + _p32(self.scale) + _p32(self.flags) + _p64(self.epoch)

    def __repr__(self) -> str:
        return f'CMTime({self.value}/{self.scale})'


class CMClock:
    """Monotonic clock that tracks time since creation."""

    def __init__(self, clock_id: int, scale: int = NANOSECOND_SCALE):
        self.clock_id = clock_id
        self.scale = scale
        self._start = time.monotonic_ns()

    def get_time(self) -> CMTime:
        elapsed_ns = time.monotonic_ns() - self._start
        if self.scale == NANOSECOND_SCALE:
            value = elapsed_ns
        else:
            value = int(elapsed_ns * self.scale / NANOSECOND_SCALE)
        return CMTime(value=value, scale=self.scale, flags=1, epoch=0)


# ---------------------------------------------------------------------------
# Dict serialization (outbound only — hardcoded for the fixed dicts we send)
# ---------------------------------------------------------------------------


def _serialize_dict(entries: list[tuple[str, object]]) -> bytes:
    """Serialize a StringKeyDict to bytes. Supports str, bool, float, int, bytes, nested dict."""
    kvs = b''
    for key, val in entries:
        k = _serialize_strkey(key)
        v = _serialize_value(val)
        pair = _p32(8 + len(k) + len(v)) + _p32(KEYV) + k + v
        kvs += pair
    return _p32(8 + len(kvs)) + _p32(DICT) + kvs


def _serialize_strkey(key: str) -> bytes:
    kb = key.encode('utf-8')
    return _p32(8 + len(kb)) + _p32(STRK) + kb


def _serialize_value(val: object) -> bytes:
    if isinstance(val, bool):
        return _p32(9) + _p32(BULV) + bytes([1 if val else 0])
    if isinstance(val, float):
        payload = bytes([6]) + _p_f64(val)
        return _p32(8 + len(payload)) + _p32(NMBV) + payload
    if isinstance(val, int):
        payload = bytes([3]) + _p32(val)
        return _p32(8 + len(payload)) + _p32(NMBV) + payload
    if isinstance(val, str):
        sb = val.encode('utf-8')
        return _p32(8 + len(sb)) + _p32(STRV) + sb
    if isinstance(val, bytes):
        return _p32(8 + len(val)) + _p32(DATV) + val
    if isinstance(val, list):
        # list of (key, value) tuples → nested dict
        return _serialize_dict(val)
    raise TypeError(f'Unsupported dict value type: {type(val)}')


# ---------------------------------------------------------------------------
# Audio Stream Basic Description (ASBD) — fixed 40-byte struct
# ---------------------------------------------------------------------------


def _default_asbd() -> bytes:
    """Default LPCM audio format: 48kHz, 16-bit, stereo.

    56 bytes: 40-byte AudioStreamBasicDescription + SampleRate repeated twice.
    Matches the Go reference implementation exactly.
    """
    buf = bytearray(56)
    struct.pack_into('<d', buf, 0, 48000.0)     # mSampleRate
    struct.pack_into('<I', buf, 8, 0x6C70636D)  # mFormatID = 'lpcm'
    struct.pack_into('<I', buf, 12, 12)         # mFormatFlags
    struct.pack_into('<I', buf, 16, 4)          # mBytesPerPacket
    struct.pack_into('<I', buf, 20, 1)          # mFramesPerPacket
    struct.pack_into('<I', buf, 24, 4)          # mBytesPerFrame
    struct.pack_into('<I', buf, 28, 2)          # mChannelsPerFrame
    struct.pack_into('<I', buf, 32, 16)         # mBitsPerChannel
    struct.pack_into('<I', buf, 36, 0)          # mReserved
    struct.pack_into('<d', buf, 40, 48000.0)    # SampleRate (repeated)
    struct.pack_into('<d', buf, 48, 48000.0)    # SampleRate (repeated)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Packet construction
# ---------------------------------------------------------------------------


def _ping_packet() -> bytes:
    return _p32(16) + _p32(PING) + _p64(0x0000000100000000)


def _clock_ref_reply(correlation_id: int, clock_ref: int) -> bytes:
    return (_p32(28) + _p32(RPLY) + _p64(correlation_id) +
            _p32(0) + _p64(clock_ref))


def _og_reply(correlation_id: int) -> bytes:
    return _p32(24) + _p32(RPLY) + _p64(correlation_id) + _p64(0)


def _time_reply(correlation_id: int, cm_time: CMTime) -> bytes:
    return _p32(44) + _p32(RPLY) + _p64(correlation_id) + _p32(0) + cm_time.to_bytes()


def _afmt_reply(correlation_id: int) -> bytes:
    error_dict = _serialize_dict([('Error', 0)])
    return (_p32(20 + len(error_dict)) + _p32(RPLY) + _p64(correlation_id) +
            _p32(0) + error_dict)


def _skew_reply(correlation_id: int, skew: float) -> bytes:
    return _p32(28) + _p32(RPLY) + _p64(correlation_id) + _p32(0) + _p_f64(skew)


def _stop_reply(correlation_id: int) -> bytes:
    return _p32(24) + _p32(RPLY) + _p64(correlation_id) + _p32(0) + _p32(0)


def _asyn_need(clock_ref: int) -> bytes:
    return _p32(20) + _p32(ASYN) + _p64(clock_ref) + _p32(NEED)


def _asyn_hpd0() -> bytes:
    return _p32(20) + _p32(ASYN) + _p64(EMPTY_CFTYPE) + _p32(HPD0)


def _asyn_hpa0(clock_ref: int) -> bytes:
    return _p32(20) + _p32(ASYN) + _p64(clock_ref) + _p32(HPA0)


def _asyn_dict_packet(subtype: int, clock_ref: int, dict_bytes: bytes) -> bytes:
    length = 20 + len(dict_bytes)
    return (_p32(length) + _p32(ASYN) + _p64(clock_ref) +
            _p32(subtype) + dict_bytes)


def _hpd1_packet() -> bytes:
    """HPD1 — tell the device what video format we want."""
    d = _serialize_dict([
        ('Valeria', True),
        ('HEVCDecoderSupports444', True),
        ('DisplaySize', [('Width', 1920.0), ('Height', 1200.0)]),
    ])
    return _asyn_dict_packet(HPD1, EMPTY_CFTYPE, d)


def _hpa1_packet(clock_ref: int) -> bytes:
    """HPA1 — tell the device what audio format we want."""
    asbd = _default_asbd()
    d = _serialize_dict([
        ('BufferAheadInterval', 0.07300000000000001),
        ('deviceUID', 'Valeria'),
        ('ScreenLatency', 0.04),
        ('formats', asbd),
        ('EDIDAC3Support', 0),
        ('deviceName', 'Valeria'),
    ])
    return _asyn_dict_packet(HPA1, clock_ref, d)


# ---------------------------------------------------------------------------
# CMSampleBuffer parser — extracts H.264 NALUs from FEED packets
# ---------------------------------------------------------------------------


def _parse_length_magic(data: bytes, off: int = 0) -> tuple[int, int, int]:
    """Return (length, magic, payload_offset)."""
    length = _u32(data, off)
    magic = _u32(data, off + 4)
    return length, magic, off + 8


def _parse_feed_sbuf(data: bytes) -> Optional[H264Frame]:
    """Parse a CMSampleBuffer from FEED packet payload (after the 16-byte asyn header).

    Returns an H264Frame with raw NALU data, or None on failure.
    """
    # data starts at the sbuf section
    length, magic, off = _parse_length_magic(data, 0)
    if magic != SBUF:
        return None

    frame = H264Frame()
    end = length
    pos = off

    while pos < end and pos + 8 <= len(data):
        sec_length = _u32(data, pos)
        sec_magic = _u32(data, pos + 4)
        if sec_length < 8 or pos + sec_length > len(data):
            break

        if sec_magic == OPTS:
            # Output Presentation Timestamp — CMTime at pos+8
            if pos + 8 + CMTime.LENGTH <= len(data):
                ct = CMTime.from_bytes(data, pos + 8)
                frame.pts_value = ct.value
                frame.pts_scale = ct.scale
            pos += 32  # opts section is always 32 bytes

        elif sec_magic == SDAT:
            # Sample data — the actual H.264 NALUs (AVCC length-prefixed)
            frame.nalu_data = data[pos + 8:pos + sec_length]
            pos += sec_length

        elif sec_magic == FDSC:
            # FormatDescriptor — contains SPS/PPS for video
            _parse_fdsc(data[pos:pos + sec_length], frame)
            pos += sec_length

        elif sec_magic in (STIA, NSMP, SSIZ, SATT, SARY):
            # Known sections we don't need — skip
            pos += sec_length

        else:
            # Unknown section — skip
            pos += sec_length

    if frame.nalu_data:
        return frame
    return None


def _parse_fdsc(data: bytes, frame: H264Frame) -> None:
    """Parse a FormatDescriptor to extract video dimensions and SPS/PPS."""
    try:
        pos = 8  # skip length + 'fdsc'

        # mdia section
        length, magic = _u32(data, pos), _u32(data, pos + 4)
        if magic != MDIA or length < 12:
            return
        media_type = _u32(data, pos + 8)
        if media_type != MEDIA_TYPE_VIDEO:
            return
        pos += length

        # vdim section
        length, magic = _u32(data, pos), _u32(data, pos + 4)
        if magic != VDIM or length < 16:
            return
        frame.width = _u32(data, pos + 8)
        frame.height = _u32(data, pos + 12)
        pos += length

        # codc section
        length, magic = _u32(data, pos), _u32(data, pos + 4)
        if magic != CODC:
            return
        pos += length

        # extn section — contains IndexKeyDict with SPS/PPS
        length, magic = _u32(data, pos), _u32(data, pos + 4)
        if magic != EXTN:
            return
        _extract_sps_pps(data[pos:pos + length], frame)
    except (IndexError, struct.error):
        pass


def _extract_sps_pps(extn_data: bytes, frame: H264Frame) -> None:
    """Walk the extensions IndexKeyDict to find the avcC record with SPS/PPS.

    The avcC record is at index key 49 → index key 105 → raw bytes.
    """
    try:
        # Find key 49 in the IndexKeyDict
        avcc_data = _find_index_key_data(extn_data[8:], 49)
        if avcc_data is None:
            return
        # Key 49's value is another IndexKeyDict; find key 105
        raw = _find_index_key_data(avcc_data, 105)
        if raw is None or len(raw) < 12:
            return
        # Parse avcC record (AVCDecoderConfigurationRecord):
        # data[6:8] = SPS length (BE uint16), data[8:8+len] = SPS NALU
        # then: PPS count, PPS length (BE uint16), PPS NALU
        sps_len = raw[7]  # low byte of BE uint16 (high byte at [6] is 0 for small NALUs)
        if 8 + sps_len + 3 > len(raw):
            return
        frame.sps = bytes(raw[8:8 + sps_len])
        pps_len = raw[10 + sps_len]
        if 11 + sps_len + pps_len > len(raw):
            return
        frame.pps = bytes(raw[11 + sps_len:11 + sps_len + pps_len])
    except (IndexError, struct.error):
        pass


def _find_index_key_data(data: bytes, target_key: int) -> Optional[bytes]:
    """Search an IndexKeyDict's entries for a specific integer key, return value bytes."""
    pos = 0
    while pos + 8 <= len(data):
        pair_len = _u32(data, pos)
        pair_magic = _u32(data, pos + 4)
        if pair_magic != KEYV or pair_len < 8:
            break
        # Inside keyv: idxk section then value
        inner = data[pos + 8:pos + pair_len]
        if len(inner) < 8:
            break
        key_len = _u32(inner, 0)
        key_magic = _u32(inner, 4)
        if key_magic == IDXK and key_len >= 10:
            key_val = int.from_bytes(inner[8:10], LE)
            value_data = inner[key_len:]
            if key_val == target_key and len(value_data) >= 8:
                val_len = _u32(value_data, 0)
                val_magic = _u32(value_data, 4)
                if val_magic == DATV:
                    return value_data[8:val_len]
                elif val_magic in (DICT, EXTN, SATT):
                    # Nested dict — return the content for further parsing
                    return value_data[8:val_len]
        pos += pair_len
    return None


# ---------------------------------------------------------------------------
# USB device discovery and activation
# ---------------------------------------------------------------------------


def _find_apple_device(udid: Optional[str] = None) -> Optional[usb.core.Device]:
    """Find an Apple iOS device by UDID (USB serial number)."""
    for dev in usb.core.find(find_all=True, idVendor=APPLE_VENDOR_ID):
        try:
            serial = dev.serial_number
            if serial is None:
                continue
            # Newer devices (Xr/Xs/etc) have 24-char serials; usbmux adds a dash
            serial_clean = serial.replace('\x00', '')
            if udid is None:
                return dev
            # Compare with and without dash
            udid_clean = udid.replace('-', '')
            serial_compare = serial_clean.replace('-', '')
            if serial_compare == udid_clean:
                return dev
        except Exception:
            continue
    return None


def _find_qt_config_number(dev: usb.core.Device) -> Optional[int]:
    """Find the config number that contains the SubClass 0x2A interface."""
    try:
        for cfg in dev:
            for intf in cfg:
                if intf.bInterfaceClass == 0xFF and intf.bInterfaceSubClass == QUICKTIME_SUBCLASS:
                    return cfg.bConfigurationValue
    except Exception:
        pass
    return None


def _active_config_has_qt(dev: usb.core.Device) -> bool:
    """Check if the active configuration has the QT interface."""
    try:
        cfg = dev.get_active_configuration()
        for intf in cfg:
            if intf.bInterfaceClass == 0xFF and intf.bInterfaceSubClass == QUICKTIME_SUBCLASS:
                return True
    except Exception:
        pass
    return False


def _activate_valeria(dev: usb.core.Device, timeout: float = 10.0) -> usb.core.Device:
    """Activate Valeria and ensure the QT config is active.

    Returns a device handle with the QuickTime config active.
    """
    qt_cfg = _find_qt_config_number(dev)
    if qt_cfg is not None and _active_config_has_qt(dev):
        logger.debug('Valeria: device already has QT config %d active', qt_cfg)
        return dev

    serial = dev.serial_number

    if qt_cfg is None:
        # QT config not present — need to send activation control transfer
        logger.info('Valeria: activating screen capture on %s…',
                     serial[:8] if serial else '???')
        try:
            dev.ctrl_transfer(0x40, 0x52, 0x00, 0x02, b'')
        except usb.core.USBError as e:
            logger.debug('Valeria: control transfer result: %s (expected)', e)

        # Wait for device to re-enumerate with QT config available
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(0.5)
            new_dev = _find_apple_device(serial)
            if new_dev is not None:
                qt_cfg = _find_qt_config_number(new_dev)
                if qt_cfg is not None:
                    dev = new_dev
                    break
        else:
            raise RuntimeError(
                f'Valeria: device did not re-enumerate within {timeout}s')
        logger.info('Valeria: device re-enumerated, QT config = %d', qt_cfg)

    # Set the QT config as active if it isn't already
    if not _active_config_has_qt(dev):
        logger.info('Valeria: setting active config to %d', qt_cfg)
        try:
            dev.set_configuration(qt_cfg)
        except usb.core.USBError as e:
            logger.error('Valeria: failed to set config %d: %s', qt_cfg, e)
            raise

    return dev


def _deactivate_valeria(dev: usb.core.Device) -> None:
    """Send control transfer to deactivate Valeria."""
    try:
        dev.ctrl_transfer(0x40, 0x52, 0x00, 0x00, b'')
    except usb.core.USBError:
        pass


def _find_qt_interface(dev: usb.core.Device):
    """Find and return the QuickTime (SubClass 0x2A) interface."""
    cfg = dev.get_active_configuration()
    for intf in cfg:
        if intf.bInterfaceClass == 0xFF and intf.bInterfaceSubClass == QUICKTIME_SUBCLASS:
            return intf
    return None


def _find_endpoints(intf) -> tuple:
    """Find bulk IN and OUT endpoints on the QT interface."""
    ep_in = ep_out = None
    for ep in intf:
        if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
            ep_in = ep
        else:
            ep_out = ep
    return ep_in, ep_out


# ---------------------------------------------------------------------------
# Protocol handler (runs in a background thread)
# ---------------------------------------------------------------------------


class _ValeraProtocol:
    """Handles the Valeria USB protocol: reads messages, sends replies,
    and pushes decoded video frames to a queue."""

    def __init__(self, ep_in, ep_out, frame_queue: queue.Queue, stop_event: threading.Event):
        self._ep_in = ep_in
        self._ep_out = ep_out
        self._frame_queue = frame_queue
        self._stop = stop_event

        # USB read buffer
        self._buf = bytearray()
        self._read_size = max(ep_in.wMaxPacketSize, 16384)

        # Protocol state
        self._clock: Optional[CMClock] = None
        self._local_audio_clock: Optional[CMClock] = None
        self._device_audio_clock_ref: int = 0
        self._need_clock_ref: int = 0
        self._need_message: bytes = b''
        self._release_count = 0
        self._video_frames = 0

        # SPS/PPS carried across frames (only present on keyframes).
        # We restamp every outgoing H264Frame so consumers can re-init their
        # decoder on the next keyframe boundary.
        self._sps: bytes = b''
        self._pps: bytes = b''

        # Skew tracking
        self._first_audio = False
        self._start_device_audio_time: Optional[CMTime] = None
        self._start_local_audio_time: Optional[CMTime] = None
        self._last_device_audio_time: Optional[CMTime] = None
        self._last_local_audio_time: Optional[CMTime] = None

        # Video dimensions
        self.width: int = 0
        self.height: int = 0

    def _write(self, data: bytes) -> None:
        try:
            self._ep_out.write(data)
        except usb.core.USBError as e:
            logger.error('Valeria: USB write error: %s', e)

    def run(self) -> None:
        """Main protocol loop — read messages and dispatch."""
        logger.info('Valeria: protocol handler started')
        try:
            while not self._stop.is_set():
                try:
                    data = self._read_message()
                except usb.core.USBError as e:
                    if e.errno == 110 or 'timeout' in str(e).lower():
                        continue
                    logger.error('Valeria: USB read error: %s', e)
                    break
                if data is None:
                    continue
                self._dispatch(data)
        except Exception as e:
            logger.error('Valeria: protocol error: %s', e)
        finally:
            logger.info('Valeria: protocol handler stopped')

    def _ensure_buf(self, needed: int) -> bool:
        """Read from USB until the buffer has at least *needed* bytes."""
        while len(self._buf) < needed:
            try:
                chunk = self._ep_in.read(self._read_size, timeout=1000)
            except usb.core.USBError as e:
                if e.errno == 110 or 'timeout' in str(e).lower():
                    if len(self._buf) == 0:
                        return False
                    continue  # retry for partial message
                raise
            if chunk:
                self._buf.extend(chunk)
        return True

    def _read_message(self) -> Optional[bytes]:
        """Read a length-prefixed message from the USB bulk endpoint.

        Uses an internal buffer to handle USB bulk packet boundaries.
        """
        if not self._ensure_buf(4):
            return None
        length = _u32(bytes(self._buf[:4]))  # length includes itself
        if length < 4 or length > 10 * 1024 * 1024:
            # Corrupted — discard and resync
            self._buf.clear()
            return None
        if not self._ensure_buf(length):
            return None
        # Extract the payload (skip 4-byte length header)
        msg = bytes(self._buf[4:length])
        del self._buf[:length]
        return msg

    def _dispatch(self, data: bytes) -> None:
        """Route a message to the appropriate handler."""
        if len(data) < 4:
            return
        magic = _u32(data)
        if magic == PING:
            logger.debug('Valeria: PING')
            self._write(_ping_packet())
        elif magic == SYNC:
            self._handle_sync(data)
        elif magic == ASYN:
            self._handle_async(data)
        else:
            logger.warning('Valeria: unknown packet magic: 0x%08x', magic)

    # -- SYNC handlers -------------------------------------------------------

    def _handle_sync(self, data: bytes) -> None:
        if len(data) < 16:
            return
        clock_ref = _u64(data, 4)
        subtype = _u32(data, 12)
        # correlation ID is at offset 16 for SYNC packets (after 16-byte header)
        corr_id = _u64(data, 16) if len(data) >= 24 else 0

        if subtype == OG:
            logger.debug('Valeria: SYNC OG (corr=%x)', corr_id)
            self._write(_og_reply(corr_id))

        elif subtype == CWPA:
            # Audio clock setup
            device_clock_ref = _u64(data, 24) if len(data) >= 32 else 0
            logger.debug('Valeria: SYNC CWPA (corr=%x, dev_clock=%x)', corr_id, device_clock_ref)
            local_clock_ref = device_clock_ref + 1000
            self._local_audio_clock = CMClock(local_clock_ref)
            self._device_audio_clock_ref = device_clock_ref

            # Send HPD1 twice (video format request), then HPA1
            hpd1 = _hpd1_packet()
            logger.debug('Valeria: sending HPD1 ×2')
            self._write(hpd1)
            self._write(hpd1)

            # Reply to CWPA
            self._write(_clock_ref_reply(corr_id, local_clock_ref))

            # Send HPA1 (audio format request)
            hpa1 = _hpa1_packet(device_clock_ref)
            logger.debug('Valeria: sending HPA1')
            self._write(hpa1)

        elif subtype == CVRP:
            # Video clock setup
            device_clock_ref = _u64(data, 24) if len(data) >= 32 else 0
            logger.debug('Valeria: SYNC CVRP (corr=%x, dev_clock=%x)', corr_id, device_clock_ref)

            self._need_clock_ref = device_clock_ref
            self._need_message = _asyn_need(device_clock_ref)
            logger.debug('Valeria: sending NEED')
            self._write(self._need_message)

            reply_clock_ref = device_clock_ref + 0x1000AF
            self._write(_clock_ref_reply(corr_id, reply_clock_ref))

        elif subtype == CLOK:
            logger.debug('Valeria: SYNC CLOK (corr=%x, clock_ref=%x)', corr_id, clock_ref)
            new_clock_ref = clock_ref + 0x10000
            self._clock = CMClock(new_clock_ref)
            self._write(_clock_ref_reply(corr_id, new_clock_ref))

        elif subtype == TIME:
            logger.debug('Valeria: SYNC TIME (corr=%x)', corr_id)
            if self._clock:
                t = self._clock.get_time()
                self._write(_time_reply(corr_id, t))

        elif subtype == AFMT:
            logger.debug('Valeria: SYNC AFMT (corr=%x)', corr_id)
            self._write(_afmt_reply(corr_id))

        elif subtype == SKEW:
            logger.debug('Valeria: SYNC SKEW (corr=%x)', corr_id)
            skew = self._calculate_skew()
            self._write(_skew_reply(corr_id, skew))

        elif subtype == STOP:
            logger.debug('Valeria: SYNC STOP (corr=%x)', corr_id)
            self._write(_stop_reply(corr_id))

        else:
            logger.warning('Valeria: unknown SYNC subtype: 0x%08x', subtype)

    # -- ASYNC handlers ------------------------------------------------------

    def _handle_async(self, data: bytes) -> None:
        if len(data) < 16:
            return
        subtype = _u32(data, 12)

        if subtype == FEED:
            self._handle_feed(data)
        elif subtype == EAT:
            self._handle_eat(data)
        elif subtype == RELS:
            logger.debug('Valeria: ASYNC RELS')
            self._release_count += 1
        elif subtype in (SPRP, TJMP, SRAT, TBAS):
            logger.debug('Valeria: ASYNC %s', {SPRP: 'SPRP', TJMP: 'TJMP',
                         SRAT: 'SRAT', TBAS: 'TBAS'}[subtype])
        else:
            logger.warning('Valeria: unknown ASYNC subtype: 0x%08x', subtype)

    def _handle_feed(self, data: bytes) -> None:
        """Parse a FEED packet and push the decoded frame."""
        frame = _parse_feed_sbuf(data[16:])
        if frame is None:
            self._write(self._need_message)
            return

        self._video_frames += 1

        if frame.width and frame.height:
            self.width = frame.width
            self.height = frame.height

        # Track SPS/PPS for decoder initialization
        if frame.sps:
            self._sps = frame.sps
        if frame.pps:
            self._pps = frame.pps

        # Forward the H264Frame to consumers. Drop-oldest on full queue
        # (live-mirror semantics: a stuck consumer must not backpressure
        # the iPad).
        try:
            self._frame_queue.put_nowait(frame)
        except queue.Full:
            try:
                self._frame_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._frame_queue.put_nowait(frame)
            except queue.Full:
                pass

        if self._video_frames % 100 == 0:
            logger.debug('Valeria: %d video frames received', self._video_frames)

        # Request next frame
        self._write(self._need_message)

    def _handle_eat(self, data: bytes) -> None:
        """Handle audio sample (EAT!) — we only track timing for skew."""
        try:
            ct = CMTime.from_bytes(data, 24)  # rough offset to opts CMTime
        except Exception:
            return
        if not self._first_audio:
            self._start_device_audio_time = ct
            self._start_local_audio_time = self._local_audio_clock.get_time() if self._local_audio_clock else ct
            self._last_device_audio_time = ct
            self._last_local_audio_time = self._start_local_audio_time
            self._first_audio = True
        else:
            self._last_device_audio_time = ct
            if self._local_audio_clock:
                self._last_local_audio_time = self._local_audio_clock.get_time()

    def _calculate_skew(self) -> float:
        if (self._start_local_audio_time is None or self._last_local_audio_time is None or
                self._start_device_audio_time is None or self._last_device_audio_time is None):
            return 1.0
        t1s = self._start_local_audio_time
        t1e = self._last_local_audio_time
        t2s = self._start_device_audio_time
        t2e = self._last_device_audio_time
        diff1 = t1e.value - t1s.value
        diff2 = t2e.value - t2s.value
        if diff2 == 0:
            return 1.0
        scaling = t2s.scale / t1s.scale if t1s.scale else 1.0
        scaled = diff1 * scaling
        return t2s.scale * scaled / diff2

    def close_session(self) -> None:
        """Send stop messages and wait for RELS."""
        logger.info('Valeria: closing session…')
        self._release_count = 0
        if self._device_audio_clock_ref:
            self._write(_asyn_hpa0(self._device_audio_clock_ref))
        self._write(_asyn_hpd0())
        # Wait for 2 RELS messages
        deadline = time.monotonic() + 3.0
        while self._release_count < 2 and time.monotonic() < deadline:
            try:
                data = self._read_message()
                if data:
                    self._dispatch(data)
            except Exception:
                break
        self._write(_asyn_hpd0())
        logger.info('Valeria: session closed')


# ---------------------------------------------------------------------------
# Public capture class
# ---------------------------------------------------------------------------


class ValeriaLibusb(IOSScreenCapture):
    """Capture iOS screen via the Valeria USB protocol on Linux/Windows.

    On macOS, libusb cannot claim Apple USB interfaces (DriverKit on macOS 15+),
    so :meth:`start` raises :class:`BackendUnavailableError`. Use
    :class:`pymobiledevice3.services.valeria_cmio.ValeriaCMIO` on macOS.

    Yields :class:`H264Frame` objects from the iPad's QuickTime alt-config.
    """

    def __init__(self, udid: Optional[str] = None) -> None:
        self._udid = udid
        self._queue: queue.Queue[H264Frame] = queue.Queue(maxsize=2)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._protocol: Optional[_ValeraProtocol] = None
        self._device: Optional[usb.core.Device] = None
        self._running = False
        self._width: int = 0
        self._height: int = 0
        self._device_name: str = ''

    @property
    def width(self) -> int:
        return self._width or (self._protocol.width if self._protocol else 0)

    @property
    def height(self) -> int:
        return self._height or (self._protocol.height if self._protocol else 0)

    @property
    def device_name(self) -> str:
        return self._device_name

    def start(self) -> None:
        if _MACOS:
            raise BackendUnavailableError(
                'valeria_libusb cannot run on macOS — libusb cannot claim '
                'Apple USB interfaces on macOS 15+. Use ValeriaCMIO instead.'
            )

        dev = _find_apple_device(self._udid)
        if dev is None:
            raise DeviceNotFoundError(
                'No Apple device found'
                + (f' with UDID {self._udid}' if self._udid else '')
            )

        try:
            self._device_name = dev.product or 'iOS device'
        except Exception:
            self._device_name = 'iOS device'
        logger.info('Valeria: found %s (serial: %s)', self._device_name,
                    (dev.serial_number or '???')[:8])

        try:
            dev = _activate_valeria(dev)
        except Exception as e:
            raise RuntimeError(f'Valeria activation failed: {e}') from e

        self._device = dev

        intf = _find_qt_interface(dev)
        if intf is None:
            raise RuntimeError('Valeria: no QuickTime interface found')

        try:
            if dev.is_kernel_driver_active(intf.bInterfaceNumber):
                dev.detach_kernel_driver(intf.bInterfaceNumber)
        except (usb.core.USBError, NotImplementedError):
            pass

        usb.util.claim_interface(dev, intf)

        ep_in, ep_out = _find_endpoints(intf)
        if ep_in is None or ep_out is None:
            raise RuntimeError('Valeria: bulk endpoints not found')

        try:
            dev.ctrl_transfer(0x02, 0x01, 0, ep_in.bEndpointAddress, b'')
            dev.ctrl_transfer(0x02, 0x01, 0, ep_out.bEndpointAddress, b'')
        except usb.core.USBError:
            pass

        logger.info('Valeria: USB endpoints ready, starting protocol handler…')

        self._protocol = _ValeraProtocol(
            ep_in, ep_out, self._queue, self._stop_event,
        )
        self._thread = threading.Thread(target=self._protocol.run, daemon=True,
                                        name='valeria-libusb')
        self._thread.start()
        self._running = True

        # Wait briefly for first frame / dimensions
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self._protocol.width:
                self._width = self._protocol.width
                self._height = self._protocol.height
                break
            time.sleep(0.1)

        logger.info('Valeria: capture started (%dx%d)', self._width, self._height)

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        if self._protocol:
            self._protocol.close_session()
        self._stop_event.set()

        if self._thread:
            self._thread.join(timeout=5.0)

        if self._device:
            _deactivate_valeria(self._device)

        logger.info('Valeria: capture stopped')

    def frames(self) -> Iterator[H264Frame]:
        while self._running or not self._queue.empty():
            try:
                yield self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

    async def aframes(self) -> AsyncIterator[H264Frame]:
        loop = asyncio.get_event_loop()
        while self._running or not self._queue.empty():
            try:
                yield await loop.run_in_executor(
                    None, lambda: self._queue.get(timeout=0.5),
                )
            except queue.Empty:
                continue
