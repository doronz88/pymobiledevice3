"""
RFB clipboard messages for ``serve-vnc --share-clipboard``.

Two wire formats share the Cut Text message type (``ServerCutText`` = 3, ``ClientCutText`` = 6):

* Classic (RFC 6143 7.5.6 / 7.6.4): ``padding(3) + length(u32) + text``. The text is ISO 8859-1
  by specification, so anything outside Latin-1 cannot be represented.
* Extended Clipboard (pseudo-encoding ``0xC0A1E5CE``, rfbproto "Extended Clipboard
  Pseudo-Encoding"; implemented by TigerVNC, noVNC and others): the length is sent negative, and
  the payload is ``flags(u32)`` followed by action-specific data. Text travels as UTF-8 inside a
  per-message zlib stream, CRLF line endings, NUL terminated.
"""

import struct
import zlib
from dataclasses import dataclass
from typing import Optional

ENC_EXTENDED_CLIPBOARD = -1063131698  # 0xC0A1E5CE as int32

FORMAT_TEXT = 1 << 0
_FORMAT_MASK = 0xFFFF

ACTION_CAPS = 1 << 24
ACTION_REQUEST = 1 << 25
ACTION_PEEK = 1 << 26
ACTION_NOTIFY = 1 << 27
ACTION_PROVIDE = 1 << 28

SERVER_CUT_TEXT = 3

# Ceiling applied when inflating a peer's text.
MAX_TEXT_BYTES = 4 * 1024 * 1024


@dataclass
class ExtendedMessage:
    flags: int
    text: Optional[str] = None  # set for a PROVIDE that carried text

    @property
    def action(self) -> int:
        # In a caps message the other action bits list what the sender supports.
        if self.flags & ACTION_CAPS:
            return ACTION_CAPS
        return self.flags & ~_FORMAT_MASK


def classic_server_cut_text(text: str) -> bytes:
    data = text.encode("latin-1", errors="replace")
    return struct.pack(">B3xI", SERVER_CUT_TEXT, len(data)) + data


def decode_classic_text(data: bytes) -> str:
    return data.decode("latin-1")


def _extended(flags: int, payload: bytes = b"") -> bytes:
    body = struct.pack(">I", flags) + payload
    return struct.pack(">B3xi", SERVER_CUT_TEXT, -len(body)) + body


def extended_caps() -> bytes:
    flags = ACTION_CAPS | ACTION_REQUEST | ACTION_PEEK | ACTION_NOTIFY | ACTION_PROVIDE | FORMAT_TEXT
    # One "maximum unsolicited size" per advertised format. 0 (the spec's recommendation) makes the
    # peer announce every change with a NOTIFY, which is then answered with a REQUEST.
    return _extended(flags, struct.pack(">I", 0))


def extended_notify(has_text: bool = True) -> bytes:
    return _extended(ACTION_NOTIFY | (FORMAT_TEXT if has_text else 0))


def extended_request() -> bytes:
    return _extended(ACTION_REQUEST | FORMAT_TEXT)


def extended_provide(text: str) -> bytes:
    data = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8") + b"\x00"
    return _extended(ACTION_PROVIDE | FORMAT_TEXT, zlib.compress(struct.pack(">I", len(data)) + data))


def parse_extended(body: bytes) -> ExtendedMessage:
    """Parse the payload of a Cut Text message whose length field was negative."""
    if len(body) < 4:
        raise ValueError("extended clipboard message shorter than its flags")
    (flags,) = struct.unpack(">I", body[:4])
    message = ExtendedMessage(flags)
    if message.action == ACTION_PROVIDE and flags & FORMAT_TEXT:
        inflater = zlib.decompressobj()
        raw = inflater.decompress(body[4:], MAX_TEXT_BYTES + 4)
        if len(raw) < 4:
            raise ValueError("truncated extended clipboard text")
        (length,) = struct.unpack(">I", raw[:4])
        data = raw[4 : 4 + length]
        if len(data) != length:
            raise ValueError("extended clipboard text exceeds the size limit")
        message.text = data.rstrip(b"\x00").decode("utf-8", errors="replace").replace("\r\n", "\n")
    return message
