# DTX Protocol Internals

Reference documentation for developers working on the DTX implementation
itself.  For usage documentation see `README.md`.

> **Acknowledgement** — wire-format details were verified against
> [frida-core's `dtx.vala`](https://github.com/frida/frida-core/blob/main/src/fruity/dtx.vala)
> (wxWindows Library Licence v3.1 / LGPL v2+, © Frida contributors).
> No source code was copied; the reference was used for protocol verification only.

---

## Wire format overview

Every DTX exchange consists of one or more **fragments** sent over a
reliable byte stream (TCP socket).  Each fragment has:

1. A fixed-size **fragment header** (≥ 32 bytes)
2. Zero or one **payload body** bytes

---

## Fragment header layout

```
Offset  Size  Type      Field              Notes
------  ----  --------  -----------------  --------------------------------
 0       4    u32le     magic              0x1F3D5B79
 4       4    u32le     cb                 total header byte length (≥ 32)
 8       2    u16le     index              0-based fragment index
10       2    u16le     count              total fragment count for message
12       4    u32le     data_size          body byte count (or total assembled
                                           size for index==0 of multi-fragment)
16       4    u32le     identifier         message id (correlated in replies)
20       4    u32le     conversation_index 0=initiator, 1=reply, …
24       4    i32le     channel_code       signed; server-sent use negative
28       4    u32le     flags              DTXTransportFlags bitmask
```

If `cb > 32` the extra `cb - 32` bytes are trailing header extensions and
must be consumed (skipped) before reading the body.

---

## Payload header layout

The first 16 bytes of every assembled message body are the **payload header**:

```
Offset  Size  Type      Field       Notes
------  ----  --------  ----------  --------------------------------
 0       1    u8        msg_type    DTXMessageType value
 1       1    u8        flags_a     reserved
 2       1    u8        flags_b     reserved
 3       1    u8        reserved    must be zero
 4       4    u32le     aux_size    byte count of aux dictionary
 8       8    u64le     total_size  aux_size + payload_size
```

Bytes `[16 .. 16+aux_size)` are the aux dictionary.
Bytes `[16+aux_size .. 16+total_size)` are the payload.

---

## Fragment reassembly algorithm

Single-fragment messages (`count == 1`):

```
read fragment header + body → process immediately
```

Multi-fragment messages (`count > 1`):

```
fragment index == 0:
    data_size = total assembled size (no body in stream)
    allocate bytearray(data_size) → DTXFragmenter

fragment index > 0:
    write payload into pre-allocated buffer at current write offset
    record slot (index, offset, length)
    when all count-1 body fragments received:
        if slots arrived in index order → return buffer as-is (zero copy)
        else sort slots, copy in order into a new bytearray
```

Memory limits enforced before any allocation:

- `MAX_BUFFERED_COUNT = 100` — max concurrent in-flight messages
- `MAX_BUFFERED_SIZE  = 30 MiB` — total buffered bytes
- `MAX_MESSAGE_SIZE   = 128 MiB` — single message ceiling
- `MAX_FRAGMENT_SIZE  = 128 KiB` — single fragment body ceiling

---

## Channel lifecycle

### Channel 0 — control handshake

Immediately after the transport is established both sides send
`_notifyOfPublishedCapabilities:` with a capabilities dictionary.  The
`DTXConnection.connect()` method:

1. Creates a `DTXChannel(0, "ctrl", …)` and a `DTXControlService` on it.
2. Sends `_notifyOfPublishedCapabilities:` with
   `{"com.apple.private.DTXBlockCompression": 0, "com.apple.private.DTXConnection": 1}`.
3. Awaits `_handshake_done` — resolved when the peer's capabilities arrive.

### `open_channel` flow

```
client                              server
  │                                   │
  │─ _requestChannelWithCode:id: ────►│
  │◄─ OK ─────────────────────────────│
  │                                   │
  │  (channel is now open on both)    │
```

`channel_code` is a positive integer assigned locally; the server maps the
same code to the service it starts on its side.

### `cancel_channel` flow

```
client                              server
  │                                   │
  │─ _channelCanceled: ──────────────►│
  │◄─ OK ─────────────────────────────│
```

The channel is removed from both sides' registries.

---

## Channel-code sign correction

The frida-core reference (`dtx.vala`, `process_message`) applies a sign flip
on the receive path:

```python
if fragment.conversation_index % 2 == 0:
    channel_code = -channel_code
```

Server-initiated dispatches arrive with an even `conversation_index` and a
**negative** `channel_code` on the wire; negating recovers the positive
locally-registered code.  Reply messages (odd `conversation_index`) keep the
code as-is.

The send path mirrors this symmetrically (`_sender.py`, `_send_message`):

```python
wire_code = channel_code if conversation_index % 2 == 0 else -channel_code
```

When **sending a reply** (odd `conversation_index`), the local `channel_code`
is the negative of the remote-opened channel (e.g. `-1`), so negating it
produces the positive wire code (`+1`) that the remote peer can look up in
its own channel registry.  When sending a host-initiated dispatch
(even `conversation_index`), the local code is already positive and should
remain positive on the wire.

Example: remote opens channel `1` → locally stored as `-1`.  Reply built
with `channel_code=-1, conversation_index=1`:
`wire_code = -(-1) = +1` ✓  The remote receives `+1` and finds its channel.

---

## Primitive type wire encoding

Each value in the aux dictionary is prefixed by a u32 type tag:

| Tag  | Python class     | Encoding                              |
|------|------------------|---------------------------------------|
|  1   | PrimitiveString  | u32 length + UTF-8 bytes              |
|  2   | PrimitiveBuffer  | u32 length + raw bytes (or NSKArchive)|
|  3   | PrimitiveInt32   | u32le value                           |
|  6   | PrimitiveInt64   | u64le value                           |
|  9   | PrimitiveDouble  | IEEE-754 float64le                    |
| 10   | PrimitiveNull    | (no value bytes)                      |

On the **parse path**, type 2 is first tried as NSKeyedArchive; on decode
failure the raw bytes are returned as `PrimitiveBuffer`.

On the **build path**, any Python object not already a `_PrimitiveBase`
instance is NSKeyedArchive-encoded and emitted as type 2.

---

## PrimitiveDictionary format

```
Offset  Size  Type  Field
------  ----  ----  ------
 0       8    u64   magic_and_flags  low byte must be 0xF0
 8       8    u64   body_length
16      ...        [key_primitive, value_primitive] × N
```

For positional arguments every key is a NULL primitive (tag=10, no bytes);
the value holds the argument.  `_args_to_aux_bytes([a, b, c])` generates
three NULL-keyed entries.

---

## NS types and NSKeyedArchive

`bpylist2.archiver` is used for all NSKeyedArchive encode/decode.  The
`ns_types.py` module registers Python proxy classes for:

- `NSError`, `NSUUID`, `NSURL`, `NSValue`, `NSMutableData`, `NSMutableString`
- `NSNull`, `XCTCapabilities`, `XCTestConfiguration`
- All `DTTapMessage` variants

Registration happens automatically at import time via
`archiver.update_class_map(...)`.

---

## `DTXService` decorator machinery (`service.py`)

`DTXService.__init_subclass__` is called once per concrete subclass.  It
walks `vars(cls)` and for each method:

- `_dtx_on_invoke` attribute → register in `cls._dtx_dispatch` dict
- `_dtx_on_data` attribute → set `cls._dtx_data_handler`
- `_dtx_on_notification` attribute → set `cls._dtx_notification_handler`
- `_dtx_on_dispatch` attribute → set `cls._dtx_dispatch_handler`
- `_dtx_method` attribute → **replace** the method with a generated
  `async _wrapper` that calls `self._channel.invoke(selector, *args)`.

The wrapper also inspects PEP-3107 annotations (via `get_type_hints`) to
build a per-parameter coercion table; at call time `_apply_primitive_coercions`
wraps plain Python values in the annotated `_PrimitiveBase` subclass.

`DTXService.__init__` then wires the class-level routing tables to the
channel callbacks:

```python
if cls._dtx_dispatch or cls._dtx_dispatch_handler:
    channel.on_invoke = self.__on_dispatch__
if cls._dtx_data_handler:
    channel.on_data = getattr(self, cls._dtx_data_handler)
if cls._dtx_notification_handler:
    channel.on_notification = getattr(self, cls._dtx_notification_handler)
```
