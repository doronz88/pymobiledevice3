"""Experimental pmd3-side Pro Mode SERVER, built stage-by-stage and validated against
a live local Screen Sharing.app client (open vnc://user:user@localhost:5988).

Goal of THIS iteration: replay the server side of the captured handshake far enough
to (a) confirm the real client selects RSA1 against our version+sectype list, and
(b) capture the client's RSA1-encrypted blob so we learn its exact semantics.

We generate our own 2048-bit RSA host key so we can later decrypt whatever the client
sends under it. Everything the client sends is logged (hex + ascii).
"""
import asyncio
import binascii
import os
import struct
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

HOST, PORT = "0.0.0.0", 5988
LOG = os.path.join(tempfile.gettempdir(), os.path.basename(__file__).replace(".py", ".log"))

RFB_VERSION = b"RFB 003.889\n"
SECURITY_TYPES = bytes([30, 33, 36, 35])   # wire: 04 1e 21 24 23

_t0 = None


def log(msg: str) -> None:
    global _t0
    now = time.time()
    if _t0 is None:
        _t0 = now
    line = f"[{now - _t0:7.3f}] {msg}"
    with open(LOG, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def dump(tag: str, data: bytes) -> None:
    h = binascii.hexlify(data).decode()
    pr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    log(f"{tag} {len(data)}B")
    for i in range(0, len(h), 64):
        off = i // 2
        log(f"    {off:04x}: {h[i:i+64]:<64}  {pr[off:off+32]}")


# One RSA host key for the process (2048-bit, e=65537, like the real server).
_HOSTKEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_SPKI_DER = _HOSTKEY.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


async def read_exactly(r, n, label):
    try:
        return await asyncio.wait_for(r.readexactly(n), timeout=15)
    except Exception as e:
        log(f"read {label} failed: {e}")
        return b""


async def handle(r, w):
    peer = w.get_extra_info("peername")
    log(f"=== client {peer} ===")
    # 1) Version
    w.write(RFB_VERSION); await w.drain(); log(f"S->C version {RFB_VERSION!r}")
    ver = await read_exactly(r, 12, "version")
    log(f"C->S version {ver!r}")
    if not ver:
        w.close(); return
    # 2) Security type list (count byte + types)
    sec = bytes([len(SECURITY_TYPES)]) + SECURITY_TYPES
    w.write(sec); await w.drain(); dump("S->C sectypes", sec)
    # 3) Client selects a type (1 byte) then a sub-message. Read the selection byte,
    #    then read the RSA1 sub-message [u32 len][payload].
    sel = await read_exactly(r, 1, "sel")
    log(f"C->S selected security type = {sel[0] if sel else '?'}")
    if not sel:
        w.close(); return
    ln = await read_exactly(r, 4, "submsg len")
    if len(ln) == 4:
        (plen,) = struct.unpack(">I", ln)
        log(f"C->S submsg payload len = {plen}")
        payload = await read_exactly(r, plen, "submsg payload")
        dump("C->S submsg", ln + payload)
    # 4) RSA1 host-key step: send [u32 total][u16 0x0001][u32 derlen][DER SPKI]
    body = struct.pack(">H", 1) + struct.pack(">I", len(_SPKI_DER)) + _SPKI_DER
    msg = struct.pack(">I", len(body)) + body
    w.write(msg); await w.drain()
    dump("S->C rsa hostkey (first 48B)", msg[:48])
    log(f"(sent RSA host key, total {len(msg)}B)")
    # 5) Capture whatever the client sends next (its RSA1-encrypted blob).
    ln2 = await read_exactly(r, 4, "client blob len")
    if len(ln2) == 4:
        (blen,) = struct.unpack(">I", ln2)
        log(f"C->S next msg len = {blen}")
        blob = await read_exactly(r, min(blen, 4096), "client blob")
        dump("C->S post-hostkey", ln2 + blob)
        # Try to decrypt the 256-byte RSA ciphertext region under our host key.
        _try_decrypt(blob)
    # Log any remaining bytes briefly.
    try:
        rest = await asyncio.wait_for(r.read(2048), timeout=4)
        if rest:
            dump("C->S trailing", rest)
    except Exception:
        pass
    log("=== done; closing ===")
    w.close()


def _try_decrypt(blob: bytes) -> None:
    """The captured client blob had layout [u16 0x0100]['RSA1'][u16 step][u16 0x0100]
    <256B ct>. Find a 256-byte window and try OAEP / PKCS1v15 under our host key."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    idx = blob.find(b"RSA1")
    ct = None
    if idx >= 0 and len(blob) >= idx + 4 + 4 + 256:
        ct = blob[idx + 8: idx + 8 + 256]
    if ct is None and len(blob) >= 256:
        ct = blob[-256:]
    if ct is None:
        log("decrypt: no 256B ciphertext window found"); return
    for name, pad in [
        ("OAEP-SHA256", padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)),
        ("OAEP-SHA1", padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)),
        ("PKCS1v15", padding.PKCS1v15()),
    ]:
        try:
            pt = _HOSTKEY.decrypt(ct, pad)
            log(f"decrypt OK via {name}: {len(pt)}B {binascii.hexlify(pt).decode()}")
            log(f"   ascii: {''.join(chr(b) if 32<=b<127 else '.' for b in pt)}")
            return
        except Exception as e:
            log(f"decrypt {name} failed: {type(e).__name__}")


async def main():
    open(LOG, "w").close()
    srv = await asyncio.start_server(handle, HOST, PORT)
    log(f"pmd3 experimental Pro Mode server on {HOST}:{PORT}")
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
