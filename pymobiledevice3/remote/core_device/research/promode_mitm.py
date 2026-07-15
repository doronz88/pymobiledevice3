"""Logging TCP proxy to capture a real Mac->Mac Screen Sharing (Pro Mode) handshake.
Screen Sharing.app (real client) -> this proxy (localhost:5999) -> 192.168.50.237:5900
(real server). Both directions logged in plaintext (RFB version, security type, SRP
step1 salt+B+options are all pre-encryption). No root needed.

Drive with:  open "vnc://user:user@localhost:5999"
"""
import asyncio
import binascii
import os
import sys
import tempfile
import time

LISTEN_HOST, LISTEN_PORT = "0.0.0.0", 5999
DST_HOST, DST_PORT = "192.168.50.237", 5900
LOG = os.path.join(tempfile.gettempdir(), os.path.basename(__file__).replace(".py", ".log"))

_start = None


def log(msg: str) -> None:
    global _start
    now = time.time()
    if _start is None:
        _start = now
    line = f"[{now - _start:7.3f}] {msg}"
    with open(LOG, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def dump(tag: str, data: bytes) -> None:
    hexs = binascii.hexlify(data).decode()
    # printable ASCII rendering to spot the scheme string / usernames
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    log(f"{tag} {len(data)}B")
    for i in range(0, len(hexs), 64):
        off = i // 2
        log(f"    {off:04x}: {hexs[i:i+64]:<64}  {printable[off:off+32]}")


async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, tag: str) -> None:
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dump(tag, data)
            dst.write(data)
            await dst.drain()
    except Exception as e:
        log(f"{tag} pump error: {e}")
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle(client_r, client_w) -> None:
    peer = client_w.get_extra_info("peername")
    log(f"=== client connected: {peer} -> forwarding to {DST_HOST}:{DST_PORT} ===")
    try:
        srv_r, srv_w = await asyncio.open_connection(DST_HOST, DST_PORT)
    except Exception as e:
        log(f"cannot reach server: {e}")
        client_w.close()
        return
    await asyncio.gather(
        pump(client_r, srv_w, "C->S"),
        pump(srv_r, client_w, "S->C"),
    )
    log("=== session closed ===")


async def main() -> None:
    open(LOG, "w").close()
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    log(f"MITM proxy listening on {LISTEN_HOST}:{LISTEN_PORT} -> {DST_HOST}:{DST_PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
