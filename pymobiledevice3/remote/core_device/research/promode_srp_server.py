"""pmd3 Pro Mode server through SRP — the make-or-break ccsrp interop test.

Drives a LIVE local Screen Sharing.app (open vnc://user:user@localhost:5988):
version -> sectypes -> RSA1 (decrypt username) -> SRP (send N,g,salt,B,iters,opts;
receive A+M1; compute expected M1 under several RFC5054/ccsrp variants and report
which one matches the client's M1). A match = srptools-free, our own SRP-6a
interoperates with Apple corecrypto ccsrp; then we send M2 and see if auth completes.
"""
import asyncio, binascii, hashlib, os, secrets, struct, tempfile, time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from srptools.constants import PRIME_4096, PRIME_4096_GEN

HOST, PORT = "0.0.0.0", 5988
LOG = os.path.join(tempfile.gettempdir(), "promode_srp_server.log")
N = int(PRIME_4096, 16)
g = int(PRIME_4096_GEN)          # 5
NBYTES = 512
PASSWORD = b"user"               # matches vnc://user:user@
ITERS = 50000
OPTIONS = b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2"

MODES = ["classic", "classic_nouser", "plain", "sha512pw"]
_state = {"i": 0}

_t0 = None
def log(m):
    global _t0
    now = time.time(); _t0 = _t0 or now
    line = f"[{now-_t0:7.3f}] {m}"
    open(LOG, "a").write(line + "\n"); print(line, flush=True)
def dump(tag, b):
    log(f"{tag} {len(b)}B  {binascii.hexlify(b[:48]).decode()}{'...' if len(b)>48 else ''}")

def H(*parts):
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()
def PAD(x):
    b = x if isinstance(x, bytes) else x.to_bytes((x.bit_length()+7)//8 or 1, "big")
    return b.rjust(NBYTES, b"\x00")
def mpi(x):     # %m  u16 len + bignum (unpadded, minimal)
    b = x.to_bytes((x.bit_length()+7)//8 or 1, "big")
    return struct.pack(">H", len(b)) + b
def mpi_fixed(x):  # server sends B as fixed 512
    return struct.pack(">H", NBYTES) + PAD(x)

_HK = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_SPKI = _HK.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

async def rd(r, n, lbl):
    try:
        return await asyncio.wait_for(r.readexactly(n), timeout=20)
    except Exception as e:
        log(f"read {lbl} failed: {e}"); return b""

def build_srp_server_msg(salt, B):
    fields = bytearray()
    fields += struct.pack(">H", 2)        # count
    fields += b"\x00"                      # flag
    fields += PAD(N)                       # N raw 512 (fixed group)
    fields += mpi(g)                       # g = %m
    fields += struct.pack("B", len(salt)) + salt          # salt = %o
    fields += mpi_fixed(B)                 # B = %m fixed 512
    fields += struct.pack(">Q", ITERS)     # iters = %q
    fields += struct.pack(">H", len(OPTIONS)) + OPTIONS   # opts = %s
    C = len(fields)
    body = struct.pack(">I", 2) + struct.pack(">H", C+4) + struct.pack(">I", C) + fields
    return struct.pack(">I", len(body)) + body

# --- x (private key from password) derivation hypotheses -------------------
def derive_x(mode, salt):
    pw = PASSWORD
    if mode == "classic":               # ccsrp_generate_x: x = H(salt | H("user:pass"))
        return int.from_bytes(H(salt, H(b"user:" + pw)), "big")
    if mode == "classic_nouser":        # x = H(salt | H(":pass"))
        return int.from_bytes(H(salt, H(b":" + pw)), "big")
    if mode == "plain":                 # x = PBKDF2(pw)
        return int.from_bytes(hashlib.pbkdf2_hmac("sha512", pw, salt, ITERS), "big")
    if mode == "sha512pw":              # x = PBKDF2(SHA512(pw))  (Apple GSA style)
        return int.from_bytes(hashlib.pbkdf2_hmac("sha512", hashlib.sha512(pw).digest(), salt, ITERS), "big")
    if mode == "std_pbkdf2":            # x = H(salt | PBKDF2(pw))
        p = hashlib.pbkdf2_hmac("sha512", pw, salt, ITERS)
        return int.from_bytes(H(salt, p), "big")
    if mode == "std_userpass":          # x = H(salt | H(user:pass_pbkdf2))
        p = hashlib.pbkdf2_hmac("sha512", pw, salt, ITERS)
        return int.from_bytes(H(salt, H(b"user:" + p)), "big")
    raise ValueError(mode)

def make_B(mode, salt, b_priv):
    x = derive_x(mode, salt)
    v = pow(g, x, N)
    k = int.from_bytes(H(PAD(N), PAD(g)), "big")
    B = (k * v + pow(g, b_priv, N)) % N
    return v, B

def compute_and_match(mode, salt, b_priv, v, B, A_int, M1_client):
    u = int.from_bytes(H(PAD(A_int), PAD(B)), "big")
    S = pow(A_int * pow(v, u, N), b_priv, N)
    Hn, Hg = H(PAD(N)), H(PAD(g))
    xor = bytes(p ^ q for p, q in zip(Hn, Hg))
    K = H(PAD(S))
    A_w, B_w = PAD(A_int), PAD(B)
    HIs = {"H(user)": H(b"user"), "H('')": H(b""), "user_raw": H(b"\x00\x00\x00\x04user")}
    formulas = {
        "xor,HI,s,A,B,K":  lambda HI: H(xor, HI, salt, A_w, B_w, K),
        "xor,HI,s,A,B,S":  lambda HI: H(xor, HI, salt, A_w, B_w, PAD(S)),
        "xor,HI,s,A,B,noK":lambda HI: H(xor, HI, salt, A_w, B_w),
        "A,B,K":           lambda HI: H(A_w, B_w, K),
        "A,B,S":           lambda HI: H(A_w, B_w, PAD(S)),
    }
    log(f"[{mode}] S bits={S.bit_length()} M1_client={binascii.hexlify(M1_client).decode()[:32]}..")
    for fn_name, fn in formulas.items():
        for hin, HI in HIs.items():
            if fn(HI) == M1_client:
                tag = f"mode={mode} formula={fn_name} HI={hin}"
                log(f"*** MATCH  {tag}")
                return (K, A_w, S, tag)
    return None

async def handle(r, w):
    log(f"=== client {w.get_extra_info('peername')} ===")
    w.write(b"RFB 003.889\n"); await w.drain()
    if not await rd(r, 12, "version"): w.close(); return
    w.write(bytes([4, 30, 33, 36, 35])); await w.drain()
    sel = await rd(r, 1, "sel"); log(f"sel type = {sel[0] if sel else '?'}")
    ln = await rd(r, 4, "submsg len");  (pl,) = struct.unpack(">I", ln) if len(ln)==4 else (0,)
    await rd(r, pl, "submsg")
    # RSA1 host key
    body = struct.pack(">H", 1) + struct.pack(">I", len(_SPKI)) + _SPKI
    w.write(struct.pack(">I", len(body)) + body); await w.drain()
    ln = await rd(r, 4, "rsa blob len"); (bl,) = struct.unpack(">I", ln) if len(ln)==4 else (0,)
    blob = await rd(r, bl, "rsa blob")
    idx = blob.find(b"RSA1")
    ct = blob[idx+8: idx+8+256] if idx >= 0 else blob[-256:]
    try:
        user = _HK.decrypt(ct, padding.PKCS1v15())
        log(f"RSA1 username plaintext: {user!r}")
    except Exception as e:
        log(f"rsa decrypt failed: {e}")
    # SRP: choose salt + ephemeral b, compute B (per this connection's x-mode), send.
    mode = MODES[_state["i"] % len(MODES)]; _state["i"] += 1
    salt = secrets.token_bytes(32)
    b_priv = int.from_bytes(secrets.token_bytes(32), "big")
    v, B = make_B(mode, salt, b_priv)
    msg = build_srp_server_msg(salt, B)
    w.write(msg); await w.drain()
    log(f"[mode={mode}] sent SRP server msg {len(msg)}B (salt {salt.hex()[:16]}.., B bits {B.bit_length()})")
    # receive client reply: [u32 payload][u16 0100][RSA1][u16 step][u16][u32][u16 Alen][A][u8 M1len][M1][u16 optlen][opts]...
    ln = await rd(r, 4, "cli len");
    if len(ln) != 4: w.close(); return
    (clen,) = struct.unpack(">I", ln)
    cli = ln + await rd(r, clen, "cli body")
    dump("C->S SRP reply", cli)
    oi = cli.find(b"mda=")
    if oi < 0:
        log("no opts in client reply — parsing differently");
    # opts preceded by [u16 optlen]; M1 = %o (u8 len + 64) right before that
    optlen_off = oi - 2
    m1_end = optlen_off
    m1_len = cli[m1_end - 65]           # the u8 length byte for M1
    M1 = cli[m1_end - 64: m1_end]
    # A = %m fixed: [u16 512][512] ending right before the M1 length byte
    a_end = m1_end - 65
    A = cli[a_end - 512: a_end]
    A_int = int.from_bytes(A, "big")
    log(f"parsed: A bits={A_int.bit_length()} (len {len(A)}), M1 len byte={m1_len}, M1={M1.hex()[:24]}..")
    match = compute_and_match(mode, salt, b_priv, v, B, A_int, M1)
    if match:
        K, Ab, S, tag = match
        M2 = H(Ab, M1, K)
        # frame M2 like the captured S->C 102B: [u32 len][u32 step=2][u16 5c][u32 58]<88B>? -> M2 is 64B
        m2body = struct.pack(">I", 2) + struct.pack(">H", len(M2)+2) + struct.pack("B", len(M2)) + M2
        w.write(struct.pack(">I", len(m2body)) + m2body); await w.drain()
        log(f"sent M2 ({tag}); watching client reaction")
        try:
            more = await asyncio.wait_for(r.read(512), timeout=6)
            dump("C->S after M2", more)
            log("=== client CONTINUED past M2 — SRP AUTH OK ===" if more else "=== client closed after M2 ===")
        except Exception as e:
            log(f"post-M2: {e}")
    else:
        log("=== NO M1 VARIANT MATCHED — need exact ccsrp convention ===")
    w.close()

async def main():
    open(LOG, "w").close()
    srv = await asyncio.start_server(handle, HOST, PORT)
    log(f"SRP test server on {HOST}:{PORT}")
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
