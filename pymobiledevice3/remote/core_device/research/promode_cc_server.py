"""pmd3 Pro Mode server using Apple's OWN corecrypto ccsrp via ctypes — the decisive
SRP interop test against a live local Screen Sharing.app.

If ccsrp_server_verify_session() returns True for a connection, the real client
computed an M1 that Apple's own server code accepts against our salt/verifier/B ->
SRP interop is proven. We cycle (verifier-username, password, session-username)
combos, one per connection, to find what the client uses.

Drive: open vnc://user:user@localhost:5988  (kill Screen Sharing between attempts)
"""
import asyncio, ctypes, hashlib, os, struct, tempfile, time
from ctypes import c_void_p, c_char_p, c_size_t, c_int, c_bool, create_string_buffer
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

HOST, PORT = "0.0.0.0", 5988
LOG = os.path.join(tempfile.gettempdir(), "promode_cc_server.log")
PASSWORD = b"user"
ITERS = 19417
OPTIONS = b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2"
NBYTES = 512

# VERIFIED recipe: username "", password = PBKDF2-SHA512(pw, salt, iters, dkLen=128).
COMBOS = [(b"", "pbkdf2_128", b"")]
_state = {"i": 0}
_t0 = None
def log(m):
    global _t0; now=time.time(); _t0=_t0 or now
    line=f"[{now-_t0:7.3f}] {m}"; open(LOG,"a").write(line+"\n"); print(line,flush=True)

# --- corecrypto ccsrp via ctypes (signatures validated by self-test) ----------
L = ctypes.CDLL("/usr/lib/libSystem.dylib")
def _s(n,res,args): f=getattr(L,n); f.restype=res; f.argtypes=args; return f
ccsha512_di = _s("ccsha512_di", c_void_p, [])
gp4096      = _s("ccsrp_gp_rfc5054_4096", c_void_p, [])
ccrng       = _s("ccrng", c_void_p, [c_void_p])
ctx_init    = _s("ccsrp_ctx_init", None, [c_void_p,c_void_p,c_void_p])
gen_ver     = _s("ccsrp_generate_verifier", c_int, [c_void_p,c_char_p,c_size_t,c_void_p,c_size_t,c_void_p,c_void_p])
sv_pub      = _s("ccsrp_server_generate_public_key", c_int, [c_void_p,c_void_p,c_void_p,c_void_p])
sv_sess     = _s("ccsrp_server_compute_session", c_int, [c_void_p,c_char_p,c_size_t,c_void_p,c_void_p])
sv_verify   = _s("ccsrp_server_verify_session", c_bool, [c_void_p,c_void_p,c_void_p])
keylen_fn   = _s("ccsrp_get_session_key_length", c_size_t, [c_void_p])
_DI, _GP, _RNG = ccsha512_di(), gp4096(), ccrng(None)

_HK = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_SPKI = _HK.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

def mpi(x): b=x.to_bytes((x.bit_length()+7)//8 or 1,"big"); return struct.pack(">H",len(b))+b
def PADn(b): return b.rjust(NBYTES,b"\x00")

def build_step1(salt, B_bytes):
    f = bytearray()
    f += struct.pack(">H",2) + b"\x00"
    # N (512 raw), g=%m, salt=%o, B=%m(fixed512), iters=%q, opts=%s
    f += PADn(_N_BYTES)
    f += mpi(5)
    f += struct.pack("B",len(salt)) + salt
    f += struct.pack(">H",NBYTES) + PADn(B_bytes)
    f += struct.pack(">Q",ITERS)
    f += struct.pack(">H",len(OPTIONS)) + OPTIONS
    C=len(f); body=struct.pack(">I",2)+struct.pack(">H",C+4)+struct.pack(">I",C)+bytes(f)
    return struct.pack(">I",len(body))+body

# RFC5054/3526 4096-bit prime bytes (the group N), needed for the on-wire N field.
_N_HEX = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB"
"5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD96"
"1C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2"
"EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
"1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA"
"2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AF"
"B81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF")
_N_BYTES = bytes.fromhex(_N_HEX)

async def rd(r,n,l):
    try: return await asyncio.wait_for(r.readexactly(n),timeout=20)
    except Exception as e: log(f"read {l}: {e}"); return b""

async def handle(r,w):
    combo = COMBOS[_state["i"]%len(COMBOS)]; _state["i"]+=1
    vuser, pwkind, suser = combo
    log(f"=== conn; combo vuser={vuser!r} pw={pwkind} suser={suser!r} ===")
    w.write(b"RFB 003.889\n"); await w.drain()
    if not await rd(r,12,"ver"): w.close(); return
    w.write(bytes([4,30,33,36,35])); await w.drain()
    sel=await rd(r,1,"sel"); log(f"sel={sel[0] if sel else '?'}")
    ln=await rd(r,4,"sm"); pl=struct.unpack(">I",ln)[0] if len(ln)==4 else 0
    await rd(r,pl,"sm2")
    body=struct.pack(">H",1)+struct.pack(">I",len(_SPKI))+_SPKI
    w.write(struct.pack(">I",len(body))+body); await w.drain()
    ln=await rd(r,4,"bl"); bl=struct.unpack(">I",ln)[0] if len(ln)==4 else 0
    blob=await rd(r,bl,"blob"); idx=blob.find(b"RSA1")
    ct=blob[idx+8:idx+8+256] if idx>=0 else blob[-256:]
    try: log(f"RSA1 user={_HK.decrypt(ct,padding.PKCS1v15())!r}")
    except Exception as e: log(f"rsa dec: {e}")
    # --- SRP via corecrypto ---
    salt=os.urandom(32)
    if pwkind=="plain":              pw = PASSWORD
    elif pwkind=="pbkdf2_64":        pw = hashlib.pbkdf2_hmac("sha512",PASSWORD,salt,ITERS,64)
    elif pwkind=="pbkdf2_128":       pw = hashlib.pbkdf2_hmac("sha512",PASSWORD,salt,ITERS,128)
    elif pwkind=="pbkdf2_128_hex":   pw = hashlib.pbkdf2_hmac("sha512",PASSWORD,salt,ITERS,128).hex().encode()
    elif pwkind=="pbkdf2_128_upper": pw = hashlib.pbkdf2_hmac("sha512",PASSWORD,salt,ITERS,128).hex().upper().encode()
    elif pwkind=="sha512":           pw = hashlib.sha512(PASSWORD).digest()
    else:                            pw = PASSWORD
    S=create_string_buffer(16384); ctx_init(S,_DI,_GP)
    ver=create_string_buffer(NBYTES)
    rc=gen_ver(S,vuser,len(pw),pw,len(salt),salt,ver); log(f"gen_verifier rc={rc}")
    B=create_string_buffer(NBYTES)
    rc=sv_pub(S,_RNG,ver,B); log(f"server_pub rc={rc}")
    w.write(build_step1(salt,B.raw)); await w.drain()
    log(f"sent step1 (B nonzero={any(B.raw)})")
    ln=await rd(r,4,"cl");
    if len(ln)!=4: w.close(); return
    clen=struct.unpack(">I",ln)[0]; cli=ln+await rd(r,clen,"clbody")
    oi=cli.find(b"mda=")
    if oi<0: log("no opts; abort parse"); w.close(); return
    m1_end=oi-2; M1=cli[m1_end-64:m1_end]; A=cli[m1_end-65-512:m1_end-65]
    Aint=int.from_bytes(A,"big")
    log(f"A bits={Aint.bit_length()} M1={M1.hex()[:24]}..")
    rc=sv_sess(S,suser,len(salt),salt,A); log(f"compute_session rc={rc}")
    HAMK=create_string_buffer(64)
    ok=sv_verify(S,M1,HAMK)
    if not ok:
        log("ccsrp_server_verify_session = FALSE"); w.close(); return
    log(f"*** SRP verify TRUE; HAMK(M2)={HAMK.raw.hex()[:32]}..")
    # Send M2: header + %o(HAMK) %o(sIV 16 rand) %s(opts="") %u(session_key_length)
    klen = keylen_fn(S); sIV = os.urandom(16)
    fields = struct.pack("B",64)+HAMK.raw + struct.pack("B",16)+sIV + struct.pack(">H",0) + struct.pack(">I",klen)
    C=len(fields); m2=struct.pack(">I",2)+struct.pack(">H",C+4)+struct.pack(">I",C)+fields
    m2=struct.pack(">I",len(m2))+m2
    w.write(m2); await w.drain()
    log(f"sent M2 ({len(m2)}B, klen={klen}); watching for control-channel bytes")
    try:
        nxt = await asyncio.wait_for(r.read(4096), timeout=6)
    except asyncio.TimeoutError:
        nxt = b"__timeout__"
    if nxt == b"__timeout__":
        log("no bytes for 6s; connection still OPEN (client waiting for server's post-auth msg)")
    elif nxt == b"":
        log("client CLOSED the connection after M2 (likely rejected M2)")
    else:
        log(f"*** client sent {len(nxt)}B after M2 — AUTH COMPLETE: {nxt.hex()[:96]}")
    w.close()

async def main():
    open(LOG,"w").close()
    srv=await asyncio.start_server(handle,HOST,PORT); log(f"cc-server on :{PORT}")
    async with srv: await srv.serve_forever()

if __name__=="__main__":
    asyncio.run(main())
