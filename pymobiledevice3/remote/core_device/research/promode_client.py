"""pmd3 Pro Mode CLIENT -> connects to real server 192.168.50.237:5900, completes the
full handshake with Apple corecrypto (client side), extracts the SRP session key, and
captures the server's (encrypted) media negotiation. With a KNOWN session key + real
ciphertext we can then crack the ChaCha20 framing offline.

RFB003.889 -> sectype 33 -> RSA1(send username encrypted) -> SRP client -> M2 verify
-> SecurityResult/ClientInit/ServerInit/SetEncodings -> capture media frames.
"""
import ctypes, hashlib, os, socket, struct, sys, time, binascii
from ctypes import c_void_p, c_char_p, c_size_t, c_int, c_bool, create_string_buffer, byref
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding

HOST, PORT = "192.168.50.237", 5900
PASSWORD = b"user"
OPTIONS = b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2"
OUT = "/private/tmp/claude-501/-Users-user-dev-pymobiledevice3/251624ea-8aed-4229-9ca9-c3004ecc29e0/scratchpad/promode_client_capture.bin"

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

L = ctypes.CDLL("/usr/lib/libSystem.dylib")
def s(n,res,args): f=getattr(L,n); f.restype=res; f.argtypes=args; return f
ccsha512_di = s("ccsha512_di", c_void_p, [])
gp4096      = s("ccsrp_gp_rfc5054_4096", c_void_p, [])
ccrng       = s("ccrng", c_void_p, [c_void_p])
ctx_init    = s("ccsrp_ctx_init", None, [c_void_p,c_void_p,c_void_p])
cl_start    = s("ccsrp_client_start_authentication", c_int, [c_void_p,c_void_p,c_void_p])
cl_chal     = s("ccsrp_client_process_challenge", c_int, [c_void_p,c_char_p,c_size_t,c_void_p,c_size_t,c_void_p,c_void_p,c_void_p])
cl_verify   = s("ccsrp_client_verify_session", c_bool, [c_void_p,c_void_p])
get_key     = s("ccsrp_get_session_key", c_void_p, [c_void_p, c_void_p])
_DI,_GP,_RNG = ccsha512_di(), gp4096(), ccrng(None)

def recvn(sk,n):
    b=b""
    while len(b)<n:
        c=sk.recv(n-len(b))
        if not c: raise EOFError(f"want {n} got {len(b)}")
        b+=c
    return b

def main():
    sk=socket.create_connection((HOST,PORT),timeout=15)
    ver=recvn(sk,12); log(f"server version {ver!r}"); sk.sendall(ver)   # echo
    ntypes=recvn(sk,1)[0]; types=recvn(sk,ntypes); log(f"sectypes {list(types)}")
    assert 33 in types
    # select RSA1: [u8 33][u32 len=10][u16 0100]['RSA1'][u32 0]
    sub=struct.pack(">H",0x0100)+b"RSA1"+struct.pack(">I",0)
    sk.sendall(bytes([33])+struct.pack(">I",len(sub))+sub); log("selected 33 RSA1")
    # server RSA host key: [u32 total][u16 0001][u32 derlen][DER SPKI]
    tot=struct.unpack(">I",recvn(sk,4))[0]; body=recvn(sk,tot)
    derlen=struct.unpack(">I",body[2:6])[0]; spki=body[6:6+derlen]
    pub=load_der_public_key(spki); log(f"server RSA host key {pub.key_size} bits")
    # send username RSA-encrypted (PKCS1v15), plaintext replicates the real client's 15B
    pt=bytes.fromhex("0000000b0000000475736572000000")
    ct=pub.encrypt(pt, padding.PKCS1v15())
    blob=struct.pack(">H",0x0100)+b"RSA1"+struct.pack(">H",2)+struct.pack(">H",len(ct))+ct
    blob=blob.ljust(0x28a-4,b"\x00")   # pad like the real client (total 0x28a payload)
    sk.sendall(struct.pack(">I",len(blob))+blob); log(f"sent RSA1 username blob ({len(blob)}B)")
    # server SRP step1
    tot=struct.unpack(">I",recvn(sk,4))[0]; msg=recvn(sk,tot)
    o=4  # skip step(4) inside? msg starts after outer len. parse: step(4) u16 u32 count(2) flag(1) N(512) ...
    step=struct.unpack(">I",msg[0:4])[0]
    # locate salt(%o 32), B(%m 512), iters(%q), opts. Parse per known layout.
    p=4; p+=2; p+=4; cnt=struct.unpack(">H",msg[p:p+2])[0]; p+=2; flag=msg[p]; p+=1
    N=msg[p:p+512]; p+=512
    glen=struct.unpack(">H",msg[p:p+2])[0]; p+=2; g=msg[p:p+glen]; p+=glen
    slen=msg[p]; p+=1; salt=msg[p:p+slen]; p+=slen
    blen=struct.unpack(">H",msg[p:p+2])[0]; p+=2; B=msg[p:p+blen]; p+=blen
    iters=struct.unpack(">Q",msg[p:p+8])[0]; p+=8
    log(f"step1: g={int.from_bytes(g,'big')} saltlen={slen} Blen={blen} iters={iters}")
    # ccsrp client
    C=create_string_buffer(16384); ctx_init(C,_DI,_GP)
    A=create_string_buffer(512); cl_start(C,_RNG,A)
    pw=hashlib.pbkdf2_hmac("sha512",PASSWORD,salt,iters,128)
    M1=create_string_buffer(64)
    rc=cl_chal(C,b"",len(pw),pw,len(salt),salt,B,M1); log(f"process_challenge rc={rc}")
    # build step2: [u16 0100][RSA1][u16 2][u16 sasltot][u32 fieldslen][%m A][%o M1][%s opts][%o cIV]
    cIV=os.urandom(16)
    fields=struct.pack(">H",512)+A.raw + struct.pack("B",64)+M1.raw + struct.pack(">H",len(OPTIONS))+OPTIONS + struct.pack("B",16)+cIV
    sasl=struct.pack(">I",len(fields))+fields
    payload=struct.pack(">H",0x0100)+b"RSA1"+struct.pack(">H",2)+struct.pack(">H",len(sasl))+sasl
    sk.sendall(struct.pack(">I",len(payload))+payload); log(f"sent step2 A+M1+opts+cIV ({len(payload)}B)")
    # server M2
    tot=struct.unpack(">I",recvn(sk,4))[0]; m2=recvn(sk,tot)
    # parse M2: step(4) u16 u32 %o(HAMK) %o(sIV) %s %u  -> extract HAMK (first %o)
    q=4; q+=2; q+=4; hlen=m2[q]; q+=1; HAMK=m2[q:q+hlen]; q+=hlen
    sivlen=m2[q]; q+=1; sIV=m2[q:q+sivlen]; q+=sivlen
    ok=cl_verify(C,HAMK)
    log(f"*** client_verify_session(M2) = {ok}  (HAMK={HAMK.hex()[:24]}.. sIV={sIV.hex()})")
    if not ok:
        log("M2 verify FAILED — handshake mismatch"); return
    klen=c_size_t(); kp=get_key(C,byref(klen)); K=ctypes.string_at(kp,klen.value)
    log(f"SESSION KEY K ({klen.value}B) = {K.hex()}")
    # post-auth plaintext RFB
    log(f"SecurityResult: {recvn(sk,4).hex()}")
    sk.sendall(b"\x01")  # ClientInit shared
    # ServerInit: [u16 w][u16 h][16 pixfmt][u32 namelen][name]
    hdr=recvn(sk,4); w,h=struct.unpack(">HH",hdr); pf=recvn(sk,16); nlen=struct.unpack(">I",recvn(sk,4))[0]; name=recvn(sk,nlen)
    log(f"ServerInit {w}x{h} name={name[24:]!r}")
    _acc=bytearray()
    def drain(tag, secs=3):
        sk.settimeout(secs); buf=b""
        try:
            while len(buf)<131072:
                c=sk.recv(8192)
                if not c: break
                buf+=c
        except socket.timeout: pass
        _acc.extend(buf)
        open(OUT,"wb").write(bytes(_acc))   # incremental save survives a kill
        has44f = b"\x00\x00\x04\x4f" in bytes(_acc)
        log(f"{tag}: {len(buf)}B (acc {len(_acc)}){'  *** 0x44f SEEN ***' if has44f else ''}")
        return buf
    # Match the REAL client's exact post-ServerInit order/bytes: 0x21 config FIRST, then SetEncodings.
    msg21=bytes.fromhex("2100003e0001000000020000000600000001000000000000001a0000000500000002b0000c03900000000000400000000000000000000000000000000000000000001200000100010001000000010a000001")
    se=bytes.fromhex("0200000d000003f3000003ea0000000600000010ffffff11000004500000044cffffff210000044d00000451000004530000045500000456")
    assert len(msg21)==82 and len(se)==56
    sk.sendall(msg21); log("sent 0x21 display-config")
    sk.sendall(se); log("sent SetEncodings (exact real bytes)")
    cap=drain("after 0x21+SetEncodings (expect 0x14 + 0x44f)")
    sk.sendall(bytes.fromhex("1200000200010000")); log("sent 0x12")
    cap2=drain("after 0x12")
    fbur=struct.pack(">BBHHHH",3,0,0,0,w,h)
    sk.sendall(fbur); log("sent FramebufferUpdateRequest")
    cap3=drain("after FBUR",6)
    allcap=cap+cap2+cap3
    open(OUT,"wb").write(allcap)
    open(OUT+".key","wb").write(K); open(OUT+".siv","wb").write(sIV)
    log(f"TOTAL captured {len(allcap)}B -> {OUT}")
    # find the 0x44f media blob
    i=allcap.find(bytes.fromhex("0000044f"))
    log(f"0x44f media blob at offset {i}" if i>=0 else "no 0x44f seen")
    if i>=0:
        log(f"0x44f region: {allcap[i:i+80].hex()}")

if __name__=="__main__":
    main()
