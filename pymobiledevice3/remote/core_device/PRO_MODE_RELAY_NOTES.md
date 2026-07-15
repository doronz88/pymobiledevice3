# Pro Mode relay: build notes (reverse-engineering in progress)

Goal: make serve-vnc a **dual-mode RFB server** that, when a Mac's Screen Sharing
client engages "Pro Mode," acts as an **entitlement-free protocol relay** — pmd3
speaks the Pro Mode wire protocol and forwards the iPhone's HEVC RTP into the
session, while **Apple's own (entitled) Screen Sharing.app runs the AVConference
receiver** (decode + jitter buffer + DisplayLink playout + rate-control). pmd3
never links AVConference, so the `com.apple.videoconference.allow-conferencing`
entitlement wall doesn't apply (Apple gates the *caller*, not the network peer).
Bonus: the client's RCTL feedback relays back through pmd3 to the device →
the encoder gets the real closed loop → the motion smear is fixed as a side effect.

Why this and not the alternatives (see VIDEOPROCESSING_RE_ROADMAP.md §10-11):
- RCTL-only: already built byte-exact on serve-web (`--rctl`); doesn't fix the
  motion collapse (control-loop dynamics too hard to hand-reproduce).
- Host AVConference receiver in pmd3: **blocked** by the entitlement.
- Pro Mode relay (this): entitlement-free, lets Apple do the whole receive path.

Binaries (on disk, thinned arm64e in scratchpad/re3):
`screensharingd` (RFB + auth + Pro Mode negotiation), `ScreensharingAgent`
(the AVConference sender side), `ScreenSharing.framework` (client). IDA sessions
via `idb_open`.

## GROUND TRUTH — real Mac→Mac Pro Mode handshake captured on the wire (2026-07-16)
Captured via a root-free logging TCP proxy (scratchpad/promode_mitm.py): real
Screen Sharing.app → proxy(localhost:5999) → real server 192.168.50.237:5900.
Everything below is pre-encryption plaintext, byte-verified. Full dump saved:
scratchpad/promode_handshake.txt. **This supersedes earlier guesses about the
entry sequence — and confirms the SRP-4096/SHA-512/ChaCha20 crypto reverse.**

Wire sequence (S=server, C=client viewer):
1. **Version**: both send `RFB 003.889\n` (0x379 = Apple's ARD minor, NOT 003.008/3.3).
2. **Security types (S→C, 5B)**: `04 1e 21 24 23` = count=4, types **[30,33,36,35]**
   (0x1e=30 legacy DH, 0x21=33 "RSA1", 0x24=36, 0x23=35). Server offers a *list*
   even under 003.889 (a 1-byte count + bytes, not the classic 3.3 single-U32).
3. **C→S (15B)**: `21 0000000a 0100 52534131 00000000` → client picks **33**, then a
   sub-message `[u32 len=10][u16 0x0100]["RSA1"][u32 0]`. Method tag is FourCC `RSA1`.
4. **RSA1 host-key step**:
   - S→C (305B): `[u32 len=0x12d][u16 0x0001][u32 derlen=0x126]<DER SPKI>` — server's
     **2048-bit RSA public key** (e=65537), verified parse. This is the host identity key.
   - C→S (654B): `[u32 len][u16 0x0100]["RSA1"][u16 step=2][u16 0x0100]<256B RSA-encrypted>`
     + zero pad — client sends an RSA-OAEP/PKCS1 blob (creds/nonce) under the host key.
5. **SRP + SASL-options step** (this is the `SRP-RFC5054-4096-SHA512-PBKDF2` exchange):
   - S→C (1169B): frame carries **N = RFC5054/RFC3526 4096-bit MODP prime** (verified
     bit-exact, 512B, starts FFFFFFFF…C90FDAA2…, ends …FFFF), **g = 5**, server public
     **B**, then the SASL options ASCII string:
     **`mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2`**
     (the leading `0x50`/'P' is a length/framing byte, not part of the string).
   - C→S (1080B): client public **A** + the same options string, then trailing
     `01000000<ptr>` runs = leaked uninitialised client stack/heap pointers (harmless).
   - S→C (102B): `[u32 len][u32 step=2][u16 0x5c][u32 0x58]<88B>` = server SRP proof M2.
6. After M2: ClientInit/ServerInit, then the video stream floods (the 16MB in the log).

Corrections/confirmations vs prior notes:
- CONFIRMED: SRP-6a, RFC5054-4096, g=5, SHA-512, ChaCha20-Poly1305 control layer,
  SALTED-SHA512-PBKDF2 KDF — all exactly as reversed from screensharingd.
- CORRECTED: entry is **not** RFB 3.3 single-U32 sectype 30. It is **003.889** +
  a **security-type list [30,33,36,35]**, client selects **33 (RSA1)**, and there is
  an **RSA host-key sub-step BEFORE** the SRP exchange. Our recon saw the client wait
  after U32=30 because 30 (legacy DH) wasn't what a modern client wanted to drive.
- The framing is `RSA1`-tagged (`[u32 len][u16 0x0100]["RSA1"][u16 step]…`), a
  superset of the `%c%m…` SASL grammar — need to pin exact field layout per message.
- KDF nuance: options say **SALTED-SHA512-PBKDF2** (the SRP `x`/verifier KDF), matching
  the `kdf=` token — so `srp_verifier()`'s PBKDF2-SHA512 is right; the 19417 default
  iteration count still needs confirming against what the server actually uses here.

Reusable harness: scratchpad/promode_mitm.py (transparent logging relay, no root) +
`open vnc://user:user@localhost:5999`. Re-run any time to capture more/deeper.

## RSA1 step DECODED — validated by building our own server (2026-07-16)
scratchpad/promode_server.py: a stage-by-stage pmd3-side server driven by a LIVE
local Screen Sharing.app (`open vnc://user:user@localhost:5988`). It reproduced the
real server's bytes exactly through RSA1 — the client could not tell it apart:
- Client selects type 33, sends `[u32 len=10][u16 0x0100]["RSA1"][u32 0]`.
- Server sends its **own** 2048-bit RSA host key (we generate the keypair, so we
  hold the private key): `[u32 total][u16 0x0001][u32 derlen][DER SPKI]`.
- Client replies `[u32 len][u16 0x0100]["RSA1"][u16 step=2][u16 0x0100][256B ct]`
  zero-padded to 0x290. The 256B ciphertext is **RSA / PKCS#1 v1.5** (NOT OAEP).
- **DECRYPTED under our host key** → plaintext `00000004 "user" …` = a
  length-prefixed **username**. So RSA1 privately conveys the username; the server
  decrypts it to look up that user's SRP verifier. The PASSWORD is proven later via
  SRP. => pmd3 sets its own verifier for whatever username it advertises; it can
  accept any username since it owns the RSA key + the verifier.
Implication: the whole RSA1 phase is now buildable end-to-end with stdlib crypto
(generate RSA-2048 host key, PKCS1v15-decrypt to read the username). No entitlement,
no proprietary bits.

## SRP server message framing — COMPLETE (clean full capture, 2026-07-16)
The whole message decodes onto the reversed SASL grammar. Server side = exactly what
pmd3 must emit:
```
[u32 payload_len=1165]          # bytes after this field
[u32 step=2]                    # SRP phase (RSA1 was phase 1)
[u16 =payload-6][u32 =payload-10]   # nested length wrappers
[u16 count=2]
[u8 flag=0x00]
N   : 512B raw big-endian       # RFC5054-4096 prime, NO length prefix (fixed group)
g   : %m  = [u16 len=1][0x05]                       # generator 5
salt: %o  = [u8 len=0x20][32B]  # ACCOUNT-FIXED (identical across captures)
B   : %m  = [u16 len=0x200][512B]                   # ephemeral server public (varies)
iters: %q = [u64] = 142857      # PBKDF2 iteration count for this account
[u8 0x00]
opts: %s  = [u8 len=0x50][80B]  # mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2
```
Because pmd3 is the SERVER it OWNS the salt, verifier, and iteration count — it does
NOT need Apple's. It generates a fresh salt, computes v = g^PBKDF2-SHA512(pw,salt,iters)
mod N, and sends {N,g,salt,B,iters,opts}; the client derives x from OUR salt+iters and
the password the user types. (Serializer = screensharingd sub_100012994.)
Client reply (C->S, phase 2) carries A + M1; server replies (S->C 102B) with M2.

### SRP INTEROP CRACKED — verified against the live client (2026-07-16)
Proven end-to-end: a corecrypto-backed pmd3 server made the real Screen Sharing.app
produce an M1 that Apple's own `ccsrp_server_verify_session` ACCEPTS. The exact recipe
(scratchpad/promode_cc_server.py, and validated self-test scratchpad round-trip):
- Call Apple corecrypto **ccsrp directly via ctypes** (symbols re-exported through
  /usr/lib/libSystem.dylib): `ccsha512_di`, `ccsrp_gp_rfc5054_4096`, `ccrng`,
  `ccsrp_ctx_init`, `ccsrp_generate_verifier`, `ccsrp_server_generate_public_key`,
  `ccsrp_server_compute_session`, `ccsrp_server_verify_session`. ctx buffer: allocate
  16 KiB and `ccsrp_ctx_init(ctx, di, gp)` (no exported sizeof needed). exchange size = 512.
  -> removes ALL M1/M2/K/u/k formula guessing; Apple's code computes them.
- **x-password = PBKDF2-HMAC-SHA512(account_password, srp_salt, iterations, dkLen=128)**
  (the 128-byte macOS ShadowHashData entropy) fed as the ccsrp "password".
  NOT dkLen=64, NOT hex-encoded, NOT plaintext, NOT SHA512-prehash — dkLen=128 raw bytes.
- **username = "" (empty)** for BOTH `ccsrp_generate_verifier` and
  `ccsrp_server_compute_session` (screensharingd passes "" to compute_session; the
  corecrypto client uses one username for x and M1, so it must be "" throughout).
- salt = 32 random bytes (server-chosen), iterations = we choose + send (19417 works).
- Server flow per connection: gen_verifier(ctx,"",pw,salt,ver) -> server_generate_public_key
  (ctx,rng,ver,B) -> send step1(N,g,salt,B,iters,opts) -> recv A(512)+M1(64) ->
  server_compute_session(ctx,"",salt,A) -> server_verify_session(ctx,M1,HAMK) == TRUE ->
  HAMK is M2. Since pmd3 is the server it invents the account_password ("user" here);
  the human types that same password into Screen Sharing.app.
This retires the interop risk. **M2 also verified**: framed as
header + `%o(HAMK 64) %o(sIV 16-rand) %s(opts="") %u(session_key_length=64)` = 102B
on the wire (byte-for-byte the same size as the real server's M2). The live client
ACCEPTS it — the connection stays OPEN (a rejected M2 closes the socket) and the
client then waits for the server's post-auth message. => the FULL Pro Mode auth
(RFB 003.889 -> sectype 33 -> RSA1 -> SRP -> M2) now completes against a real
Screen Sharing.app, driven entirely by pmd3 + Apple corecrypto.

### POST-AUTH RFB is PLAINTEXT — handshake reaches Pro Mode negotiation (2026-07-16)
After M2 the traffic is plain RFB (NOT yet encrypted); verified live — pmd3 drove the
real client through it:
- S->C `00000000` = **SecurityResult OK** (4B).
- C->S `c1` = **ClientInit** (shared flag).
- S->C 68B = **ServerInit**: `[u16 w=0x0d80][u16 h=0x08ba][16B pixfmt: 32bpp/24depth,
  truecolour, RGB max 255, shifts 16/8/0][u32 namelen=0x2c=44][44B Apple name struct
  ending "..MacBook Pro"]`. Must be byte-shaped right or the client disconnects.
- C->S 82B type **0x21** = Pro Mode display config; C->S 56B type **0x02** = SetEncodings
  with Apple Pro Mode encodings (0x3f3,0x3ea,6,0x10,0x450,0x44c,0x44d,0x451,0x453,
  0x455,0x456 + pseudo 0xffffff11/0xffffff21).
- Server then must answer: S->C 8B `140000040001000c` (type 0x14) then S->C 412B media
  negotiation blob (`00000001..0000044f..` = AVC negotiator offer + media keys), after
  which the `[u16 len][ciphertext]` **ChaCha20** control/media frames begin.

The ChaCha20 control channel (LayerInit sub_100013640): CoreUtils
`chacha20_poly1305_init_64x64(ctx, key=session_key@mech+80, nonce)` x2 (client dir uses
cIV, server dir uses sIV); frames are `[u16 len][ciphertext+16B tag]`. Only used for the
media-control messages, not the RFB handshake above.

STATUS: auth + RFB handshake DONE end-to-end vs live client (promode_cc_server.py).

### Media negotiation is SESSION-ENCRYPTED (replay proven to fail, 2026-07-16)
Replaying .237's captured 0x14 + 412B 0x44f blob at the local client -> client sends
SetEncodings + a 0x12 msg then CLOSES. So the 0x44f media blob is bound to the SRP
session (ChaCha20-Poly1305 sealed). Size math confirms one AEAD blob:
412B = 16B FBU header + 4B version(00000001) + 376B plaintext + 16B Poly1305 tag.
No shortcut: the ChaCha20 control channel must be built for real.

### Crypto primitives — ALL callable from Python via ctypes (verified present):
- ccsrp_* (libSystem) incl. ccsrp_get_session_key -> extract the 64B SRP session key K.
- CoreUtils.framework: chacha20_poly1305_init_64x64 / add_aad / encrypt / decrypt /
  final / verify / encrypt_all_64x64 / decrypt_all_64x64.
  NOTE: exact incremental-encrypt signature/state-layout still needs pinning (a naive
  ctypes call returns zero ciphertext + segfaults) -> reverse a CALLER of
  chacha20_poly1305_encrypt (NOT in screensharingd, which only imports init; the RFB
  I/O security layer that uses mech+376/mech+632 contexts lives elsewhere -- likely the
  ARDAgent/AppleVNCServer RFB lib). Also unresolved: the layer-key derivation into
  mech+80 from K, the cIV/sIV nonce scheme, and the per-frame `[u16 len][ct+tag]` format.

### REMAINING BUILD (the media half; needs iterative work + the iPhone for video):
1. ChaCha20 control channel: pin encrypt/decrypt signature + key(mech+80) + nonces +
   frame format; wrap send/recv.
2. Media negotiation CONTENT: the 376B plaintext offer (AVCMediaStreamNegotiator; reuse
   media_stream_offer.py) + SRTP master keys. Fastest reverse route: an ACTIVE
   decrypting MITM of a real Mac<->Mac session (we know password "user" for BOTH ends,
   so run SRP with each side, hold both session keys, decrypt both directions) OR
   reverse ScreensharingAgent's offer builder.
3. SRTP relay (cipher 5, AES-128-CTR -- already in pro_mode_relay.py) + SSRC/seq rewrite.
4. Bridge pmd3's displayservice HEVC RTP source (serve-vnc already receives it).

### (historical) the make-or-break risk that is now RESOLVED: ccsrp interop
Apple computes SRP with corecrypto **ccsrp** (SHA-512, RFC5054-4096, verifier x =
SALTED-SHA512-PBKDF2). Whether `srptools`' standard SRP-6a produces the identical
k / M1 / M2 (MPI zero-padding to |N|, hash input ordering) is UNVERIFIED and is the
one thing that can sink the whole approach. Decisive next experiment: extend
promode_server.py to emit the SRP step (srptools B + framing above), drive the live
client, and see if it accepts our M2 / we accept its M1. If it mismatches, swap in a
padding-exact SRP-6a (H(N)^H(g), PAD to 512B) rather than srptools. Best done live.

## Remaining after SRP: control channel + media (still to build)
ChaCha20-Poly1305 control channel keyed from the SRP session key via
SALTED-SHA512-PBKDF2 (LayerInit) -> Pro Mode capability advertise -> AVC negotiator
offer/answer (reuse media_stream_offer.py) -> SRTP (cipher 5) relay of iPhone RTP
with SSRC/seq rewrite -> relay client RCTL back to device.

## The 6 pieces to build
1. RFB server + advertise Pro Mode capability (extends serve-vnc's handshake).
2. **SRP auth** → session key.  ← REVERSED (below)
3. `AVCMediaStreamNegotiator` offer/answer over the connection.
4. SRTP-encrypt relayed RTP (cipher 5) with SRP-derived keys — unless a null
   cipher is negotiable for the AVC stream (client has `minimumEncryptionLevel`;
   legacy VNC allows unencrypted, Pro video likely does not — verify).
5. Rewrite RTP SSRC/seq/ts device→session.
6. Relay client RCTL back to the device.

## Piece 2 — SRP auth: REVERSED (screensharingd, `common/srp.m`)
Scheme string in binary: **`SRP-RFC5054-4096-SHA512-PBKDF2`**.
- SRP-6a, group **RFC5054 4096-bit**, hash **SHA-512**.
- Verifier = **PBKDF2**(password, salt), default **iterations = 19417**, **salt =
  32 random bytes**. corecrypto `ccsrp` — maps to any standard SRP-6a impl.
- Server funcs: `ccsrp_ctx_init` → `ccsrp_server_generate_public_key` (step1) →
  `ccsrp_server_compute_session` + `ccsrp_server_verify_session` (step2). All 4
  RFC5054 groups (1024/2048/4096/8192) are registered; **4096** is selected
  (`strcasecmp … "rfc5054_4096"`).
- step1: look up (salt, verifier, iterations), gen server pubkey B, send
  salt+B+options. SASL out-format `"%c%m%m%o%m%q%s"`.
- step2: read client A, `ccsrp_server_compute_session`, verify client evidence
  M1, gen 16-byte sIV, send server evidence. SASL out-format `"%o%o%s%u"`.
- Real server sources (salt,verifier) from **OpenDirectory** (`GetAuthenticationData`
  custom fn, record type Users) = a real macOS account. **pmd3 can instead supply
  its OWN (salt,verifier) from a chosen password** — no real account needed; the
  user types that password in Screen Sharing.app's auth prompt.
- **pmd3 ALREADY HAS the SRP server infra — reuse it.** `remote/tunnel_service.py`
  `_pair_setup` (RemotePairing M1-M6) uses `srptools` (`SRPContext`,
  `SRPServerSession`, `SRPClientSession`) as the SRP SERVER, with `hash_func=
  hashlib.sha512` already. `srptools.constants` ships **`PRIME_4096`/`PRIME_4096_GEN`**
  (the RFC5054-4096 group). So piece 2 = reuse `SRPServerSession` with
  `SRPContext(user, prime=PRIME_4096, generator=PRIME_4096_GEN, hash_func=sha512)`.
  Two deltas vs pairing: (a) group 3072→4096 (already available); (b) verifier `x`
  = **PBKDF2-SHA512(password, salt, iters=19417)** not standard SRP-6a `x` — but
  pmd3 owns the verifier, so compute `v = g^x mod N` with a PBKDF2 `x` and pass it
  as `SRPServerSession(context, verifier)`. SRP math fully reused; only the wire
  **framing** differs (pairing=TLV, Pro Mode=SASL `%`-buffers → `sub_100012994`).
- Key addrs (screensharingd.arm64e, imagebase 0x100000000): SRP step1/2
  `sub_100011280`; group registration `sub_100012D38`; digest select
  `sub_1000111A0("sha512")`; **SASL %-serializer `sub_100012994`** (reverse next);
  **security-layer + media-key derivation `sub_100013640` / `sub_1000135D4`**
  (reverse next — this is where the SRP session key becomes the SRTP media keys +
  the encrypted RFB data stream).

## Auth+key stacks found (two distinct SRP flows)
Master-key derivation for the RFB control stream is now pinned:
`masterKey = CC_SHA256(srp_session_key)[:16]` (in `SendSRPChallenge` /
`RFBServer/AuthenticateTheViewer.m`, `sub_100017A2C`; the SRP session key is read
raw from the ccsrp ctx at `ctx + 32*ccdh_gp_n + 32`).
- **Stack A — AES (ARD-style):** `sub_100017714` = `SetupAESKeys`. Four AES-128
  cryptors from that 16-byte masterKey: CBC-enc, CBC-dec (zero IV), ECB-enc,
  ECB-dec. (`CCCryptorCreate(alg=0=AES, keyLen=16)`.)
- **Stack B — ChaCha (SASL-SRP layer):** `common/srp.m` `sub_100011280` →
  `LayerInit sub_100013640` = ChaCha20-Poly1305, KDF `SALTED-SHA512-PBKDF2`,
  from the SRP session key.
Both are CONTROL-channel. Which one a Pro Mode by-IP session uses (and whether
the video keys branch off the same session key) is the open thread.

## Piece 4 progress — key material derivation (partial)
- **Control channel** (the encrypted RFB data stream, viewer<->server): **ChaCha20-
  Poly1305**, KDF **SALTED-SHA512-PBKDF2**, send+recv subkeys derived from the SRP
  session key. Fn `sub_100013640` ("LayerInit", screensharingd) — requires replay
  detection; init send=`chacha20_poly1305_init_64x64(+376,+80,sendKey)` recv=`(+632,
  +80,recvKey)` where +80 is the SRP session-key region.
- **Video SRTP keys**: `ScreensharingAgent` does NOT derive them (no derive/hkdf/kdf
  in that binary — only jpeg). They arrive as PARAMETERS
  (`…video1EncryptionKeyViewerToServer:ServerToViewer:…`) → **screensharingd derives
  them from the SRP session key and passes them to the agent over XPC.** SRTP suite
  = **5** (hardcoded in `createAVCVideoStream…`). Exact video-key KDF NOT yet pinned
  (screensharingd, from SRP session key) — top of the reverse-next queue. Both sides
  (server + Screen Sharing viewer) derive the same keys from the shared SRP secret;
  pmd3 must reproduce that KDF to encrypt the relayed RTP the client can decrypt.

## Piece 4 — video SRTP: CONFIRMED standard RFC 3711 AES-CTR (2026 binary)
`AVConference _SRTPEncryptData` @ `0x1bd89b768` (imagebase 0x1bd636000), called via
`_SRTPEncrypt` from the RTP send path (`_SendRTP` / `_RTPMediaQueueSecurityCallback`):
- Cipher = **AES-CTR** via CommonCrypto: per packet `CCCryptorReset(cryptor, iv)` then
  `CCCryptorUpdate` in place. Cryptor created in `-[VCMediaStreamTransport setupSRTP]`
  with the media key.
- IV/counter (16 B, "MakeCounter") = **textbook SRTP (RFC 3711)**: 14-byte **salt**
  (token, ctx+238) base, XOR **SSRC** (ctx+120), XOR **ROC** (`SRTPGetROC`) + **seq**
  (`iv[13]^=seq; iv[12]^=seq>>shift`). I.e. `IV = salt ⊕ (SSRC≪64) ⊕ ((ROC∥SEQ)≪16)`.
- => **cipher suite 5 = standard SRTP AES-128-CTR.** Matches P0's Mojave writeup, so
  it's stable across versions. **pmd3 can use a standard SRTP lib** (pylibsrtp/libsrtp)
  to encrypt the relayed RTP — no hand-rolled crypto. Auth: only encryption seen in
  SRTPEncryptData (likely NULL/short auth tag — confirm the RTCP/RTP auth len).
- Remaining sub-piece: the KDF **SRP session key → (16-B media key, 14-B salt)** per
  direction (viewer->server / server->viewer). Master key `SHA-256(session)[:16]` is
  known for the control channel; the media key+salt derivation is the last KDF to pin
  (likely a labeled expansion of the SRP session key; both peers derive identically).

## Piece 4 — media-key structure: SOLVED (no KDF)
`-[VCMediaStreamTransport getCryptoSet:withMediaKey:]` (0x1bda32e34): the mediaKey
is a plain **concatenation** `mediaKey = [AES key] ‖ [14-byte salt]`, total length
= `getSRTPMediaKeyLength(cipherSuite) + 14`. For cipher 5 (AES-128) that's
**16-byte key ‖ 14-byte salt = 30 bytes**. It's split directly (no KDF) into the
SRTP key + salt fed to `SRTPUseEncryption`. The mediaKey comes from
`streamConfig.sendMediaKey` / `receiveMediaKey` — i.e. the negotiated
`videoEncryptionKey{ViewerToServer,ServerToViewer}` tokens.
=> **Media keys are random 30-byte values the SERVER generates and exchanges in
the negotiator over the (SRP-)encrypted control channel — not derived from the SRP
session key.** So pmd3, as the server, just generates random 16-B key + 14-B salt
per direction, puts them in the negotiator answer, and SRTP-encrypts the relayed
RTP with a standard SRTP lib. `getSRTPMediaKeyLength:` maps the cipher-suite id →
AES key length. `VCDefaults forceDisableMediaEncryption` forces cipher=0 (a real
no-encryption hook; likely internal-only).

## CRYPTO STACK: fully reversed (summary)
For the relay, the entire crypto path is now mapped — no proprietary KDF remains:
1. **SRP auth** = SRP-RFC5054-4096-SHA512-PBKDF2 → reuse `srptools` (PRIME_4096).
2. **Control channel** = AES-128 (`SetupAESKeys`, key=`SHA-256(SRP session)[:16]`,
   CBC+ECB) OR ChaCha20-Poly1305 (`LayerInit`, SALTED-SHA512-PBKDF2). One of these
   secures the RFB stream over which keys/negotiation are exchanged.
3. **Media (video/audio) SRTP** = standard RFC3711 AES-CTR; per-direction mediaKey
   = random(16-B key ‖ 14-B salt), server-generated, exchanged in the negotiator;
   IV = salt ⊕ SSRC ⊕ (ROC∥SEQ). Use a stock SRTP lib.
Remaining for the relay = pure WIRE FORMAT (no more crypto RE): the SASL message
framing (`sub_100012994`) and the Pro Mode capability + `AVCMediaStreamNegotiator`
offer/answer structure (`sub_100036C54`), plus which control-channel stack (AES
vs ChaCha) the by-IP Pro Mode path selects.

## Scope reality
This is a large, multi-session reverse of a proprietary multi-binary protocol
(screensharingd handshake/auth/keying + ScreensharingAgent media + ScreenSharing.
framework viewer). Reversed so far: the entitlement wall + relay architecture, the
full SRP scheme (+ that pmd3 can reuse srptools), and the control-channel crypto.
NOT yet reversed: the exact video-key KDF, the SASL wire framing, the
AVCMediaStreamNegotiator/RFB Pro Mode capability format, and the SRTP-5 packet
format the client expects. Each is a meaty decompile; they cannot all be finished
in one pass. The queue below is the remaining work in priority order.

## Prior art / external references (checked 2026-07)
- **NO open-source project implements the Pro Mode / "High Performance" screen-
  sharing SERVER relay** (what we'd build). Too new (macOS Sonoma/Sequoia, 2024+),
  fully closed. So this is original RE — not a fork.
- **Google Project Zero "Street-Party"** (github.com/googleprojectzero/Street-Party,
  FaceTime/) + blog "Adventures in Video Conferencing Part 2" — the closest reverse.
  It's a **dylib-injection interposer** (hooks `CCCryptorCreateWithMode` + `sendmsg`
  in AVConference) that records/replays FaceTime RTP. Gives the **video SRTP scheme**
  (the piece we were hunting): CommonCrypto **AES**, per-stream **16-byte key +
  16-byte IV/token** (dumped at CCCryptorCreateWithMode); token exchanged at stream
  init; **AES-CTR**, per-packet counter = token XOR (SSRC, sequence number; seq
  XOR'd at token index 0x12). Stream id'd by dispatch-queue name
  `com.apple.VideoConference.videoTransmit`. CAVEAT: macOS **Mojave** era (2018) —
  must verify vs the 2026 binary (which showed cipher suite **5** +
  `CCCryptorCreateWithMode`, consistent). This likely == the
  `videoEncryptionKey{ViewerToServer,ServerToViewer}` tokens + cipher-5 we saw in
  ScreensharingAgent → the unpinned video-key piece is now sketched externally.
- **Legacy ARD auth** (DH-512 + MD5 + AES-128-ECB, credential encryption) is
  documented and in `libvncclient`/TigerVNC — reference for the RFB layer, but the
  modern connection uses the SRP stacks reversed above, not this.
- iOS QuickTime/usbmux screen mirroring (danielpaulus quicktime_video_hack) = the
  OLD path, not CoreDevice displayservice — n/a.
- Net: SRP + control-channel crypto reversed here; **video SRTP de-risked by P0**
  (AES-CTR, 16B key+token, counter from SSRC/seq) pending 2026 verification.

## Wire framing — SASL serializer REVERSED (`sub_100012994`, screensharingd)
Length-prefixed TLV. Message = `[u32 BE payload_len][fields…]` (len excludes the
4-byte prefix). Format tokens (`type = (char - 99) >> 1`):
- `%c` char  → 1 byte
- `%m` MPI   → `u16 BE len` + big-endian bignum bytes (`ccz_write_uint`)
- `%o` octet → `u8 len` + bytes
- `%q` u64   → 8 bytes BE
- `%s` str   → `u16 BE len` + UTF-8
- `%u` u32   → 4 bytes BE
SRP step1 out `%c%m%m%o%m%q%s` = marker, MPI, MPI, salt(octet), MPI(B), u64,
options(str e.g. "SRP-RFC5054-4096-SHA512-PBKDF2"). step2 out `%o%o%s%u` =
evidence(octet), sIV(octet, 16B), options(str), keylen(u32). Read side is the
inverse (`sub_100012350` UnBuffer). This is the framing for the whole SRP
handshake carried in the RFB Pro Mode messages.

## Negotiator offer/answer — ALREADY REVERSED in pmd3 (reuse)
`AVCMediaStreamNegotiator` (rich class in AVConference: settings IVARs `_localSSRC`,
`preferredAudioCodec`, `audioStreamMode`, `preferredMediaBitRate`,
`rtcpTimeOutEnabled`, jitterBufferMode, …). Its offer/answer is the AVConference
**mediaBlob**, and **pmd3 already builds it**: `media_stream_offer.py` reverses
`-[AVCMediaStreamNegotiator createOffer]` — a bplist with
`avcMediaStreamNegotiatorMediaBlob` (zlib protobuf: session id, HEVC/AVC CodecBanks,
feature strings, BitrateTiers, ltrp, allowRTCPFB) + mode(5 video/6 audio) +
RemoteEndpointInfo + CallID. Pro Mode exchanges this SAME negotiator offer/answer.
=> **Reuse `media_stream_offer.py` for the Pro Mode negotiation.** Delta for Pro
Mode: add the media-key fields (sendMediaKey/receiveMediaKey = random 16B key‖14B
salt) + SRTPCipherSuite=5, and carry it in the RFB Pro Mode envelope (encrypted
control channel) instead of the CoreDevice `mediastreamstart` bplist.

## STATUS: protocol essentially mapped — remaining = RFB Pro Mode envelope only
Everything the relay needs is now reversed or reusable:
- SRP auth → reuse `srptools` (PRIME_4096, PBKDF2 verifier). [reversed]
- SASL handshake framing → `sub_100012994` TLV. [reversed]
- Control-channel crypto → AES-128 (SetupAESKeys) / ChaCha20-Poly1305. [reversed]
- Negotiator offer/answer → reuse `media_stream_offer.py` mediaBlob. [reused]
- Media SRTP → standard RFC3711 AES-CTR, random exchanged keys, stock lib. [reversed]
LAST wire piece: the **RFB Pro Mode capability advertisement + the message that
triggers/carries the AVConference negotiation** (`sub_100036C54`, screensharingd,
"ProMode also enabled on viewer") — how Pro Mode is signalled in the RFB handshake
and which envelope wraps the SRP + negotiator + keys. Then it's a BUILD (RFB server
+ SRP + control channel + negotiator + SRTP relay + RTP SSRC/seq rewrite), testable
against a real Screen Sharing client by IP.

## BUILD phase (RE complete)
Device-independent pieces (buildable + unit-testable without hardware; each
validates the RE):
- [x] SASL framing codec — prototyped + round-trips (scratchpad/sasl_codec.py):
      `[u32 BE len]` + `%c`1B `%m`u16len+bignum `%o`u8len+octets `%q`u64 `%s`u16len+utf8
      `%u`u32. step1/step2 shapes verified.
- [ ] SRP server: `srptools` `SRPServerSession(SRPContext(user, prime=PRIME_4096,
      generator=PRIME_4096_GEN, hash_func=sha512), verifier)` where
      `verifier = pow(g, PBKDF2-HMAC-SHA512(pw, salt, 19417), N)`. pmd3 owns the
      verifier so the server math is standard; interop test needs a PBKDF2-x client.
- [ ] SRTP: standard RFC3711 AES-128-CTR round-trip (key‖salt=30B, IV=salt⊕SSRC⊕(ROC∥SEQ)).
Integration pieces (NEED device + a real Screen Sharing.app client to verify):
- [ ] RFB Pro Mode server loop: capability handshake (last envelope detail, pin
      during integration) → SRP → control channel → negotiator exchange (reuse
      `media_stream_offer.py` + add media keys + cipher 5) → SRTP relay (recv device
      RTP, rewrite SSRC/seq, SRTP-encrypt with the negotiated key, send to client) →
      relay client RTCP back to the device.

## Live recon harness + first-contact findings (2026-07-15, self-driven)
Harness (scratchpad/rfb_recon.py): minimal RFB server that logs exactly what
Screen Sharing.app sends; driven with `open vnc://localhost:PORT` (no second Mac
needed) + `log show/stream --predicate 'process=="Screen Sharing"'`. Reusable for
the interactive integration loop.
Findings from driving Screen Sharing.app -> recon server:
- Client forces **RFB 003.003**. In 3.3 the **server sends ONE U32 security type**
  (not a 3.7+ list). (Our first attempt sent a 3.7 list -> client choked; fixed.)
- Sending U32 **security type 30 (Apple auth)**: client then sends **0 bytes and
  waits** -> Apple auth is **SERVER-FIRST**. The server's first message is the
  Apple-auth hello = the SRP **step1** (`%c%m%m%o%m%q%s` = salt+B+options, reversed).
- So to advance the live client, pmd3 must emit a field-exact SRP step1. OPEN:
  (a) the exact %c/%m/%m/%o/%m/%q/%s field mapping (which MPI is N/g/B; the %q; the
  options string incl. the ChaCha/AES + SALTED-SHA512-PBKDF2 layer tokens) —
  re-read sub_100011280 step1 arg setup; (b) the SRP/Pro-Mode security-type number
  (30 looked like server-first Apple auth; SRP may be 30 or another). Best pinned
  interactively: emit step1, read the client's A/M1, adjust.
NEXT (interactive, with user): extend rfb_recon.py to send a real SRP step1
(reuse ProModeSrpServer for B) and observe whether the client returns A+M1 ->
that both finds the security-type number AND proves ccsrp interop. Cleanup: kill
leftover recon listeners (scratchpad rfb_recon*.py on :5905/:5906).

## Reverse-next queue (priority order)
1. `sub_100013640` / `sub_1000135D4` — SRP session key → **SRTP media keys**
   (videoEncryptionKeyViewerToServer/ServerToViewer) + RFB security layer. This
   is the KDF that produces the keys `ScreensharingAgent` feeds to
   `setSendMediaKey:`/`setReceiveMediaKey:` (cipher 5).
2. `sub_100012994` — the SASL-ish `%c%m%o%q%s%u` buffer serializer (wire framing
   for every handshake message).
3. `sub_100036C54` — Pro Mode negotiation: RFB capability advertisement +
   `AVCMediaStreamNegotiator` offer/answer (the AVConference session config: SSRC,
   ports, HEVC params). "ProMode also enabled on viewer".
4. SetEncryption handler + whether the AVC video accepts a null cipher (piece 4).
5. `ScreensharingAgent -[SSUDPSender createAVCVideoStreamWithRemoteAddress:...]`
   (already partly reversed): confirms cipher 5, SSRC/framerate/port wiring the
   relayed RTP must match.
