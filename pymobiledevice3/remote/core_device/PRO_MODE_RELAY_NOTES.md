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
