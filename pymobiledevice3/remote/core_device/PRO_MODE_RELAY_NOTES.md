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
