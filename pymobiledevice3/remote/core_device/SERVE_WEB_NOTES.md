# serve-web: motion-tearing / stall investigation — continuation notes

## CORRECTED CONCLUSION (2026-07-12) — tearing is device-side & DECODER-INDEPENDENT

**All the motion tearing (both the geometry collapse AND the "mosaic") is produced by
the device's AVConference encoder under fast motion at the ~6 Mbps cap. It is in the
encoded bitstream, and EVERY decoder renders it identically.** This supersedes
RESOLUTION #2 below, which blamed the browser's WebCodecs HW decoder — that is
**DISPROVEN**:

- **serve-vnc, native VideoToolbox decode (`--decoder vt`), tears IDENTICALLY** to the
  browser when the user swipes the **physical device** by hand. Native decode was
  claimed (by RESOLUTION #2, and by me mid-session) to be the clean path — it is not.
- It is **not HID injection / touch-session eviction** either: the trigger was a
  *physical* on-device swipe, no `/touch` sent through serve-web or VNC.
- The "ffmpeg decodes the stream CLEAN, 0 errors" evidence in RESOLUTION #2 was
  **mis-read**: ffmpeg reporting no decode *errors* means the stream is *valid/decodable*,
  NOT that the image is pristine. The device encodes valid-but-degraded (blocky/torn,
  QP-escalated) frames under motion; ffmpeg, WebCodecs, and native VideoToolbox all
  render those same degraded frames. A keyframe "clears" it for any decoder (fresh
  reference), so "keyframe fixes it" never distinguished decoder-state from bitstream.

**So the decode path was never the axis.** The real question (unchanged, still open) is
why the device's ENCODE tears for our stream but reportedly not for Xcode's, given the
encoder *config* captured from a live Xcode session was byte-identical. That difference
lives in the **stream-setup negotiation** (device-side), e.g. the unprobed `VideoSettings`
fields (`f8` pixelFormats, `f13` foveation, `f14` interleavedEncoding) or the
rate-adaptation *mode* — none of which are behind toggles yet. Next step: capture the raw
bitstream WHILE physically swiping and diff frame-by-frame vs an Xcode capture.

**serve-vnc is NOT a tear fix** (it tears too). Its fix this session (commit "serve-vnc:
send periodic video RR") is unrelated: serve-vnc sent no periodic video Receiver Report,
so the device reaped the video session at ~25 s and serve-vnc froze permanently (no
stream-restart). The RR keepalive makes it hold a live stream (verified 140 s). Also
fixed this session: a branch-introduced fps->0 watchdog restart-storm (`key_starved`
trigger) restored to master's single AU-stall trigger; the RCTL OWRD arrival-clock
(reported on the wrong epoch → phantom-congestion throttle); and the audio RR reap gate.

**The research harness earns its keep**: the CLI/`/debug` toggles (esp. runtime
`/debug/{rctl,idr}-{on,off}` — single-session A/B that sidesteps this unit's boot-time
degradation) are how the wrong theories above were eliminated. They narrow; they haven't
solved. Aim them next at the untested negotiation fields.

---

## SYSLOG GROUND TRUTH (2026-07-08) — the collapse is a hardcoded 6 Mbps device limit

Capturing `avconferenced` os_log **un-redacted** (method: a SECOND `pymobiledevice3
syslog live --userspace` tunnel alongside the serve-web `--userspace` tunnel — they
coexist) gives the device's own rate-controller state and settles this.

The `AVCRateController` + `VideoTransmitter` health prints (every 5 s) show:

- Cap is fixed: `targetBitrate=5490 kbps, bitrateCap=6000 kbps` ALWAYS.
- Under motion the encoder **trades framerate for bitrate as it approaches the cap**:
  measured `encodedFrameRate` 55→40→**28 fps** as `currentMediaBitrate` climbed
  1.8→2.2→**4.8 Mbps**. Push harder (real hand motion) and it also drops resolution
  (the 720×1280 collapse). `VCVideoStreamRateAdaptation` is the component doing it;
  the config carries `vcMediaStreamRateAdaptationEnabled = 1`.
- With the corrected RCTL loop the health print is HEALTHY: `RemoteBWE=60001 kbps,
  OWRD=0–5 ms, Uplink PLR=0.00%` — i.e. the inline-receipt fix genuinely killed the
  false-loss fps throttle (PLR was ~87% before). Confirmed here, not inferred.

Every host-side lever to move the cap was tried and RULED OUT by watching the health
print's `bitrateCap`/`targetBitrate` (all stayed 6000/5490):

- RCTL `--max-bitrate` (2000): ignored — target stays 5490 even with BWE=60001.
- `AVCMediaStreamNegotiatorAccessNetworkType` (1→3): no change.
- The offer's `f9` BitrateTier table (bumped the 6 Mbps tier to 20 Mbps): no change.
- `AVCMediaStreamNegotiatorVideoWidth/Height` (632×1368): ignored — stream stays
  native 1264×2752 (resolution is locked for screen capture).

**Conclusion:** the motion tear/fps-drop is the device encoder hitting a hardcoded
~6 Mbps cap and its rate-adaptation dropping fps then resolution. It is NOT movable
by anything we send. Xcode's smoothness (its pcap ran at ~1.7 Mbps, never near the
cap) is either lighter content or a private entitlement/service path. The only
un-explored device-side lever is turning OFF `vcMediaStreamRateAdaptationEnabled`
(would trade the collapse for blocky-but-full-frame) — its client key isn't among the
`AVCMediaStreamNegotiator*` options, so it'd need deeper AVConference RE, possibly an
entitlement. Binary: `System/Library/PrivateFrameworks/AVConference.framework`;
relevant symbols `-[VCVideoStreamRateAdaptation ...]`, `configureRateControllerWithConfig:`,
ML models `default_factors_AVCONFERENCE_NETWORK_SMART_BRAKE_fbs.bin`.

---

## STATE (2026-07-08) — two independent axes: FPS (fixed) and COLLAPSE (device-limited)

The user-reported tear ("screen shrinks to a small rectangle in the upper-left
while swiping") is a **device-side resolution collapse**: under rapid motion the
DisplayService encoder, capped at a hardcoded ~6 Mbps, drops capture resolution
(observed 720×1280 for a 1264×2752 panel), stretches the whole screen into that
smaller frame, and pins it TOP-LEFT of the fixed buffer with flat gray
(Y=Cb=Cr=128) padding. It is **in the bitstream** (ffmpeg decodes it identically),
reproduces in ~2 s of real hand motion, and — critically — synthetic /touch
swipes NEVER reproduce it (too little byte-rate to hit the cap), so it can only be
judged by hand ([[feedback-screen-stress-test-quality]]).

### FPS — FIXED. Root cause: RCTL receipt *timing*

Sending the AVConference RCTL feedback made the device throttle framerate to
<10 fps under motion. It is NOT the report content (byte-exact to Xcode) — it's
the **per-frame receipt (RTCP APP name=5)**. Xcode sends exactly ONE receipt per
frame (measured: receipt-rate == frame-rate) so the device credits each frame's
full packet span and computes ~0% uplink loss. Our old loop sent receipts on a
40/s timer via a deferred `create_task`; under motion those arrive after the
device ages the frame out → it credits ~1 of ~8 packets → false ~87% uplink loss
→ loss-defensive encoder → framerate throttle. Fix: send the receipt INLINE (not
deferred) on each RTP marker with that frame's ts (`_udp_recv_and_depacketize`).
With that, RCTL runs at full framerate. (`--no-rctl` is also full framerate,
since it sends no feedback at all.)

### COLLAPSE — device-limited, NOT fixable via RCTL (exhausted)

Every RCTL field was tried: byte-exact report, per-frame receipts, and OWRD
(w4-lo). None prevent the collapse. OWRD is a throttle knob only — flooring it to
Xcode's ~125 dropped fps to <6 (on our ~zero-delay tunnel a large OWRD reads as
congestion); the real near-zero jitter is correct for fps. So the collapse is the
device encoder's own rate-vs-quality choice at the 6 Mbps cap, not gated by the
feedback loop — matching the earlier FINDINGS caveat ("degraded even with the
loop closed"). **Xcode's RCTL is byte-identical to ours yet Xcode never
collapses (40 fps @ ~1.7 Mbps in the pcap), so its collapse-avoidance lives
OUTSIDE the RCTL feedback** — almost certainly its negotiated encode config /
rate-control mode, which is over the encrypted tunnel and NOT in the media pcap.
That stream-setup RE is the open path to true parity.

Mitigations shipped (all togglable — see below):

- **Viewer stretch compensation** (`viewer.js` `detectContentCrop`, per frame,
  `--compensate`): detect the shrunk content rect on the RAW frame and stretch it
  to fill the canvas → corner-shrink becomes a softer momentary resolution dip.
  MUST be per-frame (a stale crop zooms a full frame into its top-left — the
  "smaller screen over the old full screen" smearing). Validated offline against a
  real 85k-frame capture (flags exactly the collapsed frames, 0 clean). Partial:
  at high fps the fast collapse/recover transitions still show through somewhat.
- **Server mid-motion IDR** (`_decoder_refresh_loop`, `--motion-idr`): forces a
  keyframe ~1×/s while moving so the device re-emits full res. Fast recovery, but
  **combined with `--rctl` it throttles fps hard** — so the default keeps RCTL off.

### Defaults + research toggles

Default = maximise fps: **RCTL off, motion-IDR on, compensation on**. Everything is
togglable so the collapse/rate-control can be researched without code edits:

- CLI: `--rctl/--no-rctl`, `--motion-idr/--no-motion-idr`, `--compensate/--no-compensate`, `--max-bitrate`.
- Runtime (no restart — restarts are slow and wedge this beta device): `POST /debug/{rctl,idr}-{on,off}`.
- Viewer: `?compensate=0|1` URL override.

### Open item (true xcode-parity)

Decode Xcode's DisplayService/AVConference **stream-setup** negotiation (the
mediaBlob / VideoSettings the client sends at connect) — that, not the RCTL
feedback, is what makes Xcode's encoder hold resolution+framerate under motion.
Needs a stable (non-beta) device: this unit degrades to ~10 fps within minutes of
a fresh boot, which invalidated many mid-session fps comparisons.

---

## Earlier investigation (superseded framing below — kept for the trail)

Status: **TWO DISTINCT DEFECTS, do not conflate.**

1. **Geometry collapse** (the symptom users actually report — "screen becomes a
   small rectangle in the upper-left while swiping"): device-side, in the
   bitstream, NOT the browser and NOT RCTL. Fix is the two-part solution above
   (this section's "auto-recovered in the viewer" was an earlier /restart-watchdog
   approach, since replaced by stretch-compensation + mid-motion IDR).
2. **Motion mosaic** (scrambled blocks): the browser's WebCodecs HEVC *hardware*
   decoder mangling high-motion frames — a separate, secondary issue that is not
   fixable server-side. See RESOLUTION #2.

## RESOLUTION #1 — geometry collapse (2026-07-07, PRIMARY, fixed)

The dominant user-reported symptom ("smaller rectangle in the upper-left corner",
"screen becomes smaller while swiping") is **not** the browser and **not** our RCTL
feedback. The device-side DisplayService/AVConference encoder degrades over a
session so the captured screen collapses into the top-left corner of the fixed
1264×2752 encode buffer, the remainder filled with flat gray (Y=Cb=Cr=128) padding.
It lives **in the bitstream** — ffmpeg decodes the collapsed geometry identically.

Evidence (this session):

- **Fresh negotiation is clean with RCTL ON**: 35 rounds / 11 min of sustained hard
  synthetic motion on a just-rebooted device → 0 collapsed frames, full 1264×2752
  throughout. So RCTL does **not** cause it (this corrects the earlier suspicion).
- **A degraded session's dump is ~51% collapsed**: full-file scan of an 85 064-frame
  capture — clean for the first 20 874 frames, then two sustained collapse blocks
  (37 686 and 5 976 frames; minutes each, never flickering). The device sometimes
  self-heals (a clean block returned mid-file), matching users' "it resets itself
  quickly afterwards".
- **A `/pli` cannot fix it** (can't restore a shrunk capture region); only a full
  session re-negotiation (`/restart`) does — exactly the manual "Force Restart" cure.

**The fix (viewer.js `detectGeometryCollapse` + watchdog):** downsample the drawn
canvas to 24×52 once a second and test the collapse's spatial signature — right
column + bottom row are gray-128 padding while the top-left quadrant still holds
real content. Hold for 3 s → POST `/restart` (the audio-preserving path), rate-
limited to 1 per 20 s so a genuinely gray screen can't loop. Validated: the
signature flagged exactly the 51% collapsed frames and 0 of the 41k clean frames in
the capture; live, it fired once on a forced collapse and 0 times over 20 s / 246
hard drags of healthy motion.

## RESOLUTION #2 — motion mosaic (2026-07-07) — **DISPROVEN, see CORRECTED CONCLUSION at top**

> ⚠️ This section's conclusion ("the mosaic is the browser's WebCodecs HW decoder;
> native/software decode is clean") was **disproven 2026-07-12**: serve-vnc with native
> VideoToolbox decode tears identically under physical-device motion. The mosaic is
> device-side/in-bitstream like the collapse. Kept below for the investigation trail.

The residual scrambled-block mosaic (distinct from the geometry collapse above) is
the **browser's macOS-VideoToolbox HEVC hardware decoder** mangling high-motion
frames. The bitstream we deliver is already clean; nothing server-side (encoder
config, framing, feedback, tunnel) is wrong. Proof, all in ONE session on ONE
hard-swipe drive (`--userspace`, `--ltrp` off), so no cross-session confound:

| what was decoded | decoder | result |
| --- | --- | --- |
| server Annex-B dump (every AU) | ffmpeg (software) | **CLEAN**, 0 errors, 4822 frames |
| exact `/stream.bin` bytes the browser received (reconstructed) | ffmpeg (software) | **CLEAN**, 0 errors |
| that same `/stream.bin` content, live | browser WebCodecs (VideoToolbox HW) | **MOSAIC** |
| that same content, paced replay, fresh decoder, no rebuilds | browser WebCodecs (HW) | **MOSAIC** |

So: the browser receives clean, gapless, ffmpeg-decodable HEVC and still tears —
it is purely the HW decode step. Confirmed further:

- **No software fallback exists.** `VideoDecoder.isConfigSupported({hardwareAcceleration:'prefer-software'})`
  = **false** for HEVC in this Chrome; `configure` with it throws. Only HW decode is available.
- `optimizeForLatency` true **and** false: both mosaic. hvcC **and** Annex-B config: both mosaic.
  So no WebCodecs knob avoids it.
- `--ltrp` **amplifies** it (long-term refs the HW decoder mishandles) → keep `--ltrp` OFF, but
  no-ltrp still tears under hard motion (my earlier "no-ltrp is clean" was from scripted swipes,
  which under-reproduce; hand-driven still tears).
- Prior finding stands: MSE + fMP4 also tears — same platform HW decoder, different browser API.
- The broadcast path does **not** drop AUs (0 queue-overflow/needs_key events in the log during
  the tear), and the browser decode queue never backed up (`decodeQueueSize` maxed at 0), so it's
  not drops, backpressure, rendering, or IOSurface churn.

**Why Xcode is clean:** Xcode decodes with *native VideoToolbox* (its own decode-session config),
which handles the exact same content cleanly — as does ffmpeg (software). The browser's WebCodecs
VideoToolbox path is the weak link, and WebCodecs doesn't expose the knobs to fix it. So a browser
viewer **cannot** be made xcode-identical from our side; the input is already correct.

**The path to xcode-quality (native/software decode, not the browser):**

- **serve-vnc** decodes with software libav (PyAV/`HevcToBgraTranscoder`) → RFB → macOS Screen
  Sharing. Software decode = clean like ffmpeg, so serve-vnc should be tear-free under motion.
  This is the existing "xcode-like" path — VERIFY it's clean and point users there.
- Or a small native-decode helper (native VideoToolbox / ffmpeg) feeding the browser as raw frames
  (heavier; only if a browser front-end is required).

### Superseded browser-side ideas (would NOT help — the browser input is already clean)

1. Real RTP timestamps on `EncodedVideoChunk` instead of synthetic `+=16666`.
2. Decode-queue backpressure (queue never backs up; `decodeQueueSize`==0).
3. Render via `requestVideoFrameCallback` / `<video>`+MediaStreamTrackGenerator
   or WebGL, instead of closing/redrawing HW `VideoFrame`s on a 2D canvas (the
   current close-per-frame churns the decoder's IOSurface pool under motion).
Test each with HAND-DRIVEN motion, `--ltrp` off.

Everything else below (hvcC, RR+SDES, RCTL closed-loop, PLI-storm fix, the
Xcode-competes-for-the-conference stall finding) stands.

## TL;DR (historical — the residual "tear" referenced below IS the LTRP mosaic)

- **Stalls / freezes / the recurring "no AU progress → restart" were caused by
  running Xcode's screen mirroring at the SAME TIME as serve-web.** The device
  supports a single screen-mirror conference; two clients (Xcode + serve-web)
  compete and the device keeps reaping one (`vcMediaStreamStopConference` every
  ~20 s). **serve-web running ALONE is stable: 0 reaps, 0 stalls.** Always quit
  Xcode mirroring before testing serve-web.
- **The residual is mild tearing under rapid motion, cleared quickly by keyframes.
  Its root is NOT yet pinned.** Safari was *initially* thought tear-free, but that
  was an artifact of Safari running at ~4 fps (too few frames to show motion
  tearing). Once hvcC gave Safari good fps, **Safari ALSO tears** — so it is NOT
  Chrome-specific. Both browsers (both VideoToolbox) tear at good fps, while
  ffmpeg (software decode) shows only "mild soft/ghosting on moving elements" in
  the same bitstream. Leading theory now: **encoder-side motion artifact baked
  into the bitstream** (matches ffmpeg), and/or a VideoToolbox real-time-decode
  artifact common to both browsers — NOT a Chrome decode-path bug as first
  thought. NEEDS RE-VERIFICATION (see next steps).
- Everything below is committed and pushed on the feature branch.

## Commits (this line of work)

```
c34808c  serve-web: decode via hvcC instead of Annex-B (WebCodecs standard path)
497f881  serve-web: RTCP RR as a proper RR+SDES compound (Xcode parity)
d78b417  remotexpc: serialise send_receive_request with a per-connection lock
731b014  serve-web: stop the self-reinforcing PLI storm on static screens
ac03623  serve-web: closed-loop encoder rate control via reverse-engineered RCTL
```

Backup tag before the history rebase: `backup-before-rebase-2026-07-07`.

## What each change does / why

- **`d78b417` remotexpc lock** — `RemoteXPCConnection.send_receive_request` is a
  write-then-read over one shared reader + `_previous_frame_data` buffer with no
  demux. Two concurrent callers interleave reads → `0 bytes read on 9 expected`
  → the connection wedges permanently. An earlier XPC-based keepalive hit exactly
  this and froze the whole server. The `asyncio.Lock` serialises round-trips.
  (This is a general latent bug, not serve-web-specific.)
- **`497f881` RR+SDES** — Xcode always sends RTCP as an `RR + SDES/CNAME`
  compound (`81 ca 0002 <ssrc> 01 00 00 00`); we sent a bare RR. RFC 3550 §6.1
  requires the SDES. Device now attributes our RTCP (`didReceiveRTCPPackets`
  500+×/run). Did NOT change stall behaviour (the stalls were Xcode competing),
  but it's correct and Xcode-matching.
- **`731b014` PLI motion-window** — the decoder-refresh motion detector summed
  `_au_byte_window` including forced-IDR bytes, so one refresh IDR read as
  "motion" and triggered the next → self-reinforcing PLI storm on a static
  screen. Now counts delta AUs only.
- **`c34808c` hvcC** — viewer was configuring WebCodecs with no `description` and
  feeding Annex-B start codes → Chrome per-chunk H.265→hvcC conversion → tears
  under motion. Now: `hevc_decoder_configuration_record()` builds the hvcC from
  cached VPS/SPS/PPS, `/stream.bin` sends 4-byte-length-prefixed NALUs, `/codec`
  returns `{codec, description(b64)}`, viewer configures with the description.
  Reduced the tear (clears faster) but did **not** eliminate it.

## Ruled out as the tear cause (all tested on-device)

- **Packet loss** — 0 RTP gaps during motion on the kernel tunnel.
- **RTCP keepalive / conference reap** — the reap was Xcode competing, not us.
- **Canvas render tearing** — viewer.js already draws in a `requestAnimationFrame`
  loop (vsync-locked) and resets the canvas buffer per frame.
- **LTR-ACK / control-channel keepalive** — dead ends; see history.
- **Chrome-specific decode path** — DISPROVEN. Safari also tears once at good fps.

## NOT ruled out (leading suspects for the residual tear)

- **Encoder quality collapse under motion** — real (QP 16→35, drop_fps up to 31 at
  the 5.49 Mbps ceiling). `--ltrp` greatly improves it (QP→~19, drops→~1) but the
  user still saw tears with `--ltrp`. Still, the QP collapse / high drop_fps is the
  best mechanical candidate and its interaction with the tear isn't fully closed —
  re-test `--ltrp` visually with fresh eyes and measure whether the *visible* tear
  tracks QP/drops.
- **Encoder-inherent motion artifact in the bitstream** — ffmpeg shows "mild
  soft/ghosting on moving elements" in the same stream. Both browsers tear at good
  fps. Re-verify (below) whether the browsers' "tear" is that same in-bitstream
  ghosting amplified in real time, or something the browsers add.

## The remaining problem

Rapid-motion tearing in BOTH Chrome and Safari (at good fps), cleared quickly by
the proactive PLI keyframes. Root not pinned; leading theory is encoder-side
motion artifact (see above), NOT a browser decode-path bug. hvcC (c34808c) gave
Safari good fps and made the tear clear faster, but didn't eliminate it.

**Re-verify first thing next session:** capture the CURRENT stream with
`PMD3_SERVE_WEB_DUMP=/tmp/dump.hevc` (dump is still Annex-B) under rapid motion,
decode with `ffmpeg -i /tmp/dump.hevc -f null -` and view the frames. If ffmpeg
shows the tear → it's in the bitstream (encoder) → focus on encoder config
(`--ltrp`, bitrate/RCTL, GOP). If ffmpeg is clean but both browsers tear → it's a
real-time VideoToolbox decode/render effect → focus on the browser/render side.

## Current knobs

- `--ltrp` — OFF by default; big encoder-QP win under motion on a low-loss
  transport (kernel tunnel). Left opt-in because LTR can make a *lost* reference
  tear longer on lossy transports (`--userspace`, LAN).
- Proactive PLI refresh (decoder-refresh: motion + settle + heartbeat) — KEPT. It
  clears the residual tear. Removing it entirely → tears don't clear.
- `--rctl` / `--max-bitrate` — RCTL receiver feedback. NOTE: the RCTL frames
  counter resets on stream restart, which can make the device compute bogus
  packet loss (up to 92% → throttle). Rare now that reaps are gone, but if you
  see PLR spikes in `AVCRateController` health, make `_rtp_frames_received`
  monotonic across restarts.

## Next things to try (highest-leverage first)

0. **RE-VERIFY where the tear lives** (do this first — the Chrome-specific theory
   was wrong): `PMD3_SERVE_WEB_DUMP=/tmp/dump.hevc` under rapid motion, then
   `ffmpeg` / a player on `dump.hevc`. In-bitstream tear → encoder; clean →
   real-time decode/render. Everything below branches on this.
1. **If encoder-side:** re-test `--ltrp` visually (QP 35→19, drops 31→1 — should
   reduce it), then tune the encoder budget: raise the target bitrate and/or fix
   the RCTL bogus-loss throttle (monotonic `_rtp_frames_received`), and revisit
   GOP/keyframe cadence. This is the path to actually matching Xcode.
2. **If real-time decode/render:** both browsers use VideoToolbox, so it's the
   real-time hardware-decode + canvas presentation under motion. Try
   `optimizeForLatency:false`, real RTP timestamps on `EncodedVideoChunk` (instead
   of synthetic `+=16666`), decode-queue backpressure (`decoder.decodeQueueSize`),
   and WebGL/`requestVideoFrameCallback` rendering instead of 2D canvas.
3. **Full Xcode model (once tear is understood):** `--ltrp` default-on **+** drop
   the proactive PLI storm together, matching Xcode's zero-PLI approach.

NOTE: the earlier "Safari is clean → Chrome-specific" conclusion was WRONG —
Safari's clean look was its 4 fps hiding the motion. Don't build on it.

## How to test (important gotchas)

- **Quit Xcode mirroring first** — otherwise you reproduce the (non-bug) reap.
- Use the **kernel tunnel** (`--tunnel ""`, tunneld running) — low loss.
- Device wedges after many stream restarts in a session → recover with
  `pymobiledevice3 diagnostics restart` (no flags; device reboots ~35–45 s).
- Encoder truth is in device syslog: `pymobiledevice3 syslog live` →
  `VCPEncStatsMonitor` (Avg_QP, drop_fps, Bit_rate), `AVCRateController` health
  (Uplink PLR, actual/target bitrate), `vcMediaStreamStopConference` (reaps),
  `didReceiveRTCPPackets` (our RTCP being attributed).
- **Safari vs Chrome** is the fast diagnostic for "is the tear in the bitstream
  or the browser": Safari uses VideoToolbox directly.
- ffmpeg-decoding a `PMD3_SERVE_WEB_DUMP` capture (still emitted as Annex-B) tells
  encoder artifacts (present in ffmpeg) from browser-decode bugs (not in ffmpeg).
