# Screen-mirror anti-tear: VideoProcessing/AVConference RE roadmap

Working notes for eliminating the heavy-motion **tearing / smearing** in `serve-vnc`
and `serve-web` (CoreDevice `com.apple.coredevice.displayservice`, RTP/HEVC over the
utun tunnel). Reference target: Apple's Xcode **DeviceHub** "View Screen", which
**never tears** on the identical device + motion.

Environment these notes were taken on: **macOS 26.5.2 (build 25F84)**, Apple Silicon.
dyld-shared-cache offsets below are from this build; re-derive by symbol name on others.

---

## 1. What is NOT the cause (established, with evidence)

Do not re-litigate these — each was tested to ground truth this investigation:

| Suspect | Verdict | Evidence |
|---|---|---|
| Encoder / bitrate / QP | parity, ruled out | DeviceHub encoder telemetry under the user's real hard motion ≈ pmd3's: QP avg ~33 / max ~36, drop ~26, ~5.5 Mbps. `syslog live -pn avconferenced` (VCPEncStatsMonitor / AVCRateController). |
| Network (loss / reorder) | clean, ruled out | utun video-pcap offline analysis: **0.00% out-of-order, 0.00% forward-gaps**, 0% loss. |
| Assembled bitstream | valid, ruled out | ffmpeg decodes pmd3's Annex-B dump **CLEAN** offline (0 errors). |
| Codec / negotiation / LTRP toggles | not the differentiator | brute-forced across sessions; DeviceHub renders the *same* degraded stream clean. |
| **Decoder session API (VT vs VCP)** | **not the fix** | swapping `VTDecompressionSession` → `VCPDecompressionSession` (this branch) does not fix it, and can't touch serve-web at all (browser decodes). |

**Render-parity A/B is the linchpin:** DeviceHub receives the same QP33 / 26-drop stream
and renders sharp icons mid-transition; pmd3 tears on **both** paths — serve-vnc (native
VideoToolbox) and serve-web (browser WebCodecs). Since the two paths share almost no
*decode* code but both tear, the defect is upstream of the decoder, in the code they DO
share in spirit: **RTP receive → AU assembly → decode-feed cadence → PLI/refresh policy.**

### Conclusion / thesis to prove
The anti-tear behaviour lives in Apple's **`VideoReceiver` / `VCVideoPlayer`** layer
(jitter buffer + DisplayLink-paced playout + decode/display decoupling + near-zero PLI),
**above** the decompression session. That layer is what to reverse next.

---

## 2. The VCP decoder experiment (this branch)

Toggle `PMD3_USE_VCP=1` swaps the raw VideoToolbox entry points for
VideoProcessing.framework's `VCPDecompressionSession*` in `vt_jpeg.py` (default off →
byte-identical to the VT path). Wired but **not a fix** — kept for continued study.

Findings worth keeping:
- **ABI-identical to VT.** `VCPDecompressionSessionCreate/DecodeFrame/Invalidate` take the
  same args as their `VT*` counterparts; the VT `argtypes` bind verbatim.
- **NULL decoderSpec crashes VCP.** Unlike `VTDecompressionSessionCreate` (which tolerates a
  NULL decoderSpecification), `VCPDecompressionSessionCreate` calls `CFDictionaryGetValue()`
  on it **unconditionally** → SIGSEGV in `CFDictionaryGetValue` (`+0x1814`). Fix: pass an
  **empty but valid `CFDictionary`**; VCP reads optional keys (`AllowClientProcessDecode`,
  `NumberOfTiles`, …) and falls back to defaults. The 5th arg (callback record) is copied
  via `*(_OWORD*)(session+28) = *a5`, so it must be non-NULL.
- **Cache-only dlopen.** VideoProcessing has no on-disk dylib → `ctypes.util.find_library`
  returns None. dlopen the **full framework path**:
  `/System/Library/PrivateFrameworks/VideoProcessing.framework/VideoProcessing`.
- **Decodes synthetic I- and P-frame streams fine** (VT and VCP both clean on ffmpeg
  `testsrc` all-intra and IPPP clips).
- **UNRESOLVED: freezes on the real device stream at the first frame.** IDR decodes and
  displays; subsequent P-frames render nothing. Not reproducible with synthetic clips →
  the trigger is something in the real stream (suspected **LTRP long-term references**
  and/or the live async-callback threading) that `testsrc` does not emit. Debug via the
  dump harness in §5.

---

## 3. Decompilation HOW-TO (the tooling that actually works)

Hard-won; earlier approaches produced false conclusions or timed out.

### Extracting a framework from the dyld shared cache
```
ipsw dyld extract <shared-cache> <framework-path> --output <dir> --objc --slide
```
- `--objc --slide` = usable symbols + real addresses. **Skip `--stubs`** (too slow / times out).
- `ipsw dyld disass` and `--stubs` disassembly are too slow for interactive work — don't.

### ⚠️ The branch-island stub trap (caused a false conclusion)
Standalone extracted binaries contain DSC **branch-island stubs**: intra-cache calls are
compiled as relative jumps `libA → island → libB → fn` instead of indirect jumps. A naive
disassembler mis-symbolicates these, making unrelated symbols look "called" — this is why
an earlier pass wrongly concluded "VCP is coupled to HomeKit / MediaAnalysis and not
viable." It is **not**: VCP is pure CoreMedia / VideoToolbox. Resolve stubs by analysing
**in-cache** (IDA's dsc loader) rather than trusting the standalone binary's jumps.

### IDA Pro MCP (mrexodia `ida-pro-mcp:idalib`) — the workhorse
idalib rejects the raw cache and reports "hexrays not available" in-cache via the CLI, but
the **MCP** gives clean, in-cache-quality decompilation:
- `idb_open` (opens/adopts a session; force headless) → returns a `session_id`.
- **Every** subsequent call must pass `database=<session_id>`.
- Useful ops: `decompile` (needs `addr`), `analyze_function`, `xrefs_to`, `callees`,
  `search_text` (regex over disasm+comments), `lookup_funcs` (needs `queries: [..]`),
  `list_funcs`, `imports`, `get_string`.
- Exported functions may not appear in `lookup_funcs`; find them with `search_text` on the
  symbol name, then `decompile` the hit address.

### Sessions used this investigation (re-open with `idb_open`)
- **AVConference**: `/System/Library/PrivateFrameworks/AVConference.framework/AVConference`
- **VideoProcessing**: `/System/Library/PrivateFrameworks/VideoProcessing.framework/VideoProcessing`

---

## 4. Symbols already mapped (starting points)

VideoProcessing (this build; re-derive by name elsewhere):
- `_VCPDecompressionSessionCreate` @ `0x1b18345a8` — signature + empty-decoderSpec
  requirement + callback-record copy (`*(session+28)=*a5`). Calls `sub_1B1835088` (the real
  decoder-init) with `(allocator, formatDesc, decoderSpec, destImageAttrs, session)`.
- Decoder-init `sub_1B1835088` — huge; reads decoderSpec keys via `CFDictionaryGetValue`
  (`NumberOfTiles`, …), builds pixel-buffer pools, color transfer, stats monitor.

AVConference (from prior passes — re-confirm addresses):
- `VideoDecoder_NewFormat_InitDecoder` (~`0x1bd77f600`) — builds the decoderSpec dict:
  keys `AllowClientProcessDecode`, `DecPixelFormat`, `EncodeMVHEVC`, `NegotiationDetails`,
  `NumberOfTiles`.
- `VideoDecoder_DecodeFrame` — **decodes every frame**, *waits*
  (`VCPDecompressionSessionWaitForAsynchronousFrames`), and skips **display** (not decode)
  via `kVTDecodeFrame_DoNotOutputFrame`. Decode is decoupled from display.

---

## 5. ROADMAP — what to reverse next

The fix is in **receive + playout**, not decode. Priority order:

1. **`VideoReceiver` / `VCVideoReceiver` (AVConference) — the jitter buffer.**
   Device syslog shows `VCJitterBuffer`; pmd3 has **none**. Reverse: packet → AU assembly,
   how it tolerates reorder/jitter (vs pmd3 declaring whole-AU-corrupt), and how/when it
   hands an AU to the decoder. Compare to `screen_stream.py` `_udp_recv_and_depacketize`
   and `vnc_server.py` `_udp_recv_and_pipe`.

2. **`VCVideoPlayer` — DisplayLink-paced playout.**
   The decoded-frame presentation schedule: DisplayLink callback → which buffered decoded
   frame to *show* now, and how it holds/repeats under variable decode latency. This is the
   `decodeFrame:showFrame:` decoupling. pmd3 shows every frame as soon as decoded (synthetic
   `+=16666` PTS) — likely the tear source under bursty motion.

3. **PLI / keyframe-request policy.**
   Hypothesis: DeviceHub sends **zero PLI** and *conceals* rather than requesting recovery;
   pmd3 fires PLI + decoder-refresh aggressively, and that reset churn may itself corrupt
   the live decode ("smear then fix" = the PLI-triggered IDR clearing it). Find where
   AVConference decides to request a keyframe on the screen-mirror path — confirm if ever.

4. **Frame pacing / PTS.** Diff Apple's playout timestamps against pmd3's synthetic PTS.

---

## 6. Reproduction & verification harness

- **Capture real device Annex-B** (perfect offline fixture; serve-web ships the same device
  AUs even though it renders via WebCodecs):
  ```
  PMD3_SERVE_WEB_DUMP=/tmp/dump.hevc pymobiledevice3 developer core-device display serve-web --userspace
  ```
  Move the device under hard motion, then replay `dump.hevc` through `HEVCDecoder`
  (`vt_jpeg.py`) with `PMD3_USE_VCP=1` to reproduce the VCP freeze offline.
- **Confirm decode backend live:** `vt_jpeg` logs `decode backend: VT|VCP (...)` at session
  create.
- **Tear detection** (screenshots miss transient tears — capture timing lands in settled
  gaps): `screencapture -v -V <secs> -R <rect>` → `ffmpeg fps=4` → `tile=6x4` grid.
- **Motion driver:** serve-web viewer "Swipe ←/→" buttons clicked rapidly (~190×/14 s)
  saturates the encoder (QP 34, drop 30). Synthetic touch under-reproduces real hand motion.
- **DeviceHub reference:** Xcode → right-click device → **View Screen** (right-click →
  stop stream to end). Observe its RTP on utun5 (sudo-less pcap) + `log stream`.

---

## 7. RECEIVER ARCHITECTURE — DECODED FROM DEVICEHUB (2026-07-15)

Ground truth from a real DeviceHub "View Screen" session (Mac unified log
`ref_devicehub/mac_unified.log` + AVConference decompile, build 25F84,
imagebase `0x1bd636000`). **This is the anti-tear design to port.**

### Where it runs (confirmed)
DeviceHub (Mac, the RECEIVER) drives AVConference via `AVCVideoStream` →
`VideoReceiver` (assembly + jitter queue) → `VCVideoPlayer` (paced playout) →
`VCImageQueue` (CA display). The device (`avconferenced`) is only the SENDER
(`VCVideoStream` + rate adaptation). So the anti-tear logic is entirely in the
**Mac-side AVConference receiver** — the same role pmd3 plays.

### DeviceHub receiver telemetry under the user's motion (the recipe)
`VideoReceiver` Health (`_VideoReceiver_ReportingRegisterPeriodicTask`):
- `videoJitterQueueSize = 100.0 ms`, steady (`numOfJitterQueueSizeChanges=0`,
  `averageJitterQueueSize≈100 ms`) — **a 100 ms receiver-side jitter queue.**
- `frameErasureCount=0`, `videoStallTime=0 ms`, `significantOutOfOrderPacketCount=0`.
- `decodedFrameCount == decodedFullFrameCount` every window (105==105, 111==111)
  — **every decoded frame is a FULL frame; zero partial/concealed frames.**
- effective `videoRxAvgFrameRate ≈ 20–23 fps` (encoder offers 60; it plays what
  arrives, paced — it does NOT try to hit 60 by dropping).

`VCVideoPlayer` Health (`_VCVideoPlayer_HealthPrint`):
- `tickInterval=0.005556` (180 Hz display-link tick).
- `numAlarmsEnqueuedForDecode == …ProcessedForDecode == …ForDisplay ==
  …ProcessedForDisplay`, `numAlarmsDropped=0`,
  `alarmsSentForDecodeButNotDisplayedCount=0` — **drops zero frames.**
- `targetJitterBufferInSeconds=0`, `playbackOffsetInSeconds=0` — the 100 ms lives
  in the receiver queue, not as extra playout latency.

Stream config (CoreDevice `MediaStreamConfig`): `IsltrpEnabled: true`,
`JitterBufferMode: 1`, `KeyFrameInterval: 0`, `Framerate: 60`, 832×1792.

RTCP: **`FIR=0` for the entire session** — DeviceHub **never sent a Full Intra
Request / keyframe request**, even under heavy motion (`Lost=1`, `Jitter=0`).

### The playout scheduler (decompiled)
`_VideoReceiver_AssembleAndEnqueueFrame` → `_VCVideoPlayer_QueueAlarmForDecode`
→ `__VCVideoPlayer_QueueAlarm` @ `0x1bd75351c` (shared with `…ForDisplay`).
Playout thread `_VCVideoPlaybackAlarmThread`; display side
`__VCVideoPlayer_CheckAndProcessDisplayAlarms` @ `0x1bd754524`.

`_VCVideoPlayer_QueueAlarm(player, alarmType, _, _, rtpTimestamp, frameSeq,
flags, videoFrameTimeInSeconds)`:
- Two **sorted singly-linked alarm lists** on the player struct: decode
  (head @ +368, count @ +704) and display (head @ +376, count @ +712).
- Each alarm is inserted **in presentation-time order** — the insert loop walks
  the list comparing `videoFrameTimeInSeconds` then `rtpTimestamp` deltas. This
  is where **packet/frame reordering is absorbed**: frames go out in order
  regardless of arrival order.
- Decode alarms are scheduled **ahead of** display alarms; the gap is bounded by
  a threshold (`alarmsSentForDecodeButNotDisplayedCount` @ +428 vs limit @ +600)
  — decode-ahead without runaway.
- **No drop path** in this function. Late/early is handled by *when* the alarm
  fires (paced by the display-link clock), not by discarding frames.

### The design in one line
**100 ms jitter queue → insert every frame in presentation-time order → decode
every frame fully, ahead of display → present on the 180 Hz display-link clock →
never drop, never conceal, never request a keyframe.**

### pmd3 does the opposite on every axis (the fix plan)
| Axis | DeviceHub | pmd3 today | Fix |
|---|---|---|---|
| Jitter queue | 100 ms, steady | none (feed AU as assembled) | add a ~100 ms presentation-time-ordered queue before decode |
| Frame dropping | zero (`numAlarmsDropped=0`) | VT `1xRealTimePlayback` may drop; WebCodecs drops | decode EVERY frame; drop display, never decode |
| Playout pacing | 180 Hz display-link, sorted alarms | show-as-decoded, synthetic `+=16666` PTS | present on a steady clock from the queue, in RTP-ts order |
| Keyframe requests | `FIR=0` (never) | aggressive PLI + decoder-refresh | stop PLI/refresh churn on transient gaps (conceal, don't reset) |
| LTRP | on | on/off toggled | keep on (efficient), but the decoder must handle LTR refs — the VCP freeze (§2) is likely here |

Order to try (cheapest → deepest): (1) kill the PLI/decoder-refresh churn and
re-test — DeviceHub proves a clean stream needs none; (2) add the 100 ms
presentation-ordered jitter queue feeding an every-frame decode; (3) add
display-link-paced playout. The earlier `--jitter-ms 200` test failed likely
because it lacked (1) and (4) never-drop, and 200 ≠ 100 ms; the axes are
coupled — a jitter queue alone, with PLI churn still firing and frames still
dropping, won't reproduce the result.

### Key symbols (AVConference, build 25F84, imagebase 0x1bd636000)
- `_VideoReceiver_AssembleAndEnqueueFrame` — AU assembly + enqueue (huge; reverse
  next for the exact reorder-tolerance + whether it EVER requests a keyframe).
- `__VCVideoPlayer_QueueAlarm` @ `0x1bd75351c`, `_VCVideoPlayer_QueueAlarmForDecode`
  @ `0x1bd753500`, `__VCVideoPlayer_CheckAndProcessDisplayAlarms` @ `0x1bd754524`,
  `_VCVideoPlaybackAlarmThread`, `_VCVideoPlayer_HealthPrint`.
- `_VideoReceiver_ReportingRegisterPeriodicTask` — the Health telemetry emitter.
- IDA session: `idb_open` on `re/AVConference` (was `b08b0109` this run).

---

## 8. COMPLETE RECEIVER REVERSE (2026-07-15) — every decision point

Full decompile pass over the AVConference VideoReceiver (build 25F84,
imagebase `0x1bd636000`). This is the whole receive→display pipeline and the
four decisions that make it never tear. **The RE is done; §9 is the fix.**

### Data flow / call graph
```
RTP in → VideoPacketBuffer (per-frame packet assembly, RS-FEC)
  → _VideoReceiver_ScheduleFramesForVideoPacketBuffer
    → _VideoReceiver_AssembleAndEnqueueFrame            (assemble 1 frame)
        _VideoPacketBuffer_GetNextFrame                 (next in order)
        _VideoReceiver_CalculateFrameErasures           (missing-data metric)
        VCVideoJitterBuffer_{GetIsRunning,GetTargetJitterQueueSize,GetReferenceFrame}
        _VCVideoPlayer_{UpdateJitterBufferState,SetTargetQueueSizeInSeconds}
        _VCVideoPlayer_QueueAlarmForDecode  ───────────┐  (schedule decode)
  ── VCVideoPlaybackAlarmThread (fires alarms by clock) ┘
    → _VideoReceiver_DequeueFromOrderedFrameForDecodeQueue  (a.k.a. DequeueAndDecode)
        decode in DECODING ORDER  → VCP/VT decompress
    → _VideoReceiver_DecoderCallback (decode output)
        _VideoReceiver_CheckAndRequestKeyFrame  (only if frame flagged bad)
        _VCVideoPlayer_QueueAlarmForDisplay     (schedule display)
    → _VideoReceiver_ShowFrame  (present CVPixelBuffer to CA/VCImageQueue)
```

### Frame struct offsets (from ShowFrame + QueueAlarm decompiles)
`+16` CVPixelBuffer · `+24` rtpTimestamp · `+28` frameSeq · `+44` tileIndex ·
`+48` streamID · `+64` streamID(16) · `+66` **shouldShowFrame** · `+67`
**needsKeyFrame** (assemble/decode-failed flag) · `+70` isBaseLayer · `+88`
CMTime presentationTimestamp.

### The four decisions — verdicts

**A. Assembly** (`_VideoReceiver_AssembleAndEnqueueFrame`): pulls the next frame
in order from `VideoPacketBuffer`, computes erasures (missing sub-data) as a
*metric*, updates the `VCVideoJitterBuffer` state / target queue size, and
enqueues a **decode** alarm (`QueueAlarmForDecode`). Erasure ≠ drop: a frame is
still enqueued; erasure only feeds reporting and the needs-keyframe flag.

**B. Decode** (`_VideoReceiver_DequeueFromOrderedFrameForDecodeQueue`): dequeues
in **decoding order** ("Dequeuing decodingOrder=%d") and decompresses. Decode is
scheduled *ahead* of display (§7 alarm counts), so the decoder always runs early
— nothing is dropped to keep pace.

**C. Keyframe request** (`_VideoReceiver_CheckAndRequestKeyFrame` @ `0x1bd78cccc`
→ `_VideoReceiver_DecoderRequestKeyFrame` @ `0x1bd7987e0`):
- Gate: proceeds **only if `frame+67 (needsKeyFrame) == 1`** — a flag set by the
  decoder callback on a genuine decode/assemble failure. NOT on packet gaps, NOT
  on reorder, NOT periodically.
- Dedup: skips the FIR if "a more recent key frame ... has already been
  assembled" (compares against `receiver+43376`, last-keyframe timestamp).
- reason enum `kVCKeyFrameRequestReasonStrings` (`0x1e72ff460`); this path passes
  reason 18 (decode failure), 27 if temporal-scaled base layer.
- Net: on a clean stream (wire is 0% loss) the gate never trips → **FIR=0**,
  matching telemetry.

**D. Display** (`_VideoReceiver_ShowFrame` @ `0x1bd794b20`):
- Gate: shows only if **`frame+66 (shouldShowFrame) == 1`** — decode-ahead /
  reference-only frames are decoded but *not* displayed (the `decodeFrame:
  showFrame:` decoupling).
- **Starvation → repeat, never blank:** if the next frame's rtpTimestamp equals
  the last shown (no new frame ready), it logs a **"Microstall"** and re-shows
  the current CVPixelBuffer. No blanking, no tearing, no drop.
- Hands the CVPixelBuffer to a display callback (`receiver+1616`) with the CMTime;
  `videoFrameErasureCount = videoFramesExpected − shown` is reporting only.

### Jitter buffer
Real class **`VCVideoJitterBuffer`** (`GetIsRunning`,
`GetTargetJitterQueueSize`, `GetReferenceFrame`), driven from assembly via
`_VCVideoPlayer_{UpdateJitterBufferState,SetTargetQueueSizeInSeconds,
SetReferenceRTPTimestamp}`. Telemetry: steady **100 ms** target
(`JitterBufferMode=1`).

### Invariants that produce "never tears" (all confirmed in code + telemetry)
1. Frames assembled and decoded **in order**; presentation-time-sorted alarm
   lists absorb any reorder.
2. **Every frame is decoded fully** (erasure is a metric, not a skip).
3. **Decode runs ahead of display**; display is gated by `shouldShowFrame`.
4. **Starvation repeats the last frame** (microstall) — never blank/drop.
5. **Keyframe requested only on a real decoder-reported failure**, deduped —
   never on gaps/reorder/timers.
6. ~100 ms jitter queue smooths arrival jitter before decode.

---

## 9. Fix plan for pmd3 (unchanged thesis, now fully evidenced)
See §7 table. Order: (1) stop pmd3's PLI/decoder-refresh churn — gate any
keyframe request on a real decode failure + dedup, exactly like decision C;
(2) never drop a decode (drop *display*, not *decode* — decision B/D);
(3) ~100 ms presentation-ordered jitter queue (decision A) + repeat-last on
starvation (decision D). The axes are coupled; do them together.

---

## Code map
serve-vnc / serve-web live in
`pymobiledevice3/remote/core_device/{screen_stream,vnc_server,display_service,media_stream_offer,vt_jpeg}.py`.
Prior encoder/rate-control investigation: `SERVE_WEB_NOTES.md` (same dir).
