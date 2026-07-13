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

## Code map
serve-vnc / serve-web live in
`pymobiledevice3/remote/core_device/{screen_stream,vnc_server,display_service,media_stream_offer,vt_jpeg}.py`.
Prior encoder/rate-control investigation: `SERVE_WEB_NOTES.md` (same dir).
