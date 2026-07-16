# Screen-mirror motion tear — findings

## The symptom

CoreDevice DisplayService (`com.apple.coredevice.displayservice`) streams the
device screen as RTP/HEVC over the utun tunnel; `serve-vnc` and `serve-web`
render it. Under heavy on-device motion the picture progressively **smears**:
icons stay legible but blocky garbage drifts across the frame and accumulates
over successive frames. Apple's Xcode **DeviceHub** "View Screen" renders the
identical device and motion with **no tear** — it is the reference target.

## What was discovered

Every plausible cause on the pymobiledevice3 side was eliminated, each proven,
and the differentiator was localized to Apple's own decoder process:

- **Not the encoder / bitrate / QP** — DeviceHub's encoder telemetry under the
  same hard motion matches ours (QP ~33/36, ~5.5 Mbps).
- **Not packet loss or reorder** — a capture of DeviceHub's own RTP is perfectly
  sequence-contiguous (15342 packets, zero gaps, zero reorder).
- **Not depacketization** — our RFC-7798 output is byte-identical to ffmpeg's,
  and a fresh correct re-depacketization of the RTP is byte-identical to the
  stream DeviceHub decoded.
- **Not the bytes / not bitstream patching** — `avconferenced`'s *actual* fed
  access units (dumped live from its decoder) are **byte-for-byte identical** to
  our depacketization of the concurrent RTP, for every frame compared.
- **Not keyframe requests** — the device ignores RTCP PLI for refresh; it honors
  FIR (PT=206 FMT=4, requires `allowRTCPFB`) and emits IDRs on request, but
  periodic IDR cannot outrun the drift. Neither removes the tear.
- **Not IDR cadence** — a confirmed-clean live session ran 1588 frames with zero
  IDRs; the smearing capture has a single IDR. Same regime, opposite result.
- **Not decoder configuration** — `avconferenced`'s complete decode config was
  captured and replayed exactly (see below) → identical smear.
- **Not HW vs SW decoder** — forcing Apple's software VideoToolbox decoder
  (verified the mode switched) → identical smear.
- **Not real-time pacing** — a 16.6 ms-paced feed produces the identical smear;
  decode of complete bytes is deterministic.

The one bitstream oddity found: DisplayService appends a **constant 14-byte
footer** (`04f00ac0000003000004ec0ab003`) after the final fragment of each
coded-slice NAL. `avconferenced` strips it before decode; a plain reassembly
would feed it as trailing slice data. It is **not** the cause (decoders ignore
trailing bytes after the slice data — stripping it does not change the decode)
but it is malformed, so the depacketizer now drops it.

### The decoder configuration that was captured and replayed

Captured from `avconferenced` and replayed verbatim against the smearing
stream — all reproduce the identical smear:

- Per-frame call `VTDecompressionSessionDecodeFrameWithOptions`, `flags=0x1`
  (async), options `{ActiveVideoResolution, CalculateYUVChecksum=0,
  ContentAnalyzerCropRectangle, ExtraInLoopChromaFilter=0}`.
- VCP create spec `{NegotiationDetails="VRAE:0;SW:1;FLS", NumberOfTiles=1}`.
- VCP-level properties `NegotiationDetails`, `DecoderUsage=0`, `FaceZoom=0`,
  `MLEnhance=0`, `MLVideoEnhance=0`, `Disable270MLScale=1` — all conferencing
  feature toggles, none touching reference handling or concealment.
- VT session properties `Rotation`, `EnableGPUAcceleratedTransfer=0`,
  `WriteBlackPixelsOutsideDestRect=1`, `ScalingMode=Trim`, thread-priority — all
  display/geometry.

There is no reference-management or error-concealment knob anywhere in it.

## How it was discovered

- **Wall-clock-aligned two-sided capture** — screen-recorded the DeviceHub
  window while capturing its RTP on the utun. Frames that are clean in the
  DeviceHub window at instant *T* smear when the exact concurrent bytes are
  decoded by every standalone decoder.
- **RTP sequence-continuity analysis** — parsed the raw RTP dump to prove zero
  packet loss (no sequence gaps, marker count = frame count).
- **lldb hardware breakpoints** on `avconferenced` — the tooling unlock:
  software breakpoints never fire on dyld-shared-cache functions, hardware ones
  do. Used to capture the exact per-frame decode call, its options dictionary,
  the `VTDecompressionSessionCreate`/`VCPDecompressionSessionCreate` spec, and
  every `VTSessionSetProperty` / `VCPDecompressionSessionSetProperty` call.
  (frida was rejected by AMFI library-validation even as root under SIP-off.)
- **Low-perturbation fed-AU dump** — an lldb Python breakpoint callback that
  auto-continues (never stops the target), copying each fed `CMSampleBuffer`'s
  bytes and `rtpTimestamp` out via CoreMedia, while a passive `tcpdump` captured
  the concurrent RTP. Byte-comparing the two proved the fed bytes are identical
  to our own depacketization — refuting the "Apple patches the bitstream" theory.
- **Replay harnesses** (Swift + Python) that reconstruct `avconferenced`'s exact
  VideoToolbox and VideoProcessing/VCP configuration and decode the captured
  stream — used to rule the whole config surface in/out.
- **Forced-decoder tests** — forced Apple's software HEVC decoder and verified
  (via the `UsingHardwareAcceleratedVideoDecoder` property) that the mode
  actually switched.
- **AVConference API + entitlement inspection** — enumerated the framework's
  classes: `VCVideoDecoder` has no decode-a-buffer method (it drives a
  transport-coupled `VCVideoPlayer` engine), and `avconferenced` carries no
  codec/decode-specific entitlement.

## Conclusions

- The motion tear is a **receiver-side decode phenomenon bound to
  `avconferenced`'s execution context** — not the bytes, the depacketization,
  packet loss, keyframe cadence, or any settable VideoToolbox/VideoProcessing
  property. The DisplayService HEVC stream is subtly non-conformant, and only
  Apple's in-process conferencing decode path (reached through a
  transport-coupled `VideoReceiver`/`VCVideoPlayer` engine) reconstructs it
  cleanly. Every decoder reachable from an ordinary process — VideoToolbox HW,
  VideoToolbox SW, VideoProcessing/VCP with Apple's exact spec, ffmpeg, browser
  WebCodecs — smears on the byte-identical stream.
- **A decode-only fix in pymobiledevice3 is not achievable.** Matching DeviceHub
  would require driving `avconferenced`'s own `VideoReceiver` pipeline, which
  exposes no standalone decode API and runs in Apple's process context.
- **Landed:** the 14-byte trailer strip in `depacketize_hevc` — bitstream
  correctness / parity with Apple's receiver, not a tear fix.

## Reproduce

Decode a captured Annex-B stream offline (any VideoToolbox or ffmpeg harness)
and inspect a late frame — it smears, while the DeviceHub window at the same
wall-clock instant is clean.
