# Screen Mirror — Architecture & Upgrade Path

## Current Implementation (MJPEG, 60 fps)

```
iOS device ──[H.264 over USB]──▶ iOSScreenCapture.plugin (DAL)
    ──[DECODES to BGRA]──▶ AVCaptureVideoDataOutput
    ──[CIContext GPU JPEG encode]──▶ WebSocket
    ──▶ browser <img> tag
```

### Capture backends (priority order)

1. **AVFoundation / CoreMediaIO** (macOS + USB only, 30-60 fps)
   - Same mechanism as QuickTime Player
   - `CMIOObjectSetPropertyData` enables iOS screen capture devices per-process
   - `NSRunLoop` must be spun for CoreMediaIO DAL plugin loading (Mach port notifications)
   - Camera TCC permission is attributed to the parent terminal app
   - `CIContext.JPEGRepresentationOfImage:colorSpace:options:` for GPU-accelerated JPEG
   - Device throttles frame rate when screen is static (~25 fps) and delivers full rate during motion (~60 fps)

2. **Accessibility daemon** (~4 fps, USB or WiFi)
   - `deviceCaptureScreenshot` on `com.apple.accessibility.axAuditDaemon.remoteserver`
   - Lockdown-only, works without Developer Mode

### Key discoveries

- **NSRunLoop is required** for CoreMediaIO plugin loading. Without it, the CMIO property
  call succeeds but no devices appear. The `iOSScreenCapture.plugin` DAL plugin loads via
  Mach port notifications delivered through the run loop.

- **Camera TCC is required for frame delivery, not device discovery.** Without Camera
  permission, AVFoundation finds the device but delivers zero frames.

- **`dispatch_queue_create` on macOS 26+**: libdispatch.dylib is in the dyld shared cache
  and cannot be loaded by path. Use `ctypes.CDLL(None)` to access symbols from the default
  process symbol space.

- **Valeria protocol activation is automatic.** The `iOSScreenCaptureAssistant` daemon
  handles the USB vendor control transfer (`0x40, 0x52`) when the DAL plugin loads. No
  manual activation needed.

## Multi-device selection & the AVFoundation UDID gap

When multiple iOS devices are connected over USB, `--udid` selects which device to mirror.
The accessibility capture backend handles this natively — the lockdown service provider is
already connected to the correct device.  AVFoundation, however, has a fundamental limitation.

### The problem

Apple's `iOSScreenCapture.plugin` DAL plugin exposes each iOS device as an
`AVCaptureDevice` with a randomly generated UUID (`uniqueID`).  **There is no public or
private API to map this UUID back to the iOS device's UDID.**

| What we know on each side | AVFoundation | USB / usbmux |
|---|---|---|
| Device identifier | Random UUID v4 | UDID (40-char hex) |
| Connection ID | CMIO object ID (e.g. 37) | usbmux device ID (e.g. 63) |
| Name | `localizedName()` = "iPad" | USB product name = "iPad" |

The two ID spaces are completely separate — no shared key exists to join them.

### What was tried

| Approach | Result |
|---|---|
| CMIO device properties (brute-forced all printable 4-char selectors) | Only standard props (`uid`, `muid`, `tran`, `dloc`, …); no UDID |
| CMIO HAL enumeration API on macOS 26 | Returns error `0x776F743F` ('wot?') — broken |
| `AVCaptureDALDevice` private ivars via ObjC runtime | `_creatorID` = plugin bundle ID, nothing device-specific |
| IOKit registry search for the AVFoundation UUID | UUID not present anywhere in `ioreg` |
| `AMDeviceGetConnectionID()` vs AVFoundation `connectionID` | Different ID spaces (63 ≠ 37) |
| `AMDeviceCopyDeviceLocation()` (USB locationID) | Available from USB side (0x02110000) but CMIO `dloc` is just an enum (3 = external) |
| UUID derivation (hash of UDID?) | UUID v4 — randomly generated, not deterministic |
| `iOSScreenCaptureAssistant` system logs | Device identifiers redacted as `<private>` |
| `com.apple.cmio.guid.substitute` preference | Looked up by assistant but not set; lives only in daemon process memory |
| `CMIOObjectShow()` debug dump | Only class/name/channels — no UDID |
| DAL plugin binary (`iOSScreenCapture`) | Calls `AMDeviceCopyDeviceIdentifier()` internally but never exposes it through CMIO properties |

### Current behavior

| Scenario | Backend | FPS |
|---|---|---|
| Single device | AVFoundation | 30-60 |
| Multiple devices, different models (iPad + iPhone) | AVFoundation (matched by USB product name) | 30-60 |
| Multiple identical devices (2× iPad) + `--udid` | Accessibility (lockdown targets correct device) | ~4 |
| Multiple devices, no `--udid` | AVFoundation (first device, with warning) | 30-60 |

### Future improvement

If Apple adds a CMIO property exposing the UDID or USB locationID, or if the Valeria USB
protocol can be reverse-engineered to identify devices before AVFoundation claims them, the
AVFoundation backend could support `--udid` for same-model multi-device setups.

---

## Upgrade Path: VideoToolbox H.264 Streaming

The current MJPEG approach re-encodes every frame as an independent JPEG. This works well
at 60 fps but is suboptimal in two ways:

1. **No temporal compression** — each frame is a full image. A typical 1200x1600 JPEG at
   quality 0.6 is ~80-120 KB. At 60 fps that's ~5-7 MB/s through the WebSocket. H.264
   with temporal compression would be ~0.5-1 MB/s at equal or better visual quality.

2. **Double encode/decode** — the iOS device sends H.264 over USB, the DAL plugin decodes
   to raw pixels, we re-encode as JPEG, the browser decodes the JPEG. With H.264 output
   the browser could use its native hardware decoder.

### Architecture for H.264 path

```
iOS device ──[H.264 over USB]──▶ iOSScreenCapture.plugin (DAL)
    ──[DECODES to BGRA]──▶ AVCaptureVideoDataOutput
    ──[VTCompressionSession hardware H.264]──▶ NAL units
    ──[fMP4 muxer]──▶ WebSocket
    ──▶ browser Media Source Extensions (MSE)
```

### Implementation steps

#### 1. VTCompressionSession (Python/ctypes or PyObjC)

```
VideoToolbox.VTCompressionSessionCreate(
    allocator=None,
    width=1200, height=1600,
    codecType=kCMVideoCodecType_H264,  # 0x61766331 ('avc1')
    encoderSpecification=None,  # let system pick (hardware on Apple Silicon)
    imageBufferAttributes=None,
    compressedDataAllocator=None,
    outputCallback=callback_func,
    refcon=None,
)
```

Key properties to set:
- `kVTCompressionPropertyKey_RealTime: True` — prioritize latency over quality
- `kVTCompressionPropertyKey_ProfileLevel: kVTProfileLevel_H264_Main_AutoLevel`
- `kVTCompressionPropertyKey_AverageBitRate: 4_000_000` (4 Mbps, tunable)
- `kVTCompressionPropertyKey_MaxKeyFrameInterval: 60` (keyframe every ~1 sec)
- `kVTCompressionPropertyKey_AllowFrameReordering: False` — no B-frames, lower latency

In the AVCaptureVideoDataOutput delegate, instead of JPEG encoding:
```python
VTCompressionSessionEncodeFrame(session, pixelBuffer, timestamp, duration, None, None, None)
```

The output callback receives CMSampleBuffers containing H.264 NAL units.

#### 2. Fragmented MP4 (fMP4) muxing

Browsers' Media Source Extensions require fMP4 (ISO BMFF) format, not raw H.264.
Each segment needs:
- `ftyp` box (once, at init)
- `moov` box with `mvhd`, `trak`, `mdia`, `minf`, `stbl`, `avcC` (once, at init)
- `moof` + `mdat` boxes per segment (each containing 1-N frames)

Libraries that could help:
- Manual construction with `struct.pack` (~200 lines for minimal fMP4)
- `mp4box` / `bento4` CLI tools for reference
- Python `construct` library for declarative binary format

#### 3. Browser Media Source Extensions (MSE)

```javascript
const ms = new MediaSource();
video.src = URL.createObjectURL(ms);
ms.addEventListener('sourceopen', () => {
    const sb = ms.addSourceBuffer('video/mp4; codecs="avc1.4D0029"');
    ws.onmessage = e => {
        sb.appendBuffer(e.data);
    };
});
```

Replace the `<img>` tag with a `<video>` tag. Each WebSocket message is an fMP4 segment
that gets appended to the SourceBuffer.

#### 4. Latency considerations

- VTCompressionSession with `RealTime=True` and no B-frames adds ~1 frame of latency
- fMP4 segments of 1-3 frames keep latency low (~30-50 ms)
- MSE in browsers adds ~1 frame of buffering
- Total expected latency: ~50-100 ms (vs ~16 ms for current MJPEG)

The latency tradeoff is worth it for bandwidth savings on remote/LAN viewing. For local
use the current MJPEG path at 60 fps is already excellent.

### Alternative: Intercept H.264 before decoding

The most efficient path would skip the decode/re-encode entirely:

```
iOS device ──[H.264 over USB]──▶ intercept at USB/Valeria level ──▶ browser
```

This would require reverse-engineering the Valeria USB protocol to extract the raw H.264
stream before the DAL plugin decodes it. The protocol uses USB bulk transfers on the
SubClass 0x2A interface. Activation is via vendor control transfer `ctrl_transfer(0x40,
0x52, 0x00, 0x02)`. The stream format is undocumented but likely CMSampleBuffer-wrapped
H.264 NALUs. This approach would give zero re-encoding overhead but requires significant
reverse engineering effort.

### QuickTime's "High" vs "Maximum"

For reference, QuickTime Player's recording quality settings control the VTCompressionSession
parameters:
- **Maximum**: Higher bitrate, less compression, larger files (~100 Mbps for 1080p)
- **High**: Lower bitrate, more compression, smaller files (~30 Mbps for 1080p)

Both use hardware H.264 encoding via VideoToolbox. The visual difference is primarily
visible in high-motion scenes with fine detail.
