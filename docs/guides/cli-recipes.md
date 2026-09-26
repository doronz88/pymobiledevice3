---
search:
  boost: 2
---

# CLI Recipes

Common `pymobiledevice3` commands grouped by task.

## Device Discovery and Connectivity

```shell
# List connected devices
pymobiledevice3 usbmux list

# Browse RemoteXPC devices over bonjour
pymobiledevice3 bonjour rsd

# Forward a host port to device port
pymobiledevice3 usbmux forward HOST_PORT DEVICE_PORT
```

## Logging and Diagnostics

```shell
# View all syslog lines (including debug)
pymobiledevice3 syslog live

# Filter syslog lines
pymobiledevice3 syslog live -m SpringBoard

# Exclude syslog lines
pymobiledevice3 syslog live -v unwanted_log

# Capture Bluetooth HCI traffic in PacketLogger format
pymobiledevice3 btlogger trace.pklg

# Capture Bluetooth HCI traffic as pcapng for Wireshark
pymobiledevice3 btlogger -f pcapng trace.pcapng

# Restart device
pymobiledevice3 diagnostics restart

# Pull crash reports
pymobiledevice3 crash pull /path/to/crashes

# Show the process list (diagnosticsd API; no developer tunnel required)
pymobiledevice3 processes ps

# Match process pids by name (like pgrep)
pymobiledevice3 processes pgrep SpringBoard
```

## Network Sniffing (PCAP)

```shell
# Sniff all device traffic and write a pcap
pymobiledevice3 pcap --out capture.pcap

# Sniff only a given process, stopping after 100 packets
pymobiledevice3 pcap --process backboardd -c 100

# Sniff a single interface
pymobiledevice3 pcap -i en0
```

## Files, Apps, and Backup

```shell
# Open AFC shell (media directory)
pymobiledevice3 afc shell

# List installed apps
pymobiledevice3 apps list

# Query specific app bundle IDs
pymobiledevice3 apps query BUNDLE_ID1 BUNDLE_ID2

# Full backup
pymobiledevice3 backup2 backup --full DIRECTORY

# Preserve only selected backup payloads
pymobiledevice3 backup2 backup --only messages DIRECTORY
pymobiledevice3 backup2 backup --only messages --patch-manifest DIRECTORY
pymobiledevice3 backup2 backup --only sms DIRECTORY
pymobiledevice3 backup2 backup --only whatsapp DIRECTORY
pymobiledevice3 backup2 backup --only contacts DIRECTORY
pymobiledevice3 backup2 backup --only call_history DIRECTORY
pymobiledevice3 backup2 backup --only bookmarks DIRECTORY
pymobiledevice3 backup2 backup --only-regex '\\.(plist|db|db-shm|db-wal|sqlite|sqlite-shm|sqlite-wal|sqlitedb|sqlitedb-shm|sqlitedb-wal|storedata|storedata-shm|storedata-wal)$' DIRECTORY

# `messages` keeps sms.db plus the complete SMS/iMessage attachment, part,
# sticker, and recent-item trees. Filtering saves host disk space, but the
# device still sends all backup bytes during the first run. The complete
# Manifest.db is retained so later runs can use incremental backup state.
# Filtered backups are intended for data access, not full-device restore.
# Use --patch-manifest when another tool requires Manifest.db to reference
# only saved payloads. This forces each run to be full, and encrypted backups
# require --password so the manifest can be decrypted and re-encrypted.
# Filtered backups also require --patch-manifest when combined with --unback.

# Restore backup
pymobiledevice3 backup2 restore DIRECTORY
```

## Profiles and Configuration

```shell
# List installed configuration profiles
pymobiledevice3 profile list

# Install one or more profiles (.mobileconfig)
pymobiledevice3 profile install my.mobileconfig

# Remove a profile by its identifier/name
pymobiledevice3 profile remove com.example.profile
```

## Cryptexes (iOS 17+, RSD tunnel)

Talks to `cryptexd` directly. `cryptex list` reports a DeveloperDiskImage installed as a cryptex
(by `cryptex auto-install`, by `mounter auto-mount`, or by Xcode) as
`com.apple.MobileAsset.DDI`. A `PersonalizedDMG` mounted through the image mounter is not a
cryptex, so it does not appear there -- `mounter list` shows both.

```shell
pymobiledevice3 cryptex list
pymobiledevice3 cryptex personalization-identifiers
pymobiledevice3 cryptex nonce
pymobiledevice3 cryptex nonce --nonce-domain-handle 7
```

State-changing. Rolling a nonce invalidates anything personalized against it, so a mounted
personalized DDI must be re-personalized and re-mounted afterwards:

```shell
pymobiledevice3 cryptex roll-nonce
pymobiledevice3 cryptex uninstall com.apple.MobileAsset.DDI
```

`cryptex auto-install` is the cryptex counterpart of `mounter auto-mount` — a cryptex is
*installed*, not mounted, which is why the verb differs. It personalizes and installs the
DeveloperDiskImage over `cryptexd` alone, without the image mounter: it has Apple sign a Cryptex1
ticket for this device and installs the payloads, leaving the DDI's developer services (DVT,
testmanagerd, …) usable. The end result is indistinguishable from a `mounter auto-mount` —
`mounter list` reports it as a `Personalized` image at `/System/Developer`. In fact, from iOS 27
`mounter auto-mount` itself installs this cryptex rather than mounting the older `PersonalizedDMG`,
setting up the tunnel itself, since the cryptex is not tied to the boards listed in the DDI's build
manifest and so also covers devices newer than the DDI.

!!! warning "iOS 26 and earlier"

    `cryptexd` on iOS 26 and earlier does not accept the install the way it is sent to iOS 27: on
    iOS 26 it aborts with *"asset already present: Cryptex1,GenericVolume"*
    ([#1991](https://github.com/doronz88/pymobiledevice3/issues/1991)). There, use
    `mounter auto-mount`, which mounts the `PersonalizedDMG` on those versions.

It refuses to run while a DeveloperDiskImage is already present, whichever front-end put it there:
remove a cryptex with `cryptex uninstall com.apple.MobileAsset.DDI`, or a `PersonalizedDMG` with
`mounter umount-personalized`.

Also like `mounter auto-mount`, it downloads the DDI it needs and caches it under
`~/.pymobiledevice3` (`$XDG_DATA_HOME/pymobiledevice3` on new Linux installs), so no Xcode
installation is required and it works on any host:

```shell
pymobiledevice3 cryptex auto-install

# Use a local bundle instead of the download, e.g. Xcode's own
pymobiledevice3 cryptex auto-install --restore-dir /Library/Developer/DeveloperDiskImages/iOS_DDI/Restore
```

!!! note "Overlap with `mounter`"

    `cryptexd` and the image mounter are two front-ends onto the same cryptex subsystem, so some
    queries exist in both places. Where they overlap, `cryptex` is the more precise source:

    - `cryptex personalization-identifiers` returns a strict superset of
      `mounter query-personalization-identifiers` (19 `img4_chip_*` fields versus 8), including
      the product class used by the `Cryptex1,UseProductClass` personalization variant.
    - `cryptex nonce` returns the nonce structure (56 bytes, the 48-byte nonce at offset 2);
      `mounter query-nonce` returns those 48 bytes alone.
    - `cryptex nonce` validates the domain and fails loudly on an unknown one, whereas
      `mounter query-nonce` silently falls back to the default nonce for an unrecognized
      `--image-type`.

    `mounter` still wins when you have no tunnel: it works over plain USB, while every `cryptex`
    command needs RSD.

## App install records (iOS 17+, RSD tunnel)

```shell
# LaunchServices install record (DB UUID/sequence, install path, persistent identifier)
pymobiledevice3 apps install-record com.apple.Preferences --userspace
```

## Darwin Notifications

```shell
# Post a notification
pymobiledevice3 notification post com.example.notification

# Subscribe and stream notifications as they fire
pymobiledevice3 notification observe com.example.notification
```

On iOS 17+ with an RSD tunnel, `--remotexpc` talks to the notification proxy directly over
RemoteXPC instead of tunnelling the lockdown service through its `.shim.remote` alias:

```shell
pymobiledevice3 notification observe --remotexpc com.example.notification --userspace
pymobiledevice3 notification post --remotexpc com.example.notification --userspace
```

## SpringBoard UI

```shell
# Print current screen orientation
pymobiledevice3 springboard orientation

# Save an app's icon to a PNG
pymobiledevice3 springboard icon com.apple.mobilesafari safari-icon.png

# Save the home-screen wallpaper to a PNG
pymobiledevice3 springboard wallpaper-home-screen wallpaper.png
```

## Firmware Update

```shell
# Update using local IPSW file
pymobiledevice3 restore update -i /path/to/ipsw

# Update using IPSW URL
pymobiledevice3 restore update -i https://example.com/firmware.ipsw
```

## Developer Mode and DDI

```shell
# Enable Developer Mode
pymobiledevice3 amfi enable-developer-mode

# Auto-mount DeveloperDiskImage
pymobiledevice3 mounter auto-mount
```

`mounter auto-mount` picks the right DeveloperDiskImage for the device's iOS version:

| iOS | Image |
| --- | --- |
| < 17.0 | the classic `DeveloperDiskImage.dmg` for that version, over the image mounter |
| 17.0 - 26.x | the `PersonalizedDMG` over the image mounter |
| 27.0+ | the Cryptex1 DDI over `cryptexd` |

!!! note "Newer devices (e.g. the iPhone 18 series) only work with the Cryptex1 DDI"

    Every `PersonalizedDMG` build identity is tied to one chip/board pair, so it can only be
    personalized for the devices listed in the DDI's build manifest -- and even Xcode 27.1's DDI
    stops at `iPhone18,5`. A device outside that list gets no ticket for it (see
    [`NoSuchBuildIdentityError`](troubleshooting.md#could-not-find-the-manifest-for-board-and-chip-nosuchbuildidentityerror)).
    The Cryptex1 identity names no device at all, so its ticket request is valid for any device and
    Apple's signing server decides. This is also how Xcode supports these devices, which run iOS
    27 or later, where `auto-mount` installs the cryptex (as does `cryptex auto-install`).

Installing the Cryptex1 DDI needs an RSD tunnel; you don't need to pass one: the CLI sets up a no-root tunnel and retries by itself
(*"Trying again over ... since RSD is required for this command"*). All variants are downloaded
and cached under `~/.pymobiledevice3` (`$XDG_DATA_HOME/pymobiledevice3` on new Linux installs),
and the iOS 17+ ones end up mounted at `/System/Developer`. See
[Cryptexes](#cryptexes-ios-17-rsd-tunnel) for installing the cryptex directly.

For iOS 17+ tunnel setup, see:
[iOS 17+ tunnels](ios17-tunnels.md)

## DVT Examples

```shell
# Simulate location (iOS < 17.0)
pymobiledevice3 developer simulate-location set -- lat long

# Simulate location (iOS >= 17.0)
pymobiledevice3 developer dvt simulate-location set -- lat long

# Play GPX route
pymobiledevice3 developer dvt simulate-location play route.gpx

# Add random timing noise between -500 and 500 ms
pymobiledevice3 developer dvt simulate-location play route.gpx 500

# Clear simulated location
pymobiledevice3 developer dvt simulate-location clear

# Take a screenshot
pymobiledevice3 developer dvt screenshot /path/to/screen.png

# Detailed process list
pymobiledevice3 developer dvt sysmon process single

# Stream processes above 50% CPU
pymobiledevice3 developer dvt sysmon process monitor threshold 50

# Stream one process and only show the selected fields
pymobiledevice3 developer dvt sysmon process monitor process --filter pid=123 --key name --key cpuUsage --key physFootprint

# Stream one process with human-readable memory sizes
pymobiledevice3 developer dvt sysmon process monitor process --filter name=SpringBoard --key name --key physFootprint --human

# Keep streaming across relaunches: re-apply the filter on every snapshot instead of
# stopping once the originally selected process is gone
pymobiledevice3 developer dvt sysmon process monitor process --filter name=MyApp --choose last --keep-monitoring

# Stream oslog
pymobiledevice3 developer dvt oslog

# Kill a process
pymobiledevice3 developer dvt kill PID

# Disable the jetsam memory limit for a process (stop it being killed for
# exceeding its memory allowance)
pymobiledevice3 developer dvt memlimitoff PID

# List files in an un-chrooted path
pymobiledevice3 developer dvt ls PATH

# Launch an app
pymobiledevice3 developer dvt launch com.apple.mobilesafari

# Live KDebug parsing (strace-like)
pymobiledevice3 developer dvt core-profile-session parse-live

# Save KDebug events to file
pymobiledevice3 developer dvt core-profile-session save FILENAME

# Device information
pymobiledevice3 developer dvt device-information

# Energy monitor
pymobiledevice3 developer dvt energy PID1 PID2 ...
```

## Core Device (iOS 17+)

These commands talk to iOS 17+ `CoreDevice` services through the RSD tunnel.
See [iOS 17+ tunnels](ios17-tunnels.md) for tunnel setup.

!!! note "Prerequisites"
    These require both an RSD tunnel **and** the Developer Disk Image (DDI) mounted. Mount it once
    per boot with:

    ```shell
    pymobiledevice3 mounter auto-mount
    ```

```shell
# Take a screenshot (PNG)
pymobiledevice3 developer core-device screen-capture screenshot /path/to/screen.png

# Fetch an application's icon (PNG). Size is given in points; pixel size is size * scale
pymobiledevice3 developer core-device fetch-app-icon com.apple.Preferences /path/to/icon.png
pymobiledevice3 developer core-device fetch-app-icon com.example.app /path/to/icon.png --width 176 --height 176 --scale 2

# Fail instead of returning a generic placeholder when the app has no icon
pymobiledevice3 developer core-device fetch-app-icon com.example.app /path/to/icon.png --no-placeholder
```

### HID input

```shell
# Press a named hardware button (home, power, lock, sleep, volume-up, volume-down, mute, siri)
pymobiledevice3 developer core-device hid button home press

# Hold/release a named button (states: down, up, canceled)
pymobiledevice3 developer core-device hid button volume-up down
pymobiledevice3 developer core-device hid button volume-up up

# Press by raw HID (usage_page, usage_code) — decimal or 0xHEX
pymobiledevice3 developer core-device hid raw-button 0x0C 0x40 press

# List the device's registered HID surfaces (each has a _ServiceID).
# Touch goes via 257 (mainTouchscreen) or 1281 (touchscreenGesture).
pymobiledevice3 developer core-device universal-hid-service list-connected

# Deliver a raw HID report to a connected surface. The layout is
# surface-specific; capture devicectl traffic with misc/remotexpc_sniffer.py
# to learn it for a new surface.
pymobiledevice3 developer core-device universal-hid-service send-report 1281 <hex>

# --- touch gestures (auto-managed media stream — see hid_service.py) ---
#
# X/Y are UInt16 (0..65535) normalised across the device's screen, so
# (0, 0) is top-left and (65535, 65535) is bottom-right regardless of the
# device's pixel resolution. Useful anchors regardless of model:
#   center                (32768, 32768)
#   top-center            (32768,  5000)
#   bottom-center         (32768, 60000)
#   home-indicator area   (32768, 62000+)
#
# To convert from pixel coordinates, query the device's pixel size first:
#   pymobiledevice3 developer core-device get-display-info
#       # → displays[0].currentMode.size = [828, 1792] for an iPhone 11, etc.
# then scale linearly: hid_x = round(px_x * 65535 / px_w).

# Tap at the screen center
pymobiledevice3 developer core-device universal-hid-service tap -- 32768 32768

# Drag from near the top to near the bottom (e.g. pull-down)
pymobiledevice3 developer core-device universal-hid-service drag -- 32768 5000 32768 60000

# Pure pointer-motion gesture (moves cursor without registering a contact)
pymobiledevice3 developer core-device universal-hid-service swipe -- 100 400 700 400

# Batched gestures inside ONE media stream — reads stdin / a script file.
# Recognised lines: tap, drag, swipe, move, sleep (and # comments).
printf 'tap 32768 32768\nsleep 0.3\ndrag 32768 5000 32768 60000\n' | \
    pymobiledevice3 developer core-device universal-hid-service session
```

### Screen streaming (HEVC video)

Two ways to view (and control) the device's screen live, both fed by the same
device-initiated HEVC stream over the RSD tunnel:

- **`serve-web`** — serves the screen over HTTP for any modern browser; the
  HEVC decode happens in-browser via WebCodecs, so it works cross-platform with
  no external tools. Touch, hardware buttons (drawn on the edges of the phone
  frame), and keyboard are wired back to the device. The **View** panel zooms
  (`Ctrl+=` / `Ctrl+-` / `Ctrl+0`) and rotates the displayed device.
- **`serve-vnc`** — serves the screen as a VNC (RFB 3.8) server for macOS
  Screen Sharing or any VNC client. macOS-only, because the server-side HEVC
  decode goes through VideoToolbox. Right-click in the viewer is the Home
  button; `Ctrl+H/L/[/]/\/S` map to Home / Lock / Volume Down / Volume Up /
  Mute / Siri. Add `--audio` to also play the device's system audio out of the
  host Mac's speakers.

```shell
# Query what the device's media-stream server supports
pymobiledevice3 developer core-device display get-media-support-info
pymobiledevice3 developer core-device display get-media-stream-server-status

# Serve the device screen live to any modern browser (see notes above)
pymobiledevice3 developer core-device display serve-web
# then open http://127.0.0.1:8080/

# Serve the device screen as a VNC (RFB 3.8) server, macOS-only (see notes above)
pymobiledevice3 developer core-device display serve-vnc
# then Finder ⌘K -> vnc://127.0.0.1:5901

# Either one, reachable from the rest of the LAN: bind every interface and set a password,
# since whoever reaches the port can both watch and control the device
pymobiledevice3 developer core-device display serve-web --bind 0.0.0.0 --password s3cret
pymobiledevice3 developer core-device display serve-vnc --bind 0.0.0.0 --password s3cret

# Capture raw RTP/HEVC packets to a file (length-prefixed)
pymobiledevice3 developer core-device display start-video-stream /tmp/cap.rtp --duration 10

# Convert that capture to an Annex-B .h265 bitstream playable by ffplay/VLC
misc/rtp_dump.py /tmp/cap.rtp /tmp/cap.h265
ffplay -framerate 60 /tmp/cap.h265
```

Both can share the clipboard with the device, in both directions:

- `serve-web`: turn on **Sync** in the viewer's Clipboard panel. Text and
  images copied on the device land in the browser machine's clipboard, and
  whatever was copied there is on the device by the time you paste. A picture
  copied out of a rich-text app such as Notes is not shared: it only exists
  inside the app's rich representations, and reading those blocks the device's
  pasteboard service for about a minute (copy the picture from Photos, or take
  a screenshot, instead). The browser only grants
  clipboard access on a secure context (`localhost`, or `--https`) and asks for
  permission once; it also refuses clipboard writes from a background tab, so a
  device copy made meanwhile lands when you return to the page.
- `serve-vnc --share-clipboard`: text only (RFB has no image clipboard). Uses
  the RFB clipboard messages, so it follows
  the VNC client's own clipboard setting. UTF-8 with clients that implement the
  Extended Clipboard pseudo-encoding (TigerVNC, noVNC, …); other clients get
  the classic Latin-1 message.

```shell
pymobiledevice3 developer core-device display serve-vnc --share-clipboard
```

!!! warning "Camera and microphone conflicts"
    iOS will not start a screen-mirroring session while a foreground app is
    using the camera or microphone. This is the same restriction Apple's Xcode
    Device Hub enforces. If the **Camera**, **Voice Memos**, or a similar app is
    in the foreground when you launch `serve-web` / `serve-vnc`, the command
    prints a one-line explanation and exits with a non-zero code rather than
    serving — quit that app on the device and run it again. Conversely, while a
    mirroring session is active those apps cannot acquire the sensors and will
    record silence or black video, so stop mirroring before capturing with
    them.

### Location

```shell
# List the location-simulation scenarios baked into the device
pymobiledevice3 developer core-device location available-scenarios
```

## WebInspector Automation

```shell
# JavaScript shell on open tab (requires Web Inspector enabled)
pymobiledevice3 webinspector js-shell

# JavaScript shell filtered to one app's WebViews
pymobiledevice3 webinspector js-shell --bundle-id com.example.MyApp

# JavaScript shell without inspector console events
pymobiledevice3 webinspector js-shell --no-console-enable

# JavaScript shell without the console history the page replays on attach
pymobiledevice3 webinspector js-shell --no-replayed-log

# List opened tabs
pymobiledevice3 webinspector opened-tabs

# JavaScript shell on automation tab (requires Remote Automation enabled)
pymobiledevice3 webinspector js-shell --automation

# JavaScript automation shell for a specific app
pymobiledevice3 webinspector js-shell --automation --bundle-id com.example.MyApp

# Launch automation session to URL
pymobiledevice3 webinspector launch URL

# Selenium-like interactive shell
pymobiledevice3 webinspector shell

# CDP bridge: debug pages with Chrome DevTools or VS Code
# (see the WebView debugging guide)
pymobiledevice3 webinspector cdp
```
