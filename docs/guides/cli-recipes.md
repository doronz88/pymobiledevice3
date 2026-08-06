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

Talks to `cryptexd` directly. `cryptex list` reports a mounted personalized DeveloperDiskImage as
`com.apple.MobileAsset.DDI`.

```shell
pymobiledevice3 cryptex list --userspace
pymobiledevice3 cryptex personalization-identifiers --userspace
pymobiledevice3 cryptex nonce --userspace
pymobiledevice3 cryptex nonce --nonce-domain-handle 7 --userspace
```

State-changing. Rolling a nonce invalidates anything personalized against it, so a mounted
personalized DDI must be re-personalized and re-mounted afterwards:

```shell
pymobiledevice3 cryptex roll-nonce --userspace
pymobiledevice3 cryptex uninstall com.apple.MobileAsset.DDI --userspace
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

```shell
# Query what the device's media-stream server supports
pymobiledevice3 developer core-device display get-media-support-info
pymobiledevice3 developer core-device display get-media-stream-server-status

# Serve the device screen live to any modern browser (Safari / HEVC-enabled
# Chrome). Decode happens in-browser via WebCodecs — no ffmpeg required.
pymobiledevice3 developer core-device display serve-web
# then open http://127.0.0.1:8080/

# Serve the device screen as a VNC (RFB 3.8) server -- view via macOS
# Screen Sharing.app (Finder ⌘K -> vnc://) or any VNC client.
# macOS-only (server-side HEVC decode through VideoToolbox).
# Right-click in the viewer = Home button; Ctrl+H/L/[/]/\\/S = Home /
# Lock / VolDown / VolUp / Mute / Siri. Add --audio to also play the
# device's system audio out the host Mac's speakers.
pymobiledevice3 developer core-device display serve-vnc
# then Finder ⌘K -> vnc://127.0.0.1:5901

# Capture raw RTP/HEVC packets to a file (length-prefixed)
pymobiledevice3 developer core-device display start-video-stream /tmp/cap.rtp --duration 10

# Convert that capture to an Annex-B .h265 bitstream playable by ffplay/VLC
misc/rtp_dump.py /tmp/cap.rtp /tmp/cap.h265
ffplay -framerate 60 /tmp/cap.h265
```

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
