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

# Restart device
pymobiledevice3 diagnostics restart

# Pull crash reports
pymobiledevice3 crash pull /path/to/crashes
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
pymobiledevice3 backup2 backup --only sms DIRECTORY
pymobiledevice3 backup2 backup --only whatsapp DIRECTORY
pymobiledevice3 backup2 backup --only contacts DIRECTORY
pymobiledevice3 backup2 backup --only call_history DIRECTORY
pymobiledevice3 backup2 backup --only bookmarks DIRECTORY
pymobiledevice3 backup2 backup --only-regex '\\.(plist|db|db-shm|db-wal|sqlite|sqlite-shm|sqlite-wal|sqlitedb|sqlitedb-shm|sqlitedb-wal|storedata|storedata-shm|storedata-wal)$' DIRECTORY

# Restore backup
pymobiledevice3 backup2 restore DIRECTORY
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
pymobiledevice3 developer dvt sysmon process monitor pid 123 --key name --key cpuUsage --key physFootprint

# Stream one process with human-readable memory sizes
pymobiledevice3 developer dvt sysmon process monitor pid 123 --key name --key physFootprint --human

# Stream oslog
pymobiledevice3 developer dvt oslog

# Kill a process
pymobiledevice3 developer dvt kill PID

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

```shell
# Take a screenshot (PNG)
pymobiledevice3 developer core-device screen-capture screenshot /path/to/screen.png
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
```
