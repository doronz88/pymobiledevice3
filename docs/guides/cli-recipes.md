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

## WebInspector Automation

```shell
# JavaScript shell on open tab (requires Web Inspector enabled)
pymobiledevice3 webinspector js-shell

# List opened tabs
pymobiledevice3 webinspector opened-tabs

# JavaScript shell on automation tab (requires Remote Automation enabled)
pymobiledevice3 webinspector js-shell --automation

# Launch automation session to URL
pymobiledevice3 webinspector launch URL

# Selenium-like interactive shell
pymobiledevice3 webinspector shell
```
