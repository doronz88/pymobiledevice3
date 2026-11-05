---
title: Home
template: home.html
hide:
  - navigation
  - toc
---

`pymobiledevice3` is a pure Python 3 implementation for interacting with iOS devices
(iPhone, iPad, ...). It ships both a **command-line tool** and a **Python API**, and runs on
Windows, Linux, and macOS. Coming from Android? Think of it as `adb` for iOS.

## What it can do

<div class="grid pmd-features" markdown>

- :material-monitor-cellphone: **[Screen mirroring and control](guides/screen-mirroring.md)** in any
  browser or VNC client: touch, buttons, keyboard, audio and a shared clipboard (iOS 27+)
- :material-lan-connect: **[Packet capture per process](guides/packet-capture.md)**: every packet on
  every interface, labelled with the app that sent it, straight into Wireshark
- :material-magnify-scan: **[strace for iOS](guides/kdebug.md)**: every syscall of every process
  with decoded arguments and paths, live, on a stock device
- :material-language-javascript: **[JavaScript shell](guides/webview-debugging.md#interactive-javascript-shell)**
  into any Safari tab or inspectable WebView, with completion from the live page
- :material-web: **[Chrome DevTools, VS Code and Playwright](guides/webview-debugging.md)** on iOS
  Safari and WebViews through a CDP bridge
- :material-tools: **[Developer services without Xcode](guides/cli-recipes.md#dvt-examples)**: screenshots,
  process control, location simulation, sysmon; on iOS 17+ over a [no-root tunnel](guides/ios17-tunnels.md)
  built for you, on Windows and Linux too
- :material-text-box-search-outline: **[Syslog and oslog](cli/syslog.md)** streaming
- :material-folder-open-outline: **[Device files](cli/afc.md)**: shell, copy, and
  [mount as a drive](guides/webdav-mounting.md)
- :material-apps: **[Apps](cli/apps.md) and [profiles](cli/profile.md)**: install, list, manage
- :material-bug-outline: **[Crash reports](cli/crash.md)** collection
- :material-cellphone-arrow-down: **[Firmware update and restore](guides/restore.md)**, recovery and DFU,
  without Finder or iTunes
- :material-backup-restore: **[Backups](cli/backup2.md)**: create, restore, browse
- :material-usb: **[Discovery](cli/usbmux.md)** over USB and Wi-Fi, plus TCP port forwarding
- :material-bell-ring-outline: **[Notifications](cli/notification.md)** and
  **[SpringBoard](cli/springboard.md)** control
- :material-language-python: **[Python API](guides/python-api.md)** for all of the above

</div>

## Where to go next

<div class="grid cards" markdown>

- :material-download: **[Installation](installation.md)**

    Install with uv (no Python knowledge needed) and run your first command.

- :material-console: **[CLI recipes](guides/cli-recipes.md)**

    Task-oriented examples for everyday commands.

- :material-lifebuoy: **[Troubleshooting](guides/troubleshooting.md)**

    Error messages mapped to their causes and fixes.

- :material-tunnel-outline: **[iOS 17+ tunnels](guides/ios17-tunnels.md)**

    Reach developer services on modern iOS: the no-root tunnel is built for you, no flags needed.

- :material-language-python: **[Python API](guides/python-api.md)**

    Connect to a device and drive services from your own code.

- :material-book-open-variant: **[API reference](api/index.md)**

    Generated reference for the public classes.

- :material-sitemap: **[Protocol internals](internals/idevice-protocol-layers.md)**

    How the iDevice stack, RemoteXPC, and DTX actually work.

</div>

## License and credits

Licensed under GPL-3.0-or-later. See the
[project page](https://github.com/doronz88/pymobiledevice3) for the full list of contributors.

### Can I use pymobiledevice3 in a closed-source app?

Not by asking for an exception. Requests for written permission or a commercial
license come in regularly, and the answer is always no. The reason is that no single
person can grant one:

- pymobiledevice3 has well over a hundred contributors and no contributor license
  agreement, so each contributor keeps the copyright on their own code.
- The userspace tunnel's TCP/IP stack (`pmd-pytcp`, `pmd-net-addr`, `pmd-net-proto`)
  is a fork of Sebastian Majewski's [PyTCP](https://github.com/ccie18643/PyTCP),
  which is also GPL.

What you can do:

- **Release your app under the GPL.** You can still sell it. The GPL lets you charge
  for the app as long as you also provide its source code.
- **Run pymobiledevice3 as a separate program** that your app launches and talks to
  (for example through its CLI), instead of linking it into your closed code. Whether
  that keeps your app separate enough depends on how closely the two are tied
  together. This page is not legal advice, so check your setup with a lawyer.

Either way, also check the licenses of the other dependencies you bundle.
Contributions back are always welcome.
