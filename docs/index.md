---
title: Home
template: home.html
hide:
  - navigation
  - toc
---

`pymobiledevice3` is a pure Python 3 implementation for interacting with iOS devices
(iPhone, iPad, ...). It ships both a **command-line tool** and a **Python API**, and runs on
Windows, Linux, and macOS.

## What it can do

<div class="grid pmd-features" markdown>

- :material-usb: **[Discovery](cli/usbmux.md)** over USB (usbmux) and bonjour, plus TCP port forwarding
- :material-text-box-search-outline: **[Syslog and oslog](cli/syslog.md)** streaming
- :material-apps: **[Apps](cli/apps.md) and [profiles](cli/profile.md)**: install, list, manage
- :material-folder-open-outline: **[AFC file access](cli/afc.md)**, shell and Finder mount
- :material-bug-outline: **[Crash reports](cli/crash.md)** collection
- :material-lan-connect: **[Packet capture](cli/pcap.md)** (PCAP) network sniffing
- :material-cellphone-arrow-down: **[Firmware update](guides/restore.md)**, recovery and DFU workflows
- :material-bell-ring-outline: **[Notifications](cli/notification.md)** listen and post
- :material-view-grid-outline: **[SpringBoard](cli/springboard.md)** options, query and set
- :material-web: **[WebInspector](guides/webview-debugging.md)** automation and a CDP bridge for DevTools,
  VS Code, Playwright and Puppeteer
- :material-tools: **[DDI/DVT developer tooling](cli/developer.md)**, iOS 17+ over a [tunnel](guides/ios17-tunnels.md)
- :material-backup-restore: **[Backup and restore](cli/backup2.md)**

</div>

## Where to go next

<div class="grid cards" markdown>

- :material-download: **[Installation](installation.md)**

    Install from PyPI or source and run your first command.

- :material-console: **[CLI recipes](guides/cli-recipes.md)**

    Task-oriented examples for everyday commands.

- :material-tunnel-outline: **[iOS 17+ tunnels](guides/ios17-tunnels.md)**

    Reach developer services on modern iOS — including the no-root `--userspace` tunnel.

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
