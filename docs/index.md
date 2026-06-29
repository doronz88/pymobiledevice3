# pymobiledevice3

`pymobiledevice3` is a pure Python 3 implementation for interacting with iOS devices
(iPhone, iPad, ...). It ships both a **command-line tool** and a **Python API**, and runs on
Windows, Linux, and macOS.

[Get started :material-arrow-right:](installation.md){ .md-button .md-button--primary }
[CLI recipes](guides/cli-recipes.md){ .md-button }
[Python API](guides/python-api.md){ .md-button }

## What it can do

- Device discovery over bonjour and USB (usbmux)
- TCP port forwarding
- Syslog and oslog streaming
- Profile and application management
- AFC file access
- Crash report collection
- Network sniffing (PCAP)
- Firmware update, recovery/DFU workflows
- Notification listen/post
- Querying and setting SpringBoard options
- WebInspector automation
- DDI/DVT developer tooling (iOS 17+ over a tunnel)
- Backup and restore

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
