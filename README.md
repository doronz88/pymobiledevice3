# PyMobileDevice3

<!-- markdownlint-disable MD013 -->
[![Python application](https://github.com/doronz88/pymobiledevice3/workflows/Python%20application/badge.svg)](https://github.com/doronz88/pymobiledevice3/actions/workflows/python-app.yml "Python application action")
[![Pypi version](https://img.shields.io/pypi/v/pymobiledevice3.svg)](https://pypi.org/project/pymobiledevice3/ "PyPi package")
[![Downloads](https://static.pepy.tech/personalized-badge/pymobiledevice3?period=total&units=none&left_color=grey&right_color=blue&left_text=Downloads)](https://pepy.tech/project/pymobiledevice3)
[![Discord](https://img.shields.io/discord/1133265168051208214?logo=Discord&label=Discord)](https://discord.gg/52mZGC3JXJ)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/doronz88/pymobiledevice3)
<!-- markdownlint-enable MD013 -->

## Overview

`pymobiledevice3` is a pure Python 3 implementation for interacting with iOS devices (iPhone, iPad, ...).
It includes both a CLI and a Python API and is supported on:

- Windows
- Linux
- macOS

Main features:

- Device discovery over bonjour
- TCP port forwarding
- Syslog and oslog streaming
- Profile and application management
- AFC file access
- Crash report collection
- Network sniffing (PCAP)
- Firmware update
- Recovery/DFU workflows
- Notification listen/post (`notify_post()`)
- Querying and setting SpringBoard options
- WebInspector automation
- DDI/DVT developer tooling
- Backup and restore

## Quick Start

Install from PyPI:

```shell
python3 -m pip install -U pymobiledevice3
```

Or install from source:

```shell
git clone git@github.com:doronz88/pymobiledevice3.git
cd pymobiledevice3
python3 -m pip install -U -e .
```

Verify connectivity and run first commands:

```shell
pymobiledevice3 usbmux list
pymobiledevice3 syslog live
pymobiledevice3 apps list
```

## Platform Notes

- Windows:
  - Install iTunes from Microsoft Store:
    <https://apps.microsoft.com/detail/9pb2mz1zmb1s?hl=en-US&gl=US>
  - For WSL2, enable mirrored networking mode:
    <https://learn.microsoft.com/en-us/windows/wsl/networking#mirrored-mode-networking>

    ```none
    [wsl2]
    networkingMode=mirrored
    ```
- Linux:
  - Install `usbmuxd`: <https://github.com/libimobiledevice/usbmuxd>

- OpenSSL:
  - OpenSSL is explicitly required for older iOS versions (`< 13`).

- Recovery/DFU support
  - Requires `libusb`.

### Support Matrix (Developer Services)

`iOS >= 17` developer services require tunnel-based transport.

| Host OS | iOS 17.0-17.3.1 | iOS 17.4+ |
| --- | --- | --- |
| macOS | Supported | Supported |
| Windows | Supported (requires additional drivers) | Supported |
| Linux | Limited | Supported (lockdown tunnel) |

See the detailed guide: [iOS 17+ tunnels](docs/guides/ios17-tunnels.md)

## Common CLI Tasks

See full recipes: [CLI recipes](docs/guides/cli-recipes.md)

```shell
# List connected devices
pymobiledevice3 usbmux list

# Watch syslog
pymobiledevice3 syslog live

# Pull crash reports
pymobiledevice3 crash pull /path/to/crashes

# Mount DDI
pymobiledevice3 mounter auto-mount

# DVT screenshot (requires developer setup)
pymobiledevice3 developer dvt screenshot /path/to/screen.png
```

Install shell completions:

```shell
pymobiledevice3 install-completions
```

## Python API and Protocol Internals

- Protocol overview:
  [Understanding iDevice protocol layers](misc/understanding_idevice_protocol_layers.md)
- DTX API quick start:
  [DTX README](pymobiledevice3/dtx/README.md)
- DTX internals:
  [DTX DEVELOPMENT](pymobiledevice3/dtx/DEVELOPMENT.md)
- RemoteXPC internals:
  [RemoteXPC](misc/RemoteXPC.md)
- Building custom CLI commands with `service_provider`:
  [Guide](docs/guides/writing-commands-with-service-provider.md)

## Documentation Map

See [Documentation index](docs/README.md) for task-focused guides.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
Agent-specific contributor guidance is in [AGENTS](AGENTS.md).

## License and Credits

This work is licensed under GPL 3.0 and credited to several major contributors:

- Hector Martin "marcan" <hector@marcansoft.com>
- Mathieu Renard
- [doronz](https://github.com/doronz88) <doron88@gmail.com>
- [matan1008](https://github.com/matan1008) <matan1008@gmail.com>
- [Guy Salton](https://github.com/guysalt)
- [netanelc305](https://github.com/netanelc305) <netanelc305@protonmail.com>
- Inbar Agmon <inbar2812@gmail.com> ([Project's logo](https://repository-images.githubusercontent.com/357904774/6d6fb035-5953-425d-9afd-cc1087df0cfb))
