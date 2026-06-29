# PyMobileDevice3

<!-- markdownlint-disable MD013 -->
[![Python application](https://github.com/doronz88/pymobiledevice3/workflows/Python%20application/badge.svg)](https://github.com/doronz88/pymobiledevice3/actions/workflows/python-app.yml "Python application action")
[![Pypi version](https://img.shields.io/pypi/v/pymobiledevice3.svg)](https://pypi.org/project/pymobiledevice3/ "PyPi package")
[![Downloads](https://static.pepy.tech/personalized-badge/pymobiledevice3?period=total&units=none&left_color=grey&right_color=blue&left_text=Downloads)](https://pepy.tech/project/pymobiledevice3)
[![Discord](https://img.shields.io/discord/1133265168051208214?logo=Discord&label=Discord)](https://discord.gg/52mZGC3JXJ)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/doronz88/pymobiledevice3)
<!-- markdownlint-enable MD013 -->

`pymobiledevice3` is a pure Python 3 implementation for interacting with iOS devices (iPhone, iPad, ...).
It ships both a **command-line tool** and a **Python API**, and runs on Windows, Linux, and macOS.

Highlights: device discovery, port forwarding, syslog/oslog streaming, app & profile management, AFC
file access, crash reports, PCAP sniffing, firmware update, recovery/DFU, backup/restore, WebInspector
automation, and DDI/DVT developer tooling (iOS 17+ over a tunnel).

## Install

```shell
python3 -m pip install -U pymobiledevice3
```

Then verify connectivity:

```shell
pymobiledevice3 usbmux list
pymobiledevice3 syslog live
pymobiledevice3 apps list
```

## Documentation

📖 **Full documentation: <https://doronz88.github.io/pymobiledevice3/>**

- [Installation & platform notes](https://doronz88.github.io/pymobiledevice3/installation/)
- [CLI recipes](https://doronz88.github.io/pymobiledevice3/guides/cli-recipes/)
- [iOS 17+ tunnels & support matrix](https://doronz88.github.io/pymobiledevice3/guides/ios17-tunnels/)
- [Python API guide](https://doronz88.github.io/pymobiledevice3/guides/python-api/)
- [Python API reference](https://doronz88.github.io/pymobiledevice3/api/)
- [Protocol internals (RemoteXPC, DTX, iDevice layers)](https://doronz88.github.io/pymobiledevice3/internals/idevice-protocol-layers/)

The docs are built from [`docs/`](docs/) with MkDocs (`mkdocs.yml`).

## Community

Questions, ideas, or want to help? Join the community on [Discord](https://discord.gg/52mZGC3JXJ).

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
