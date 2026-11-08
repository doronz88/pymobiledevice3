# PyMobileDevice3

<!-- markdownlint-disable MD013 -->
[![Python application](https://github.com/doronz88/pymobiledevice3/workflows/Python%20application/badge.svg)](https://github.com/doronz88/pymobiledevice3/actions/workflows/python-app.yml "Python application action")
[![Pypi version](https://img.shields.io/pypi/v/pymobiledevice3.svg)](https://pypi.org/project/pymobiledevice3/ "PyPi package")
[![Python versions](https://img.shields.io/pypi/pyversions/pymobiledevice3)](https://pypi.org/project/pymobiledevice3/ "Supported Python versions")
[![License](https://img.shields.io/pypi/l/pymobiledevice3)](https://github.com/doronz88/pymobiledevice3/blob/master/LICENSE "License")
[![Docs](https://img.shields.io/badge/docs-online-blue)](https://doronz88.github.io/pymobiledevice3/ "Documentation")
[![Downloads](https://static.pepy.tech/personalized-badge/pymobiledevice3?period=total&units=none&left_color=grey&right_color=blue&left_text=Downloads)](https://pepy.tech/project/pymobiledevice3)
[![Discord](https://img.shields.io/discord/1133265168051208214?logo=Discord&label=Discord)](https://discord.gg/52mZGC3JXJ)
<!-- markdownlint-enable MD013 -->

`pymobiledevice3` is a pure Python 3 implementation for interacting with iOS devices (iPhone, iPad, ...).
It ships both a **command-line tool** and a **Python API**, and runs on Windows, Linux, and macOS. Coming
from Android? Think of it as `adb` for iOS.

Highlights:

- [Screen mirroring and control](https://doronz88.github.io/pymobiledevice3/guides/screen-mirroring/) in any
  browser or VNC client, with touch, buttons, keyboard, audio and clipboard (iOS 27+)
- [Per-process packet capture](https://doronz88.github.io/pymobiledevice3/guides/packet-capture/) straight into Wireshark
- [strace-style syscall tracing](https://doronz88.github.io/pymobiledevice3/guides/kdebug/) of every process, live
- A [JavaScript shell and a CDP bridge](https://doronz88.github.io/pymobiledevice3/guides/webview-debugging/) for
  Safari and WebViews (Chrome DevTools, VS Code, Playwright)
- Developer services without Xcode (screenshots, location simulation, sysmon, DDI mounting); on iOS 17+ over a
  no-root tunnel each command builds for you, on Windows and Linux too
- Syslog/oslog, apps & profiles, device files, crash reports, backups, firmware update/restore and recovery/DFU

## Install

Install with [uv](https://docs.astral.sh/uv/), which fetches a suitable Python for you and puts
`pymobiledevice3` on your PATH:

```shell
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# then, in a new terminal
uv tool install --managed-python pymobiledevice3
```

Upgrade later with `uv tool upgrade pymobiledevice3`, or try it without installing via
`uvx --managed-python pymobiledevice3 usbmux list`. Already manage Python yourself? `pipx install pymobiledevice3`
works too, and for scripting against the [Python API](https://doronz88.github.io/pymobiledevice3/guides/python-api/)
`pip install pymobiledevice3` inside your project's virtualenv.

PyPI is the only official distribution channel. Third-party packages (for example the AUR's
`python-pymobiledevice3`) are not maintained by this project and may be outdated.

On Windows and Linux, first install the
[platform prerequisites](https://doronz88.github.io/pymobiledevice3/installation/#platform-notes)
(iTunes or `usbmuxd`). Then connect the device by USB, unlock it, and verify connectivity:

```shell
pymobiledevice3 usbmux list   # lists connected devices
pymobiledevice3 apps list     # first device command: tap "Trust" on the device if asked
pymobiledevice3 syslog live   # streams the device log; Ctrl+C to stop
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

## Claude Code plugin

The repository ships its
[device-operator agent skill](https://doronz88.github.io/pymobiledevice3/guides/codex-device-operator-skill/)
as a Claude Code plugin, teaching the agent to operate a connected iPhone or iPad through pymobiledevice3:

```
/plugin marketplace add doronz88/pymobiledevice3
/plugin install pymobiledevice3-device-operator@pymobiledevice3
```

## Community

Questions, ideas, or want to help? Join the community on [Discord](https://discord.gg/52mZGC3JXJ).

## Sponsors

A huge thank you to our sponsors for supporting this project! 💖

<!-- markdownlint-disable MD013 -->
<a href="https://www.testmuai.com/?utm_medium=sponsor&utm_source=doron">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/doronz88/pymobiledevice3/18b75e567decdb4d1f0a213ec92ba014fa35d1c0/misc/sponsors/testmu-ai-dark.svg">
    <img alt="TestMu AI (formerly LambdaTest)" src="https://raw.githubusercontent.com/doronz88/pymobiledevice3/18b75e567decdb4d1f0a213ec92ba014fa35d1c0/misc/sponsors/testmu-ai.svg" width="320">
  </picture>
</a>
<!-- markdownlint-enable MD013 -->

[![TestingBot](https://github.com/testingbot.png?size=48)](https://testingbot.com) [**TestingBot**](https://testingbot.com)

[![SmartDust](https://github.com/smartdust-me.png?size=48)](https://smartdust.me) [**SmartDust**](https://smartdust.me)

[![AnNEDoMini](https://github.com/AnNEDoMini.png?size=48)](https://github.com/AnNEDoMini) [**AnNEDoMini**](https://github.com/AnNEDoMini)

Want to support the project as well? Sponsor it via [GitHub Sponsors](https://github.com/sponsors/doronz88) or
[Ko-fi](https://ko-fi.com/doronz).

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
Agent-specific contributor guidance is in [AGENTS](AGENTS.md).

## License and Credits

This work is licensed under GPL 3.0. Planning to ship it in a closed-source app? Read
[this FAQ](https://doronz88.github.io/pymobiledevice3/#can-i-use-pymobiledevice3-in-a-closed-source-app)
first. The project is credited to several major contributors:

- Hector Martin "marcan" <hector@marcansoft.com>
- Mathieu Renard
- [doronz](https://github.com/doronz88) <doron88@gmail.com>
- [matan1008](https://github.com/matan1008) <matan1008@gmail.com>
- [Guy Salton](https://github.com/guysalt)
- [netanelc305](https://github.com/netanelc305) <netanelc305@protonmail.com>
- Inbar Agmon <inbar2812@gmail.com> ([Project's logo](https://repository-images.githubusercontent.com/357904774/6d6fb035-5953-425d-9afd-cc1087df0cfb))
