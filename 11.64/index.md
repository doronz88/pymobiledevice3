`pymobiledevice3` is a pure Python 3 implementation for interacting with iOS devices (iPhone, iPad, ...). It ships both a **command-line tool** and a **Python API**, and runs on Windows, Linux, and macOS. Coming from Android? Think of it as `adb` for iOS.

## What it can do

- **[Screen mirroring and control](https://doronz88.github.io/pymobiledevice3/latest/guides/screen-mirroring/index.md)** in any browser or VNC client: touch, buttons, keyboard, audio and a shared clipboard (iOS 27+)
- **[Packet capture per process](https://doronz88.github.io/pymobiledevice3/latest/guides/packet-capture/index.md)**: every packet on every interface, labelled with the app that sent it, straight into Wireshark
- **[strace for iOS](https://doronz88.github.io/pymobiledevice3/latest/guides/kdebug/index.md)**: every syscall of every process with decoded arguments and paths, live, on a stock device
- **[JavaScript shell](https://doronz88.github.io/pymobiledevice3/latest/guides/webview-debugging/#interactive-javascript-shell)** into any Safari tab or inspectable WebView, with completion from the live page
- **[Chrome DevTools, VS Code and Playwright](https://doronz88.github.io/pymobiledevice3/latest/guides/webview-debugging/index.md)** on iOS Safari and WebViews through a CDP bridge
- **[Developer services without Xcode](https://doronz88.github.io/pymobiledevice3/latest/guides/cli-recipes/#dvt-examples)**: screenshots, process control, location simulation, sysmon; on iOS 17+ over a [no-root tunnel](https://doronz88.github.io/pymobiledevice3/latest/guides/ios17-tunnels/index.md) built for you, on Windows and Linux too
- **[Syslog and oslog](https://doronz88.github.io/pymobiledevice3/latest/cli/syslog/index.md)** streaming
- **[Device files](https://doronz88.github.io/pymobiledevice3/latest/cli/afc/index.md)**: shell, copy, and [mount as a drive](https://doronz88.github.io/pymobiledevice3/latest/guides/webdav-mounting/index.md)
- **[Apps](https://doronz88.github.io/pymobiledevice3/latest/cli/apps/index.md) and [profiles](https://doronz88.github.io/pymobiledevice3/latest/cli/profile/index.md)**: install, list, manage
- **[Crash reports](https://doronz88.github.io/pymobiledevice3/latest/cli/crash/index.md)** collection
- **[Firmware update and restore](https://doronz88.github.io/pymobiledevice3/latest/guides/restore/index.md)**, recovery and DFU, without Finder or iTunes
- **[Backups](https://doronz88.github.io/pymobiledevice3/latest/cli/backup2/index.md)**: create, restore, browse
- **[Discovery](https://doronz88.github.io/pymobiledevice3/latest/cli/usbmux/index.md)** over USB and Wi-Fi, plus TCP port forwarding
- **[Notifications](https://doronz88.github.io/pymobiledevice3/latest/cli/notification/index.md)** and **[SpringBoard](https://doronz88.github.io/pymobiledevice3/latest/cli/springboard/index.md)** control
- **[Python API](https://doronz88.github.io/pymobiledevice3/latest/guides/python-api/index.md)** for all of the above

## Where to go next

- **[Installation](https://doronz88.github.io/pymobiledevice3/latest/installation/index.md)**

  Install with uv (no Python knowledge needed) and run your first command.

- **[CLI recipes](https://doronz88.github.io/pymobiledevice3/latest/guides/cli-recipes/index.md)**

  Task-oriented examples for everyday commands.

- **[Troubleshooting](https://doronz88.github.io/pymobiledevice3/latest/guides/troubleshooting/index.md)**

  Error messages mapped to their causes and fixes.

- **[iOS 17+ tunnels](https://doronz88.github.io/pymobiledevice3/latest/guides/ios17-tunnels/index.md)**

  Reach developer services on modern iOS: the no-root tunnel is built for you, no flags needed.

- **[Python API](https://doronz88.github.io/pymobiledevice3/latest/guides/python-api/index.md)**

  Connect to a device and drive services from your own code.

- **[API reference](https://doronz88.github.io/pymobiledevice3/latest/api/index.md)**

  Generated reference for the public classes.

- **[Protocol internals](https://doronz88.github.io/pymobiledevice3/latest/internals/idevice-protocol-layers/index.md)**

  How the iDevice stack, RemoteXPC, and DTX actually work.

## License and credits

Licensed under GPL-3.0-or-later. See the [project page](https://github.com/doronz88/pymobiledevice3) for the full list of contributors.

### Can I use pymobiledevice3 in a closed-source app?

Not by asking for an exception. Requests for written permission or a commercial license come in regularly, and the answer is always no. The reason is that no single person can grant one:

- pymobiledevice3 has well over a hundred contributors and no contributor license agreement, so each contributor keeps the copyright on their own code.
- The userspace tunnel's TCP/IP stack (`pmd-pytcp`, `pmd-net-addr`, `pmd-net-proto`) is a fork of Sebastian Majewski's [PyTCP](https://github.com/ccie18643/PyTCP), which is also GPL.

What you can do:

- **Release your app under the GPL.** You can still sell it. The GPL lets you charge for the app as long as you also provide its source code.
- **Run pymobiledevice3 as a separate program** that your app launches and talks to (for example through its CLI), instead of linking it into your closed code. Whether that keeps your app separate enough depends on how closely the two are tied together. This page is not legal advice, so check your setup with a lawyer.

Either way, also check the licenses of the other dependencies you bundle. Contributions back are always welcome.
