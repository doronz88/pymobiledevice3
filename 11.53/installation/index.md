# Installation

## Install the CLI

The recommended way is [uv](https://docs.astral.sh/uv/): it installs `pymobiledevice3` into its own isolated environment, downloads a suitable Python if yours is missing or too old, and puts the command on your PATH. You don't need to know Python to use it.

1. Install uv (skip if you already have it):

   ```
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

   ```
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

1. Open a new terminal (so the updated PATH is picked up) and install:

   ```
   uv tool install --managed-python pymobiledevice3
   ```

   `--managed-python` makes uv use its own up-to-date Python instead of whatever the system has (Apple's `/usr/bin/python3`, for example, is an old 3.9 built against LibreSSL, which can't talk to some devices).

1. Check that the command is found:

   ```
   pymobiledevice3 version
   ```

Upgrade with `uv tool upgrade pymobiledevice3`; remove with `uv tool uninstall pymobiledevice3`. To try a command without installing anything, use `uvx --managed-python pymobiledevice3 <command>`.

Why not `pip install`?

Installing CLI tools into the system Python is blocked on many setups (Homebrew Python, Debian 12+, Ubuntu 23.04+, Arch all refuse with `externally-managed-environment`), and Apple's `/usr/bin/python3` installs the command somewhere that isn't on your PATH. A tool installer avoids both.

### Alternatives

- **pipx**: `pipx install pymobiledevice3` is equivalent if you already use pipx.
- **As a library**: to use the [Python API](https://doronz88.github.io/pymobiledevice3/latest/guides/python-api/index.md), add it to your project's virtual environment like any other dependency (`pip install pymobiledevice3` / `uv add pymobiledevice3`).

PyPI is the only official distribution channel. Distribution packages such as the AUR's `python-pymobiledevice3` are not maintained by this project and may be outdated.

### Running with `sudo`

Most commands need no root. For the few that do (for example a privileged `remote tunneld`), note that Linux `sudo` resets PATH and won't find a per-user install. Pass the full path instead:

```
sudo "$(which pymobiledevice3)" remote tunneld
```

On Windows there is no `sudo`: run the command from a terminal opened with **Run as administrator**.

## Platform notes

Before the first command, make sure the host can see USB-connected devices. pymobiledevice3 talks to them through **usbmuxd**, a host service that multiplexes connections to iOS devices over USB and Wi-Fi.

- Install iTunes: <https://www.apple.com/itunes/download/win64>. It provides the *Apple Mobile Device Service* every usbmux-based command talks to; you don't need to open iTunes itself.

- Prefer that package over the Microsoft Store "Apple Devices" app. The Store app's service does not discover devices over Wi-Fi, so an uncabled device never appears in `pymobiledevice3 usbmux list` even with `lockdown wifi-connections on` — reaching it then takes an explicit `--mobdev2`.

- Under WSL2, pymobiledevice3 uses the Windows host's Apple Mobile Device Service, so install iTunes on Windows and enable mirrored networking in `%UserProfile%\.wslconfig`:

  ```
  [wsl2]
  networkingMode=mirrored
  ```

- Install and start `usbmuxd` (<https://github.com/libimobiledevice/usbmuxd>). Most distributions package it, for example `sudo apt install usbmuxd` on Debian/Ubuntu or `sudo dnf install usbmuxd` on Fedora.

- Works out of the box with the system usbmuxd.

Additional requirements:

- **iOS older than 13** needs a Python linked against OpenSSL, for the legacy TLS settings those devices use. Python builds linked against LibreSSL instead (such as Apple's `/usr/bin/python3`) cannot connect to them.
- **Recovery/DFU** support requires `libusb` on Linux and Windows. On macOS it goes through IOKit and needs nothing extra (`pymobiledevice3 restore --libusb ...` uses libusb there too, if installed).

## Verify connectivity

Connect the device with a USB cable and unlock it. The first command that talks to the device pairs with it: the device shows a *Trust This Computer?* dialog, and the command waits until you tap **Trust** (and enter the device passcode).

```
pymobiledevice3 usbmux list   # lists connected devices; no pairing needed
pymobiledevice3 apps list     # pairs if needed, then lists installed apps
pymobiledevice3 syslog live   # streams the device log; Ctrl+C to stop
```

If `usbmux list` prints an empty list, or a command fails, run `pymobiledevice3 doctor` and see [Troubleshooting](https://doronz88.github.io/pymobiledevice3/latest/guides/troubleshooting/index.md).

Install shell completions (restart the shell afterwards):

```
pymobiledevice3 --install-completion
```

## iOS 17+ developer services

Developer services (the `developer` commands, DDI mounting, cryptexes) on iOS 17 and later are reached through an RSD (RemoteServiceDiscovery) tunnel to the device. You don't have to set it up: on iOS 17.4+ every command that needs one establishes a no-root, in-process userspace tunnel on its own, with no flag and no `sudo`. iOS 17.0-17.3 is served no-root by Apple's own tunnel on macOS, but needs a privileged `tunneld` running on Linux and Windows. See [iOS 17+ tunnels](https://doronz88.github.io/pymobiledevice3/latest/guides/ios17-tunnels/index.md) for the full picture, the support matrix, and the other cases that call for `tunneld`.

## From source

```
git clone https://github.com/doronz88/pymobiledevice3.git
cd pymobiledevice3
uv tool install -e .   # or: python3 -m pip install -U -e . inside a venv
```

Requires **Python 3.9+**.
