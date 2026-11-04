# Installation

## Install the CLI

The recommended way is [uv](https://docs.astral.sh/uv/): it installs `pymobiledevice3` into its own
isolated environment, downloads a suitable Python if yours is missing or too old, and puts the
command on your PATH. You don't need to know Python to use it.

1. Install uv (skip if you already have it):

    === "macOS / Linux"

        ```shell
        curl -LsSf https://astral.sh/uv/install.sh | sh
        ```

    === "Windows"

        ```powershell
        powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
        ```

2. Open a new terminal (so the updated PATH is picked up) and install:

    ```shell
    uv tool install pymobiledevice3
    ```

Upgrade with `uv tool upgrade pymobiledevice3`; remove with `uv tool uninstall pymobiledevice3`.
To try a command without installing anything, use `uvx pymobiledevice3 <command>`.

!!! note "Why not `pip install`?"
    Installing CLI tools into the system Python is blocked on many setups (Homebrew Python, Debian 12+,
    Ubuntu 23.04+, Arch all refuse with `externally-managed-environment`), and Apple's
    `/usr/bin/python3` installs the command somewhere that isn't on your PATH. A tool installer
    avoids both.

### Alternatives

- **pipx**: `pipx install pymobiledevice3` is equivalent if you already use pipx.
- **As a library**: to use the [Python API](guides/python-api.md), add it to your project's virtual
  environment like any other dependency (`pip install pymobiledevice3` / `uv add pymobiledevice3`).

PyPI is the only official distribution channel. Distribution packages such as the AUR's
`python-pymobiledevice3` are not maintained by this project and may be outdated.

### Running with `sudo`

Most commands need no root. For the few that do (for example a privileged `remote tunneld`), note that
Linux `sudo` resets PATH and won't find a per-user install. Pass the full path instead:

```shell
sudo "$(which pymobiledevice3)" remote tunneld
```

## From source

```shell
git clone git@github.com:doronz88/pymobiledevice3.git
cd pymobiledevice3
uv tool install -e .   # or: python3 -m pip install -U -e . inside a venv
```

Requires **Python 3.9+**.

## Verify connectivity

```shell
pymobiledevice3 usbmux list
pymobiledevice3 syslog live
pymobiledevice3 apps list
```

Install shell completions:

```shell
pymobiledevice3 --install-completion
```

## Platform notes

=== "Windows"

    - Install iTunes: <https://www.apple.com/itunes/download/win64>. It provides the *Apple Mobile
      Device Service* every usbmux-based command talks to.
    - Prefer that package over the Microsoft Store "Apple Devices" app. The Store app's service
      does not discover devices over Wi-Fi, so an uncabled device never appears in
      `pymobiledevice3 usbmux list` even with `lockdown wifi-connections on` — reaching it then
      takes an explicit `--mobdev2`.
    - For WSL2, enable mirrored networking mode:

        ```none
        [wsl2]
        networkingMode=mirrored
        ```

=== "Linux"

    - Install `usbmuxd`: <https://github.com/libimobiledevice/usbmuxd>

=== "macOS"

    - Works out of the box with the system usbmuxd.

Additional requirements:

- **OpenSSL** is explicitly required for older iOS versions (`< 13`).
- **Recovery/DFU** support requires `libusb` on Linux and Windows. On macOS it goes through IOKit and
  needs nothing extra (`pymobiledevice3 restore --libusb ...` uses libusb there too, if installed).

## iOS 17+ developer services

`iOS >= 17` developer services require tunnel-based transport. You don't have to set it up:
every command that needs a tunnel establishes a no-root, in-process userspace tunnel on its own, with
no flag and no `sudo`. See [iOS 17+ tunnels](guides/ios17-tunnels.md) for the full picture, the
support matrix, and the cases that still call for a privileged `tunneld`.
