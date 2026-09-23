# Installation

## From PyPI

```shell
python3 -m pip install -U pymobiledevice3
```

## From source

```shell
git clone git@github.com:doronz88/pymobiledevice3.git
cd pymobiledevice3
python3 -m pip install -U -e .
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
- **Recovery/DFU** support requires `libusb`.

## iOS 17+ developer services

`iOS >= 17` developer services require tunnel-based transport. The tunnel normally needs
root/admin; you can instead add `--userspace` to a developer command for a no-root, in-process
tunnel. See [iOS 17+ tunnels](guides/ios17-tunnels.md) for the full picture and the support matrix.
