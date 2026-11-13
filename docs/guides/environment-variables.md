---
search:
  boost: 2
---

# Environment variables

Every `pymobiledevice3` environment variable, what it sets, and where it is explained in depth.
Each one is a default: where a matching command-line option exists, the option always wins.

Set a variable for the current shell session like this:

=== "macOS / Linux"

    ```shell
    export PYMOBILEDEVICE3_UDID=00008110-001234567890801E
    ```

=== "Windows (PowerShell)"

    ```powershell
    $env:PYMOBILEDEVICE3_UDID = "00008110-001234567890801E"
    ```

`pymobiledevice3 usbmux list` shows each connected device's UDID (its unique device identifier).

## Device selection

| Variable | Value | Effect |
| --- | --- | --- |
| `PYMOBILEDEVICE3_UDID` | device UDID | Default for `--udid` — the device every command targets. |
| `PYMOBILEDEVICE3_RECONNECT_ANY` | any non-empty value | With `--reconnect`: after a mid-command disconnect, reconnect to the **first available** device even when its UDID differs from the device the command originally targeted. A warning is printed and the re-invocation targets the newly connected device. |
| `PYMOBILEDEVICE3_USBMUX` | unix socket path or `HOST:PORT` | Default for `--usbmux` — where `usbmuxd` is listening. |
| `USBMUXD_SOCKET_ADDRESS` | unix socket path or `HOST:PORT` | Same as above; honored for compatibility with `libimobiledevice`. |

## Transport (iOS 17+ tunnels)

| Variable | Value | Effect |
| --- | --- | --- |
| `PYMOBILEDEVICE3_DEFAULT_FALLBACK` | `native`, `userspace` or `tunneld` | Which transport the **automatic** selection prefers, both for commands that require an RSD and for the retry the CLI performs when a command turns out to need a tunnel. Built-in default: `userspace`. An unrecognized value logs a warning and is ignored. |
| `PYMOBILEDEVICE3_NATIVE` | `1` | Same as `--native`: piggyback Apple's `remoted` tunnel via `remotepairingd`. macOS only, no root, opt-in (see [Native remoted tunnel](network-stacks.md#native-remoted-tunnel-macos-only)). |
| `PYMOBILEDEVICE3_USERSPACE` | `1` | Same as `--userspace`: force the in-process pure-Python userspace tunnel. |
| `PYMOBILEDEVICE3_WIFI` | `1` | Same as `--wifi`: build the userspace tunnel over Wi-Fi (RemotePairing over bonjour) for a device paired with `remote pair`, e.g. an Apple TV. `PYMOBILEDEVICE3_UDID` then holds the pairing identifier. |
| `PYMOBILEDEVICE3_TUNNEL` | `UDID`, `UDID:PORT` or `UDID@HOST[:PORT]` | Same as `--tunnel`: take the tunnel from a running `tunneld`; the `@HOST` form bridges through a remote tunneld's `WS /connect`. An empty UDID picks the only tunnel, or prompts. |

`--rsd`, `--tunnel`, `--userspace` and `--native` are mutually exclusive, so set at most one of
their variables; `--wifi` may be combined only with `--userspace`. See
[iOS 17+ tunnels](ios17-tunnels.md) for when each transport applies, and
[Understanding the network stacks](network-stacks.md) for how they differ.

```shell
# prefer the macOS native tunnel for this shell
export PYMOBILEDEVICE3_DEFAULT_FALLBACK=native
```

## Restore and Recovery/DFU

| Variable | Value | Effect |
| --- | --- | --- |
| `PYMOBILEDEVICE3_IPSW_DIR` | directory | Default for `--ipsw-dir` on the `restore` commands that take an IPSW: reuse a firmware build already downloaded there, and download new ones into it instead of a temporary directory. |
| `PYMOBILEDEVICE3_USB_BACKEND` | `iokit` or `libusb` | Same as `restore --libusb` when set to `libusb`: reach Recovery/DFU devices through libusb instead of IOKit on macOS. `iokit` is only valid on macOS; other platforms always use libusb. |

## Output

| Variable | Value | Effect |
| --- | --- | --- |
| `NO_COLOR` | any non-empty value | Disables colored output and logs, like `--no-color` (see [no-color.org](https://no-color.org)). |

## Advanced

| Variable | Value | Effect |
| --- | --- | --- |
| `PYMOBILEDEVICE3_NATIVE_TARGET_UID` | numeric uid | Which login user's `remotepairingd` the native tunnel talks to. `remotepairingd` is registered per-user, so a **root** process (CI runner, LaunchDaemon) needs this to reach the pairing owned by the logged-in user. Ignored (with a warning) when not running as root. |

## Set by your environment, not by you

These are read from the environment your shell or OS already provides; they are listed so their
effect is not a surprise.

| Variable | Effect |
| --- | --- |
| `SUDO_USER` | Under `sudo`, pymobiledevice3 resolves `~` (and therefore `~/.pymobiledevice3` — or `$XDG_DATA_HOME/pymobiledevice3` on new Linux installs — where pair records live) to the **invoking** user's home, not root's. |
| `SUDO_UID`, `SUDO_GID` | Files pymobiledevice3 creates under `sudo` are chowned back to the invoking user, so a later non-root run can still read them. |
| `XDG_DATA_HOME` | Linux only: fresh installations keep pymobiledevice3's files under `$XDG_DATA_HOME/pymobiledevice3` (`~/.local/share/pymobiledevice3` when unset), per the XDG Base Directory Specification. An existing `~/.pymobiledevice3` keeps being used. Note that plain `sudo` (`env_reset`) strips this variable, so a sudo run falls back to `~/.local/share` of the invoking user — use `sudo -E` (or `env_keep`) if your `XDG_DATA_HOME` points elsewhere and the sudo run should match. |
| `ALLUSERSPROFILE` | Windows only: where Apple's `Lockdown` pair records are looked up (`%ALLUSERSPROFILE%\Apple\Lockdown`). |
| `TERM` | Passed through to the shell `developer debugserver` spawns; defaults to `xterm-256color`. |
| `_PYMOBILEDEVICE3_COMPLETE` | Set by the shell-completion scripts (`--install-completion`). Its presence makes commands skip connecting to the device. |
