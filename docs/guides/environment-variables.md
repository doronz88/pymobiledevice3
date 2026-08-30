---
search:
  boost: 2
---

# Environment variables

Every `pymobiledevice3` environment variable, what it sets, and where it is explained in depth.
Each one is a default: the matching command-line option always wins.

## Device selection

| Variable | Value | Effect |
| --- | --- | --- |
| `PYMOBILEDEVICE3_UDID` | device UDID | Default for `--udid` — the device every command targets. |
| `PYMOBILEDEVICE3_USBMUX` | unix socket path or `HOST:PORT` | Default for `--usbmux` — where `usbmuxd` is listening. |
| `USBMUXD_SOCKET_ADDRESS` | unix socket path or `HOST:PORT` | Same as above; honored for compatibility with `libimobiledevice`. |

## Transport (iOS 17+ tunnels)

| Variable | Value | Effect |
| --- | --- | --- |
| `PYMOBILEDEVICE3_DEFAULT_FALLBACK` | `native`, `userspace` or `tunneld` | Which transport the **automatic** selection prefers, both for commands that require an RSD and for the retry the CLI performs when a command turns out to need a tunnel. Built-in default: `native` on macOS, `userspace` elsewhere. An unrecognized value logs a warning and is ignored. |
| `PYMOBILEDEVICE3_NATIVE` | `1` | Same as `--native`: piggyback Apple's `remoted` tunnel via `remotepairingd`. macOS only, no root. |
| `PYMOBILEDEVICE3_USERSPACE` | `1` | Same as `--userspace`: force the in-process pure-Python userspace tunnel. |
| `PYMOBILEDEVICE3_TUNNEL` | `UDID`, `UDID:PORT` or `UDID:UDS_PATH` | Same as `--tunnel`: take the tunnel from a running `tunneld`. An empty UDID picks the only tunnel, or prompts. |

`--rsd`, `--tunnel`, `--userspace` and `--native` are mutually exclusive, so set at most one of
their variables. See [iOS 17+ tunnels](ios17-tunnels.md) for when each transport applies, and
[Understanding the network stacks](network-stacks.md) for how they differ.

```shell
# opt back out of the macOS native default for this shell
export PYMOBILEDEVICE3_DEFAULT_FALLBACK=userspace
```

## Advanced

| Variable | Value | Effect |
| --- | --- | --- |
| `PYMOBILEDEVICE3_NATIVE_TARGET_UID` | numeric uid | Which login user's `remotepairingd` the native tunnel talks to. `remotepairingd` is registered per-user, so a **root** process (CI runner, LaunchDaemon) needs this to reach the pairing owned by the logged-in user. Ignored (with a warning) when not running as root. |
| `PYMOBILEDEVICE3_USERSPACE_TCP_RELAY` | any non-empty value | Debug: force the userspace tunnel's relays onto loopback TCP even where `AF_UNIX` exists, reproducing the Windows relay path on any platform. |

## Set by your environment, not by you

These are read from the environment your shell or OS already provides; they are listed so their
effect is not a surprise.

| Variable | Effect |
| --- | --- |
| `SUDO_USER` | Under `sudo`, pymobiledevice3 resolves `~` (and therefore `~/.pymobiledevice3`, where pair records live) to the **invoking** user's home, not root's. |
| `SUDO_UID`, `SUDO_GID` | Files pymobiledevice3 creates under `sudo` are chowned back to the invoking user, so a later non-root run can still read them. |
| `XDG_DATA_HOME` | Linux only: fresh installations keep pymobiledevice3's files under `$XDG_DATA_HOME/pymobiledevice3` (`~/.local/share/pymobiledevice3` when unset), per the XDG Base Directory Specification. An existing `~/.pymobiledevice3` keeps being used. |
| `ALLUSERSPROFILE` | Windows only: where Apple's `Lockdown` pair records are looked up (`%ALLUSERSPROFILE%\Apple\Lockdown`). |
| `TERM` | Passed through to the shell `developer debugserver` spawns; defaults to `xterm-256color`. |
| `_PYMOBILEDEVICE3_COMPLETE` | Set by the shell-completion scripts (`--install-completion`). Its presence makes commands skip connecting to the device. |
