---
search:
  boost: 2
---

# Troubleshooting

Common failures mapped to their causes and fixes. Each section quotes the error message (or
exception name) the CLI prints, so you can search this page for what you're seeing.

Start with `doctor`. It checks the *host* — whether usbmux is reachable and finds devices over
Wi-Fi, whether mDNS queries can leave the machine, and which tunnel transports are usable — and,
when a device is attached, what that device is: its model and OS version, whether it is paired, and
whether developer mode and a developer disk image are in place. It needs no device, which is the
point when nothing shows up at all, and it separates "this machine cannot discover devices" from
"the device is not there":

```shell
pymobiledevice3 doctor
```

It exits non-zero when something is broken, and `--json` produces the same report as data. It never
pairs, so running it cannot pop a trust dialog.

Please paste its output when opening an issue — it answers most of what would otherwise be asked in
follow-up questions.

For any problem, running with increased verbosity usually reveals what is going on:

```shell
pymobiledevice3 -vv <command...>
```

## Device discovery

### "Device is not connected" (`NoDeviceConnectedError`)

No device was found over usbmux (the host service, usbmuxd, that connects to iOS devices over USB
and Wi-Fi).

- Check the cable, unlock the device, and check that it shows up in `pymobiledevice3 usbmux list`.
- On Linux, make sure [usbmuxd](https://github.com/libimobiledevice/usbmuxd) is installed and
  running.
- On Windows, install iTunes — it provides the *Apple Mobile Device Service* that
  pymobiledevice3 relies on. Prefer the [classic installer](https://www.apple.com/itunes/download/win64)
  over the Microsoft Store "Apple Devices" app: the Store app's service does not discover devices
  over Wi-Fi, so a device with no cable never appears in `usbmux list`.
- If you passed `--udid`, verify it matches a connected device (see the next section).

### "Failed to connect to usbmuxd socket" (`ConnectionFailedToUsbmuxdError`)

The usbmuxd daemon itself is not reachable.

- On Linux, start it: `sudo systemctl start usbmuxd` (or run `usbmuxd -f` in the foreground to
  see its logs).
- On Windows, make sure the *Apple Mobile Device Service* is running.
- If your daemon listens on a non-default address, point pymobiledevice3 at it with
  `--usbmux HOST:PORT` (or a unix socket path), or the `PYMOBILEDEVICE3_USBMUX` /
  `USBMUXD_SOCKET_ADDRESS` environment variables.

### "Device not found: ..." (`DeviceNotFoundError`)

The UDID you passed (via `--udid` or `PYMOBILEDEVICE3_UDID`) doesn't match any device known to
the transport that was asked for it — the message names that transport (`usbmux`, `tunneld`,
`remotepairingd` for the native tunnel). List what's actually connected:

```shell
pymobiledevice3 usbmux list
```

### The device is advertising over Wi-Fi but `usbmux list` does not show it

Two different things have to be true, and only the first lives on the device:

```shell
pymobiledevice3 bonjour mobdev2   # is the device announcing itself?
pymobiledevice3 usbmux list       # has this host's daemon listed it?
```

When the browse finds it and the listing does not, nothing is wrong on the device — the host's
daemon has not picked the announcement up. `EnableWifiConnections` takes effect immediately when
set, so re-running `lockdown wifi-connections on` will not change anything.

Three things to try, cheapest first:

- Unplug and replug the cable, or toggle Wi-Fi off and on on the device. Both make the daemon
  re-discover, and it often recovers on its own given a minute.
- Make the device re-announce itself, which costs nothing and does not change any setting:

    ```shell
    pymobiledevice3 notification post com.apple.mobile.lockdown.BonjourServiceChanged
    ```

    `lockdownd` (the device's pairing and service daemon) observes that notification, tears down its wireless connections and re-registers
    the Bonjour service. It is what `lockdownd` posts to itself after pair records change.

- Confirm **this** host is paired with the device over USB. Wi-Fi reach is per host: the device
  advertises one authentication tag per paired host, so a machine that has never been cabled to it
  cannot recognise it however the setting is set.

If the browse finds nothing either, the setting really is off (or this host cannot send mDNS at
all — see `pymobiledevice3 doctor`).

## Pairing and trust

### "Waiting for the user to answer the Trust dialog on the device" (`PairingDialogResponsePendingError`)

The device is showing the *Trust This Computer?* dialog. Unlock the device, tap **Trust**, enter
the passcode if asked, and run the command again.

### "The user refused to trust this computer" (`UserDeniedPairingError`)

**Don't Trust** was tapped. To make the dialog reappear, reset the device's trust decisions:
*Settings → General → Transfer or Reset iPhone → Reset → Reset Location & Privacy*, then
reconnect the cable.

### "The device is protected with a passcode. Unlock it and try again." (`PasswordRequiredError`)

Pairing (and some lockdown operations) require the device to be unlocked. Unlock it and retry.

### "Device is not paired" (`NotPairedError`)

The host has no valid pair record for this device. Create one:

```shell
pymobiledevice3 lockdown pair
```

If pairing keeps failing with *"The device does not recognize this computer's pairing record"*
(`InvalidHostIDError`), the device holds a stale record for this host — unpair first
(`pymobiledevice3 lockdown unpair`) or reset trust as described above, then pair again.

## Developer services

### "Failed to start service" (`InvalidServiceError`)

The single most common error. A developer service was requested but the device can't provide
it yet. In order:

1. **Enable Developer Mode** (iOS 16+):

    ```shell
    pymobiledevice3 amfi enable-developer-mode
    ```

    This reboots the device. If it fails with *"Cannot enable Developer Mode while the device has
    a passcode set"* (`DeviceHasPasscodeSetError`), remove the device passcode temporarily — iOS refuses
    to enable Developer Mode automatically while one is set (you can instead enable it manually
    under *Settings → Privacy & Security → Developer Mode*).

2. **Mount the Developer Disk Image** (DDI), the Apple-signed image that adds developer services
   to the device (once per boot):

    ```shell
    pymobiledevice3 mounter auto-mount
    ```

    This downloads the correct image for your iOS version and caches it under
    `~/.pymobiledevice3` (`$XDG_DATA_HOME/pymobiledevice3` on new Linux installs,
    `%USERPROFILE%\.pymobiledevice3` on Windows) — no Xcode required. From iOS 27 the image is the
    Cryptex1 DDI, installed over `cryptexd` just like `pymobiledevice3 cryptex auto-install`; it also
    covers devices newer than the DDI itself.
    That needs an RSD (RemoteServiceDiscovery) tunnel, which `auto-mount` sets up by itself (see the
    [CLI recipes](cli-recipes.md#cryptexes-ios-17-rsd-tunnel)).

3. On **iOS 17+**, developer commands also need a tunnel — but you normally don't need to do
   anything: the CLI establishes a no-root userspace tunnel in-process automatically (you'll
   see a *"Trying again over a no-root userspace tunnel"* warning, which is normal). The
   exception is iOS 17.0-17.3 on Linux/Windows, which needs a running `tunneld` (see
   [below](#unable-to-connect-to-tunneld-tunneldconnectionerror)). See
   [iOS 17+ tunnels](ios17-tunnels.md) for the full picture.

### "DeveloperDiskImage already mounted" (`AlreadyMountedError`)

Nothing to fix: the image is already there and developer services can use it, so
`mounter auto-mount` reports this at info level and exits 0, so scripts can run it unconditionally.
It exits non-zero only when no image could be mounted. To replace it — for
example with a newer DDI — remove it first. Which command applies depends on how it was mounted:
`cryptex list` shows `com.apple.MobileAsset.DDI` only when it was installed as a cryptex (by
`auto-mount` from iOS 27, `cryptex auto-install`, or Xcode):

```shell
pymobiledevice3 cryptex uninstall com.apple.MobileAsset.DDI   # installed as a cryptex
pymobiledevice3 mounter umount-personalized                   # mounted by the image mounter
pymobiledevice3 mounter umount-developer                      # iOS < 17
```

Older versions of `cryptex auto-install` did not notice an image mounted by the image mounter and
failed late with *"mkdir custom mount path: /System/Developer [17: File exists]"*. That is the
same situation — remove the mounted image as above, or upgrade pymobiledevice3.

### "Trying again over ... since RSD is required for this command"

A warning, not an error: the command needs an RSD tunnel, so the CLI retries over a no-root tunnel
by itself. It appears for developer commands on iOS 17+ (*"since it is a developer command on an
iOS 17+ device"*), and for `mounter auto-mount` from iOS 27, where the DeveloperDiskImage is
installed as a cryptex over `cryptexd`, which is only reachable through an RSD tunnel. Pass `--tunnel`, `--userspace` or `--native`
to pick the transport up front. If the retry itself fails, see
[iOS 17+ tunnels](ios17-tunnels.md).

### "The image's build manifest has no entry for this device" (`NoSuchBuildIdentityError`) { #could-not-find-the-manifest-for-board-and-chip-nosuchbuildidentityerror }

The device is newer than the DeveloperDiskImage — typically a newly released model such as the
iPhone 18 series. The image mounter's `PersonalizedDMG` only lists the boards known when the DDI
was built (Xcode 27.1's stops at `iPhone18,5`), so there is nothing to personalize for this one,
and such devices can **only** use the Cryptex1 DDI, which has no such list. Upgrade
pymobiledevice3: these devices run iOS 27 or later, where `mounter auto-mount` installs the cryptex.

### "does not install the DeveloperDiskImage as a cryptex" / "asset already present: Cryptex1,GenericVolume"

iOS installs the DeveloperDiskImage as a cryptex only from 26.4. Below it, `cryptexd` may import
the image but the kernel does not let it mount one at `/System/Developer`, and its asset-type table
is ordered differently, so the install fails: older pymobiledevice3 versions crashed `cryptexd`
there (*"asset already present: Cryptex1,GenericVolume"*, followed by a bare *"Aborted."*)
([#1991](https://github.com/doronz88/pymobiledevice3/issues/1991)). Below iOS 26.4 use
`pymobiledevice3 mounter auto-mount`, which mounts the `PersonalizedDMG`, and upgrade if an older
pymobiledevice3 (11.19.0 - 11.19.2) took the cryptex path there.

If `cryptex auto-install` fails on iOS 26.4 or later with *"cryptexd closed the connection without
replying"*, capture `pymobiledevice3 syslog live -m cryptexd` while running it and open an issue with
both.

### "Unable to connect to tunneld" (`TunneldConnectionError`)

You passed `--tunnel` (or the automatic fallback chose tunneld — which happens on Linux/Windows
with iOS 17.0–17.3, where the userspace tunnel has no reliable transport; macOS serves those devices
no-root via the native tunnel), but no tunneld daemon is running. Start one with root privileges
in a separate terminal and leave it running:

```shell
sudo "$(which pymobiledevice3)" remote tunneld
```

On Windows, run `pymobiledevice3 remote tunneld` from an Administrator terminal instead. See
[Running with `sudo`](../installation.md#running-with-sudo) for why the full path is needed on
Linux.

### "This command requires root privileges" / "admin privileges" (`AccessDeniedError`)

The requested operation needs elevated privileges — typically creating a kernel tunnel
(`remote start-tunnel`, `remote tunneld`). Re-run with `sudo` (macOS/Linux; see
[Running with `sudo`](../installation.md#running-with-sudo)) or from an Administrator shell
(Windows). For developer commands, prefer the default no-root userspace
tunnel instead — it requires no privileges at all.

### `PskCipherNotSupportedError`

Your Python's SSL backend cannot negotiate the PSK ciphers the TCP tunnel requires — typical
for interpreters linked against LibreSSL, such as Apple's `/usr/bin/python3`. Reinstall on a
uv-managed Python, which is linked against OpenSSL:

```shell
uv tool install --reinstall --managed-python pymobiledevice3
```

Or use any other Python build linked against OpenSSL (e.g. the
[python.org](https://www.python.org/downloads/) installer, or `brew install python`).

### `QuicProtocolNotSupportedError`

Apple removed QUIC tunnel support in iOS 18.2+. Drop the QUIC protocol selection
(`--protocol quic`) and use a TCP tunnel (`--protocol tcp`).

## WebInspector

### "Web Inspector is disabled" (`WebInspectorNotEnabledError`)

Enable it on the device: *Settings → Apps → Safari → Advanced → Web Inspector* (on iOS 17 and
earlier, *Settings → Safari → Advanced*).

### "Remote Automation is disabled" (`RemoteAutomationNotEnabledError`)

Automation commands (`webinspector launch`, `webinspector js-shell --automation`,
`webinspector shell`) additionally require *Remote Automation* in the same *Advanced* menu.

## Backup

### Encrypted backups

If the device has backup encryption enabled, commands that read backup contents need the
password: pass `--password` (`-p`) to `backup2` subcommands. A
`BackupFilterPasswordRequiredError` means you combined a filtered backup with
`--patch-manifest` on an encrypted backup — that also requires `--password`, so the manifest
can be decrypted and re-encrypted.

### "device asked the host to free N bytes"

The device decided the backup destination is too small and asked the host to make room
(`DLMessagePurgeDiskSpace`). pymobiledevice3 has no way to reclaim space on your behalf, so it
answers "failed to purge" — exactly like Apple's own host does when its purge fails — and lets
the device report what it wants to do next.

Free up at least the requested number of bytes and retry. Note that the first filtered backup
still transfers *all* backup bytes from the device (filtering saves disk, not transfer) — budget
space accordingly.

Run with `-vv` to also see the figure the host reported for `DLMessageGetFreeDiskSpace`; that is
the number the device compared against, and it comes from `statvfs` on the backup directory (on
macOS, raised to the purgeable-aware capacity Finder uses).

## Still stuck?

- Re-run with `-vv` and read the debug logs.
- Search the [GitHub issues](https://github.com/doronz88/pymobiledevice3/issues).
- Ask on [Discord](https://discord.gg/52mZGC3JXJ).
