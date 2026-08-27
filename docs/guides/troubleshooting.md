---
search:
  boost: 2
---

# Troubleshooting

Common failures mapped to their causes and fixes. Each section quotes the error message (or
exception name) the CLI prints, so you can search this page for what you're seeing.

For any problem, running with increased verbosity usually reveals what is going on:

```shell
pymobiledevice3 -vv <command...>
```

## Device discovery

### "Device is not connected" (`NoDeviceConnectedError`)

No device was found over usbmux.

- Check the cable and that the device shows up in `pymobiledevice3 usbmux list`.
- On Linux, make sure [usbmuxd](https://github.com/libimobiledevice/usbmuxd) is installed and
  running.
- On Windows, install iTunes from the
  [Microsoft Store](https://apps.microsoft.com/detail/9pb2mz1zmb1s) — it provides the Apple
  Mobile Device Support service that pymobiledevice3 relies on.
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

## Pairing and trust

### "Waiting for user dialog approval" (`PairingDialogResponsePendingError`)

The device is showing the *Trust This Computer?* dialog. Unlock the device, tap **Trust**, and
run the command again.

### "User refused to trust this computer" (`UserDeniedPairingError`)

**Don't Trust** was tapped. To make the dialog reappear, reset the device's trust decisions:
*Settings → General → Transfer or Reset iPhone → Reset → Reset Location & Privacy*, then
reconnect the cable.

### "Device is password protected. Please unlock and retry" (`PasswordRequiredError`)

Pairing (and some lockdown operations) require the device to be unlocked. Unlock it and retry.

### "Device is not paired" (`NotPairedError`)

The host has no valid pair record for this device. Create one:

```shell
pymobiledevice3 lockdown pair
```

If pairing keeps failing with an `InvalidHostIDError`, the device holds a stale record for this
host — unpair first (`pymobiledevice3 lockdown unpair`) or reset trust as described above, then
pair again.

## Developer services

### "Failed to start service" (`InvalidServiceError`)

The single most common error. A developer service was requested but the device can't provide
it yet. In order:

1. **Enable Developer Mode** (iOS 15+):

    ```shell
    pymobiledevice3 amfi enable-developer-mode
    ```

    This reboots the device. If it fails with *"Cannot enable developer-mode when passcode is
    set"* (`DeviceHasPasscodeSetError`), remove the device passcode temporarily — iOS refuses
    to enable Developer Mode automatically while one is set (you can instead enable it manually
    under *Settings → Privacy & Security → Developer Mode*).

2. **Mount the Developer Disk Image** (once per boot):

    ```shell
    pymobiledevice3 mounter auto-mount
    ```

    This downloads the correct image for your iOS version and caches it under
    `~/.pymobiledevice3` — no Xcode required. On iOS 17+ you can alternatively use
    `pymobiledevice3 cryptex auto-install` (see the
    [CLI recipes](cli-recipes.md#cryptexes-ios-17-rsd-tunnel)).

3. On **iOS 17+**, developer commands also need a tunnel — but you normally don't need to do
   anything: the CLI establishes a no-root userspace tunnel in-process automatically (you'll
   see a *"Trying again over a no-root userspace tunnel"* warning, which is normal). See
   [iOS 17+ tunnels](ios17-tunnels.md) for the full picture.

### "Unable to connect to Tunneld" (`TunneldConnectionError`)

You passed `--tunnel` (or the automatic fallback chose tunneld — which happens on
iOS 17.0–17.3, where the userspace tunnel has no reliable transport), but no tunneld daemon is
running. Start one with root privileges and leave it running:

```shell
sudo pymobiledevice3 remote tunneld
```

### `AccessDeniedError` / "This command requires root/admin"

The requested operation needs elevated privileges — typically creating a kernel tunnel
(`remote start-tunnel`, `remote tunneld`). Re-run with `sudo` (macOS/Linux) or from an
Administrator shell (Windows). For developer commands, prefer the default no-root userspace
tunnel instead — it requires no privileges at all.

### `PskCipherNotSupportedError`

Your Python's SSL backend cannot negotiate the PSK ciphers the TCP tunnel requires — typical
for interpreters linked against LibreSSL. Use a Python build linked against OpenSSL (e.g. the
[python.org](https://www.python.org/downloads/) installer, or `brew install python`).

### `QuicProtocolNotSupportedError`

Apple removed QUIC tunnel support in iOS 18.2+. Drop the QUIC protocol selection and use the
default TCP tunnel.

## WebInspector

### "Web Inspector is not enabled" (`WebInspectorNotEnabledError`)

Enable it on the device: *Settings → Safari → Advanced → Web Inspector*.

### "Remote Automation is not enabled" (`RemoteAutomationNotEnabledError`)

Automation commands (`webinspector launch`, `js-shell --automation`, `shell`) additionally
require: *Settings → Safari → Advanced → Remote Automation*.

## Backup

### Encrypted backups

If the device has backup encryption enabled, commands that read backup contents need the
password: pass `--password` to `backup2` subcommands. A
`BackupFilterPasswordRequiredError` means you combined a filtered backup with
`--patch-manifest` on an encrypted backup — that also requires `--password`, so the manifest
can be decrypted and re-encrypted.

### "Not enough disk space" (`NotEnoughDiskSpaceError`)

The host doesn't have room for the backup. Note that the first filtered backup still transfers
*all* backup bytes from the device (filtering saves disk, not transfer) — budget space
accordingly or free some up.

## Still stuck?

- Re-run with `-vv` and read the debug logs.
- Search the [GitHub issues](https://github.com/doronz88/pymobiledevice3/issues).
- Ask on [Discord](https://discord.gg/52mZGC3JXJ).
