# Restoring and updating devices

`pymobiledevice3 restore update` reimplements the host side of an IPSW restore:
what Finder, Xcode and idevicerestore do when they flash a device. This guide
explains the choices the command offers, what happens on the device, and which
requests go to Apple's signing server (TSS) along the way. The measured numbers
come from an iPhone18,4 on iOS 27.0 (build 24A435); they differ per device.

## What a restore does

1. **Normal mode.** The device is found through usbmuxd. Its build, ECID, AP
   and SEP nonces and the peripheral state (`PreflightInfo`) are read over
   lockdown, and the AP ticket is requested from TSS. Only then is the device
   sent into recovery mode.
2. **Recovery.** iBSS/iBEC are uploaded and the device is booted into the
   restore ramdisk from the IPSW.
3. **Restore mode.** The ramdisk's `restored` asks the host for everything it
   needs, item by item: the root filesystem, firmware components, per-peripheral
   tickets, the baseband, cryptexes. The host answers each request, proxying
   FDR traffic in between. This phase is where all the time goes.
4. **Reboot** into the new build.

If the device is already in recovery or DFU mode, step 1 is skipped: the tool
waits for such a device, identifies it by ECID (`--ecid` picks one when
several are connected) and starts from step 2. Nothing that needs lockdown is
available then, so anything derived from `PreflightInfo` (including
`--tss-batch`, below) is simply not done.

## Choosing the firmware

`-i` / `--ipsw` accepts a local path or an `http(s)://` URL. A URL is
downloaded to a temporary directory and deleted after the restore. With `-i`
omitted, the tool asks ipsw.me for the builds Apple currently signs for the
device's product type and lets you pick one interactively; that needs network
access and works from normal mode as well as recovery (the product type comes
from lockdown or from the recovery-mode device table).

Whatever the source, the build must be signed by Apple at restore time, since
the AP ticket comes from TSS. A `--tss` SHSH blob can be supplied for the AP
ticket instead of asking TSS; the peripheral tickets are still requested live.

## Update or erase

By default the restore is an **update in place**: the `Upgrade Install (IPSW)`
build identity is used, the data volume is kept, and the device comes back with
its apps and settings. `--erase` selects the `Erase Install (IPSW)` identity
instead: a factory reset that recreates the filesystem. Both go through the
same steps above; erase is what you want for a device stuck in recovery with no
usable data volume, or to wipe it.

`--ignore-fdr` is a debugging option: the host connects to the FDR service but
does not proxy its traffic.

## The helper commands

- `restore enter` puts a normal-mode device into recovery; `restore exit`
  re-enables auto-boot and reboots a recovery-mode device back to iOS;
  `restore restart` reboots either.
- `restore tss` requests (and with `--out` saves) the AP ticket for a build
  without restoring, `--behavior Update|Erase` selecting the identity.
- `restore ramdisk` boots the IPSW's restore ramdisk and stops there.
- `restore shell` opens an IPython shell with the iBoot (`irecv`) client of a
  recovery/DFU device.

## TSS requests during a restore

Every restore signs firmware against `gs.apple.com`. Without any flag:

1. **The AP request**, in normal mode, before the device enters recovery. It
   asks for `ApImg4Ticket` against the ECID, the AP and SEP nonces and the
   build manifest. When the build identity has a `RecoveryVariant`, a second AP
   request follows for the recoveryOS root ticket.
2. **One request per peripheral updater**, during the restore. `restored` asks
   for each chip's ticket with a `FirmwareUpdaterData` message; on iOS 18 and
   later the device builds the TSS request itself (`DeviceGeneratedRequest`)
   and the host adds the manifest digests and forwards it. On this device that
   is T200 (battery management), Rose (UWB), Centauri (Wi-Fi/Bluetooth), Savage
   (Face ID, two loops), SE (Secure Element), Vinyl (eSIM), Baseband, and after
   FDR sealing Rose again plus Cryptex1 and its local policy: 11 requests.

That is 13 sequential requests of about half a second each for a full update on
this device. Nothing is reused between restores: every chip carries a nonce and
most regenerate it at every boot.

### The empty preflight message

Before it asks for a chip's ticket, `restored` sends `FirmwareUpdaterPreflight`
for that chip. It does so because the host's restore options declare
`PersonalizedDuringPreflight`, which tells the device the host may already hold
tickets from a personalization done in normal mode. Apple's own host only fills
that stash for Apple displays (their USB-C and timing controllers); for iPhones
it answers with an empty dictionary, and so does pymobiledevice3. The message is
logged at debug level and is not a problem.

### `--tss-batch`

With the flag, the peripheral ticket requests are built up front from the
device's lockdown `PreflightInfo` (each chip's identity fields and current
nonce) plus the build manifest, and are sent **inside the AP request**. TSS
answers every ticket in that one response, so the prefetch adds no request.

During the restore, when `restored` asks for a chip's ticket, the host compares
the device's own request with what it signed, entry for entry (nonces, digests
and flags included). Only an identical request is answered from the prefetch;
any difference, or a request on which the device asks for a fresh
personalization (`MessageForceRepersonalization`, or any loop but the first),
goes to TSS as usual. A prefetched ticket is never served against a nonce the
chip has since discarded.

At the end of the restore a summary is logged:

```
TSS PREFETCH SUMMARY
  prefetched up-front : 7 ['SE', 'Rose', 'Centauri', 'Savage', 'T200', 'Vinyl', 'Baseband']
  hits                : 3 ['T200', 'SE', 'Vinyl']
  request mismatches  : 5 ['Rose', 'Centauri', 'Baseband', 'Savage', 'Rose']
  not prefetched      : 0 []
  >> TSS requests saved during the restore: 3
```

A hit saves one request. A mismatch costs nothing: the request the reactive
path would have made is made, and the log line names the entries that differed
(on this device always the chip's nonce). Which chips hit depends on whether
the chip keeps its nonce across the boot into the restore ramdisk:

| Chip | Nonce across the boot into the ramdisk | Outcome |
| --- | --- | --- |
| T200, SE, Vinyl | kept | served from the prefetch |
| Rose, Centauri, Baseband, Savage | regenerated | live request, as without the flag |
| Cryptex1 | not exposed before the restore | never prefetched |

Request count per restore on this device: 13 without the flag, 10 with it.

If TSS ever rejects the AP request because of a prefetched entry, the AP
request is retried alone and the restore proceeds with every chip on the live
path. That is the only case in which the flag costs a request, and it happens
before the device leaves normal mode. A chip whose request cannot be built is
left to the live path.

The flag is opt-in because it relies on pymobiledevice3 reproducing each chip's
request format from `PreflightInfo`; a format change in a future iOS build
turns into misses, not into wrong tickets, and the miss log shows which entries
no longer match. The per-chip request builders live in
`pymobiledevice3/restore/tss.py` (`PREFETCHABLE_UPDATERS`); the
`tss-batch-prefetch` skill in the repository describes how to validate and
extend them.
