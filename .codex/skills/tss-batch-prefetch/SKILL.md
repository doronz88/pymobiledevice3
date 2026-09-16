---
name: tss-batch-prefetch
description: Maintain the batched TSS-prefetch list of peripheral updaters (`PREFETCHABLE_UPDATERS` in `pymobiledevice3/restore/tss.py`). Use when onboarding a new device model, debugging a TSS rejection of the combined POST, or extending the prefetch to cover additional chips (e.g. Cryptex1, Timer, TCON, future Apple peripherals). Walks through enumerating candidates from `PreflightInfo.DeviceInfo`, adding entries safely, and validating with a non-destructive dry-run before a live restore.
---

# TSS Batch Prefetch Maintainer

## What this skill is for

`pymobiledevice3 restore update --tss-batch` collapses N standalone TSS POSTs (one per peripheral updater) into a single batched POST. The set of peripherals included is hardcoded in `PREFETCHABLE_UPDATERS` (`pymobiledevice3/restore/tss.py`), co-located with the `add_*_tags` helpers it references; `Restore` imports it and drives the orchestration. Each entry pairs a `PreflightInfo.DeviceInfo` key with the matching `add_*_tags` helper.

Use this skill when:
- You connect a new device model (different SoC, newer iOS) and want to find out what additional chips are prefetchable
- The batched POST starts failing on a particular device or build
- You're debugging a `"This device isn't eligible for the requested build"` or `"An internal error occurred"` from TSS for a peripheral
- You want to add support for a new updater family (Timer, AppleTCON, Cryptex1, etc.)

## How the prefetch path works (essential mental model)

```
Restore.update()
  └─ Restore._prepare_tss_riders()                   ← if --tss-batch (opt-in, default off)
       ├─ per peripheral: _merge_device_info(params, DeviceInfo entry) + add_<chip>_tags on a
       │    scratch TSSRequest → that chip's request entries (@<chip>,Ticket: True + fields)
       └─ Recovery.tss_riders = all of them (one dict)
  └─ Recovery.boot_ramdisk() → fetch_tss_record() → get_tss_response()
       └─ Recovery._send_tss_request(): the AP request + the riders, ONE POST to gs.apple.com/TSS
            (riders never override an AP entry; consumed once — the RecoveryVariant re-fetch goes without)
            → rejected? retry the AP request alone; peripherals go reactive (only extra request there is)
  └─ Restore._store_tss_riders(): keep each <chip>,Ticket the AP response came back with,
       together with the request entries that were signed

at restore time (from restored's DataRequestMsg):
  Restore.send_firmware_updater_data()
    └─ Restore.get_device_generated_firmware_data()   ← iOS 18+ path
         └─ _lookup_prefetched_tss_by_ticket(response_ticket, arguments)
              compares the WHOLE arguments.DeviceGeneratedRequest against the signed entries
              (bytes by content, dicts entry for entry; extra signed entries are fine)
              → identical : serve the prefetched ticket, skip the live request
              → any diff  : log the keys, fall back to a live request (never a stale ticket)
```

TSS signs the AP ticket and every peripheral ticket in that one request (verified on iPhone18,4 /
iOS 27.0 24A435 for every combination of SE2, Rose, Savage, T200, Vinyl, Centauri). The prefetch
therefore costs no request of its own; each hit is one live request saved during the restore.

Key invariant in `_merge_device_info`: **a manifest-derived int never gets clobbered by a DeviceInfo-derived bytes value for the same key.** Without this, `Savage,ChipID` (which the manifest gives as int `1` but PreflightInfo gives as raw bytes `b'\x00\x00\x00\x01'`) gets sent as bytes and TSS rejects the whole batch with a misleading `"not eligible"` error.

## What Apple built the preflight mechanism for (and why iPhones only see the empty message)

Reverse-engineered from MobileDevice (macOS 27.0) and restored_external / restoreserviced (iOS 27.0):

- The host-side stash lives in `AMRAuthInstallCopyAllPreflightOptions`: updaters set up from a
  per-chip `DeviceInfo`/`DeviceInfoTags`/`DeviceInfoRequests` dictionary, personalized in normal
  mode, tickets written under `<PersonalizedRestoreBundlePath>/amai/<Updater>/<tag>`, and served
  by `_handleFirmwareUpdaterPreflight` (`{"FirmwareResponsePreflight": {tag: ticket}}`) plus
  `AMRestoreUpdaterPersonalize` (skips TSS on a stash hit unless `MessageArgUpdaterLoopCount != 0`
  or `MessageForceRepersonalization`).
- Every iPhone updater in the host table is flagged "device restore info" and needs
  `DeviceInfoTags` + `DeviceInfoRequests`. The lockdown path never supplies them, and the RemoteXPC
  path (`AMRemoteServiceDeviceProxy::Restore` → restoreserviced `getdevicesidepreflightinfo`)
  builds the payload only for `DeviceClass == "AppleDisplay"`: Ace3 (USB-C port controllers) and
  Banyan (`Baobab,TCON`). The device-side consumers of `PreflightTickets` are Ace3, PS190,
  AppleTypeCRetimer, T200 and AppleConvergedFirmwareUpdater-based updaters, with contexts named
  `OTA Preflight`, `NeRD Preflight`, `Tethered Preflight`: displays, Macs and OTA updates.
- iPhones send `FirmwareUpdaterPreflight` only because the host option
  `PersonalizedDuringPreflight` is set (Apple sets it whenever the AP/baseband were personalized in
  normal mode; we set it unconditionally). Apple's host answers `{}` for every iPhone chip and
  signs reactively; pymobiledevice3 does the same. `--tss-batch` is therefore a pymobiledevice3-only
  use of the mechanism, and it deliberately serves on the later `FirmwareUpdaterData` request
  (where the device's own request can be compared) rather than through `FirmwareResponsePreflight`.

## Onboarding a new device — diagnose in 4 commands

Run these against a fresh device in normal mode:

```bash
# 1. Confirm connectivity + capture build info
uvx --from . pymobiledevice3 lockdown info | head -20

# 2. Enumerate what PreflightInfo.DeviceInfo exposes on THIS device
#    (`pymobiledevice3 restore preflight` prints the same three dictionaries as JSON; the snippet
#    below shows the types/lengths that matter for add_*_tags)
uvx --from . python3 -c "
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux
async def main():
    ld = await create_using_usbmux()
    p = await ld.get_value('', 'PreflightInfo')
    di = p.get('DeviceInfo') or {}
    print('peripherals exposed:', sorted(di.keys()))
    for chip, fields in di.items():
        print(f'\n[{chip}]')
        for k, v in fields.items():
            t = type(v).__name__
            if isinstance(v, (bytes, bytearray)):
                print(f'  {k:35s} ({t} len={len(v)}): {bytes(v).hex()[:64]}')
            elif isinstance(v, dict):
                print(f'  {k:35s} ({t}): keys={list(v.keys())[:6]}')
            else:
                print(f'  {k:35s} ({t}): {v!r}')
asyncio.run(main())
"

# 3. Dry-run the existing batched POST (read-only against TSS, no device touch)
#    See references/dryrun-batched.py.template for a starter — copy to /tmp/ and run.

# 4. If you want to find peripherals that DataRequestMsg fires for but DeviceInfo doesn't expose,
#    do a real restore once with --tss-batch and look for `get_device_generated_firmware_data (X):`
#    lines in the log. Anything not in PREFETCHABLE_UPDATERS is a candidate IF its state is also
#    visible pre-restore (often it isn't — see references/chip-stability-matrix.md).
```

## Adding a new peripheral to the batch

For each candidate from step 2, you need four pieces of metadata. Find them by:

| Metadata | How to get it |
|---|---|
| `preflight_key` | The exact key in `PreflightInfo.DeviceInfo`. Step 2 output. |
| `preflight_nonce` | The nonce field name inside that DeviceInfo entry (e.g. `Rap,Nonce`, or bare `Nonce` for T200-style chips with no prefix). |
| `ticket_name` | The response key TSS returns. Same as `@<X>,Ticket` in the request. Derive from `add_<chip>_tags`'s `self._request["@<X>,Ticket"] = True` line in `tss.py`. |
| `devgen_nonce` | The nonce field name in `DataRequestMsg.Arguments.DeviceGeneratedRequest` at restore time. **Often differs from `preflight_nonce` for chips like T200** where `PreflightInfo` uses bare names but restored uses prefixed ones. Capture from a real restore log via `get_device_generated_firmware_data (X): ...`. |
| `add_tags` | The `TSSRequest` helper, passed as the function object itself (e.g. `TSSRequest.add_se2_tags`, `TSSRequest.add_rose_tags`) — not a string. It's called as `add_tags(tss, parameters, None)`. |

Then add a `PrefetchableUpdater` to `PREFETCHABLE_UPDATERS` in `tss.py` (a tuple of
`PrefetchableUpdater`, each holding a list of `PrefetchVariant` — see the dataclass
definitions in `tss.py` for every field):

```python
PrefetchableUpdater("NewChip", "<DeviceInfo key>", [
    PrefetchVariant(
        ticket_name="<X>,Ticket",
        add_tags=TSSRequest.add_<chip>_tags,
        preflight_nonce="<nonce field in DeviceInfo>",
        devgen_nonce="<nonce field in DeviceGeneratedRequest>",
    ),
]),
```

A chip with more than one on-device shape (cf. Savage's flat `Savage,*` vs nested
`YonkersDeviceInfo`) gets one `PrefetchVariant` per shape, tried in order until one
whose nonce is present wins. A composite nonce (cf. Vinyl's `eUICC,Gold.Nonce` +
`eUICC,Main.Nonce`) uses `nonce_path=` / `devgen_nonce_path=` instead of the single-key
`preflight_nonce=` / `devgen_nonce=`.

If the chip lacks an `add_<chip>_tags` helper in `tss.py`, add one mirroring the pattern of `add_savage_tags` / `add_veridian_tags`. The helper's job is to copy the chip's fields onto the request and set `@<X>,Ticket: True`.

## Validation protocol — DO NOT skip

A wrong entry will silently fail the batched POST and TSS returns useless error messages (`"not eligible"`, `"internal error"`). Validate non-destructively before any restore:

1. **Dry-run only.** Construct a `Restore` object with `enable_tss_batch=True`, call `_prepare_tss_riders()` and then `recovery.get_tss_response()`; do not call `boot_ramdisk` or `restore_device`. See `references/dryrun-batched.py.template`. Confirm `recovery.tss_riders_applied` is True and every expected `<X>,Ticket` key comes back in the response.
2. **Diff against ramrod** — always, not only on failure, because the prefetch is served on an exact match: run a real restore once *without* `--tss-batch` and take the `get_device_generated_firmware_data (X): {...}` log entry for each chip (restored's own `DeviceGeneratedRequest`). Without a restore, `pymobiledevice3 restore preflight-requests -i <ipsw> --updater <X>` returns the request the device builds in normal mode; it is the ramdisk's for T200 and Rose, but two entries short for SE and merged for Savage, so prefer the restore log when you have one. Compare it entry for entry against the tracked `request` your rider built — `Restore._request_mismatches(device_request, ours)` is the same check the restore uses. Anything but the nonce must match, or the chip will never hit. See `references/diff-against-ramrod.py.template`. Typical gaps: entries restored synthesizes that `PreflightInfo` lacks (`Rap,FdrRootCaDigest`, `Wireless1,UID_MODE`, `UniqueBuildID`), typing (bytes vs int) on `ChipID` / `PatchEpoch` / `SecurityDomain`.
3. **Live restore with `--tss-batch`** only after that. Watch for `TSS prefetch HIT for <chip>` lines and the summary at the end.

## Chips you should not add (the empirical findings)

Read `references/chip-stability-matrix.md` for the full per-chip table. Short version:

- **Cryptex1** — fires a DataRequestMsg during restore but its nonce isn't exposed in any non-entitled lockdown / MobileGestalt / PreflightInfo surface. Can't be prefetched without `com.apple.private.RestoreRemoteServices.restoreservice.remote`, which pymobiledevice3 doesn't carry.
- **Savage on A19** — its normal-mode `DeviceInfo` merges the JasmineIR1 and Yonkers parts, but restored asks for them as two separate loops (JasmineIR1 first, Yonkers second) with a nonce each; neither ever matches. Left in the table for the older flat-`Savage,*` SoCs.

You **can** keep peripherals whose nonce rotates on the normal→restore mode transition (Rose, Centauri, Baseband, Savage): the mismatch is detected entry for entry in `_lookup_prefetched_tss_by_ticket` and falls back to a live request. They cost nothing (they ride in the AP request) but they also save nothing on such a device; see the matrix for which chips are stable where.

## Quick scripts

- `references/dryrun-batched.py.template` — read-only TSS validation harness
- `references/diff-against-ramrod.py.template` — diff our request against the working DataRequestMsg shape

## Commit guidance

Per `AGENTS.md`:
- Use a scoped commit subject like `restore: Add <Chip>,Ticket to batched TSS prefetch`.
- Keep the `PREFETCHABLE_UPDATERS` edit and any new `add_*_tags` helper together in one commit — both now live in `tss.py`.
- Don't bundle this with unrelated cleanup.

## Out-of-scope (do NOT attempt from this skill)

- Fetching device-built requests from `com.apple.RestoreRemoteServices.restoreserviced` (`getdevicesidepreflightinfo`) to replace the `add_*_tags` helpers. It works (see the matrix), but it needs the chip's firmware files pushed to the device, one RemoteXPC connection per command, and it returns the same normal-mode nonces `PreflightInfo` already reports — no extra hits.
- Modifying `send_baseband_data` to bypass live POSTs. The AP-batch BBTicket reuse path is already coded; live POSTs there are dictated by per-chip baseband nonce rotation and are not safe to skip.
- Disabling `--tss-batch` as default. The default is opt-in by design — the batched POST changes wire-traffic shape and the user should consent.
