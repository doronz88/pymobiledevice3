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
  └─ Restore._prefetch_combined_batch()              ← if --tss-batch (opt-in, default off)
       ├─ build ONE TSSRequest:
       │    common AP tags (ECID, ChipID, BoardID, SecurityDomain)
       │    per-peripheral: _merge_device_info(params, info) + add_<chip>_tags
       │    @<chip>,Ticket: True for each
       ├─ POST to gs.apple.com/TSS — get back all tickets in one response
       └─ cache per-peripheral: {nonce, response, ticket_name, devgen_nonce_field}

at restore time (from restored's DataRequestMsg):
  Restore.send_firmware_updater_data()
    └─ Restore.get_device_generated_firmware_data()   ← iOS 18+ path
         └─ _lookup_prefetched_tss_by_ticket(response_ticket, arguments)
              compares cached nonce vs arguments.DeviceGeneratedRequest[<devgen_nonce_field>]
              → cache HIT: serve cached, skip the POST
              → drift   : log + fall back to live POST
```

Key invariant in `_merge_device_info`: **a manifest-derived int never gets clobbered by a DeviceInfo-derived bytes value for the same key.** Without this, `Savage,ChipID` (which the manifest gives as int `1` but PreflightInfo gives as raw bytes `b'\x00\x00\x00\x01'`) gets sent as bytes and TSS rejects the whole batch with a misleading `"not eligible"` error.

## Onboarding a new device — diagnose in 4 commands

Run these against a fresh device in normal mode:

```bash
# 1. Confirm connectivity + capture build info
uvx --from . pymobiledevice3 lockdown info | head -20

# 2. Enumerate what PreflightInfo.DeviceInfo exposes on THIS device
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

1. **Dry-run only.** Construct a `Restore` object with `enable_tss_batch=True`, call `_prefetch_combined_batch()`, do not call `boot_ramdisk` or `restore_device`. See `references/dryrun-batched.py.template`. Confirm all expected `<X>,Ticket` keys come back in the response.
2. **Diff against ramrod** (only when something fails). Run a real restore once *without* `--tss-batch` and look at the `get_device_generated_firmware_data (X): {...}` log entry for that chip — that dict contains restored's own `DeviceGeneratedRequest`. Field-by-field compare it against what your batched POST sends. The mismatching field is the bug — see `references/diff-against-ramrod.py.template`. Most failures are typing mismatches (bytes vs int) on `ChipID` / `PatchEpoch` / `SecurityDomain`.
3. **Live restore with `--tss-batch`** only after the dry-run succeeds. Watch for `TSS prefetch CACHE HIT for <chip>` lines.

## Chips you should not add (the empirical findings)

Read `references/chip-stability-matrix.md` for the full per-chip table. Short version:

- **Cryptex1** — fires a DataRequestMsg during restore but its nonce isn't exposed in any non-entitled lockdown / MobileGestalt / PreflightInfo surface. Can't be prefetched without `com.apple.private.RestoreRemoteServices.restoreservice.remote`, which pymobiledevice3 doesn't carry.
- **Baseband** — already part of `Recovery.get_tss_response`'s AP batch when `firmware_preflight_info` provides BB state. Don't add to `PREFETCHABLE_UPDATERS` separately; it's a different code path with chip-specific nonce-rotation semantics in `send_baseband_data`.

You **can** add peripherals whose nonce rotates on the normal→restore mode transition (Rose, Savage). The drift is detected in `_lookup_prefetched_tss` and gracefully falls back to a reactive POST — no harm, slight win from sharing the batched POST.

## Quick scripts

- `references/dryrun-batched.py.template` — read-only TSS validation harness
- `references/diff-against-ramrod.py.template` — diff our request against the working DataRequestMsg shape

## Commit guidance

Per `AGENTS.md`:
- Use a scoped commit subject like `restore: Add <Chip>,Ticket to batched TSS prefetch`.
- Keep the `PREFETCHABLE_UPDATERS` edit and any new `add_*_tags` helper together in one commit — both now live in `tss.py`.
- Don't bundle this with unrelated cleanup.

## Out-of-scope (do NOT attempt from this skill)

- Probing `com.apple.RestoreRemoteServices.restoreserviced` over RemoteXPC to fetch chip state. 480-request shape probe was exhausted; every request returns `{'result': 'error'}` without the private entitlement. Recorded in `references/chip-stability-matrix.md`.
- Modifying `send_baseband_data` to bypass live POSTs. The AP-batch BBTicket reuse path is already coded; live POSTs there are dictated by per-chip baseband nonce rotation and are not safe to skip.
- Disabling `--tss-batch` as default. The default is opt-in by design — the batched POST changes wire-traffic shape and the user should consent.
