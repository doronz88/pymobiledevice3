# Chip Stability Matrix

Empirical findings about which peripheral nonces survive the normal-mode → restore-mode transition. Determines which prefetched TSS tickets stay valid (cache hits) vs. which always drift (forcing a reactive POST).

## Verified on iPhone 12,1 / iOS 27.0 / build 24A5355q

| Chip | In `PreflightInfo.DeviceInfo`? | Nonce stable across mode transition? | Cache hits during restore? | Reason |
|---|---|---|---|---|
| **SE / Secure Enclave** | yes (`SE`) | ✅ stable | yes | nonce rooted in SEP boot session, latched per boot |
| **T200 / BMU (battery management)** | yes (`T200`, bare-name fields) | ✅ stable | yes | low security stakes, boot-stable by design |
| **Rose / Rap (wireless coprocessor)** | yes (`Rose`) | ❌ regenerates | no (drifts both queries) | handles secure routing / U1; rotates per state change for replay resistance |
| **Savage (legacy biometric coprocessor)** | yes (`Savage`) | ❌ regenerates | no (drifts at restore-mode entry) | high-security, rotates aggressively |
| **Cryptex1** | **no** (NOT in `DeviceInfo`) | n/a (no pre-restore source) | n/a | nonce only reachable via `restoreserviced` RemoteXPC, which requires `com.apple.private.RestoreRemoteServices.restoreservice.remote` |
| **Baseband** | no (separate `FirmwarePreflightInfo`) | partial | yes via AP batch only | handled in `Recovery.get_tss_response` + `send_baseband_data`, not `PREFETCHABLE_UPDATERS` |
| **AppleTCON / Baobab** | no (not on this SoC) | n/a | n/a | iPhone 12 doesn't have a TCON. Likely on iPad Pro / iPhone 15+. |
| **AppleTypeCRetimer / Timer** | no (not on this SoC) | n/a | n/a | USB-C retimer; iPhone 15+. |
| **Yonkers** | no | n/a | n/a | Older Savage variant; not on A13. |

## Verified on iPhone 18,4 / iPhone Air / D23AP / A19 (ChipID 0x8150) / iOS 27.0 / build 24A5355q

TSS dry-run + a live ramrod-diff restore (build 24A5355q, --no-erase, succeeded). All 5 device peripheral tickets sign in **one** combined POST.

| Chip | `PreflightInfo.DeviceInfo` shape on A19 | TSS ticket | In batch? | Notes |
|---|---|---|---|---|
| **SE** | flat `SE` entry, also carries `SE,OSUPubKeyID` | ✅ **`SE2,Ticket`** | yes | A19 uses the **SE2** generation, not the legacy `SE,Ticket`. Ramrod capture: `ResponseTags == ['SE2,Ticket']`; DeviceGeneratedRequest = `SE,ChipID/ID/Nonce/RootKeyIdentifier` + `SE,RapRTKitOS`/`SE,RapSwBinDsp` (Digest) + `SE,UpdatePayload` (Production hash). Fixed by new `add_se2_tags`; `add_se_tags` kept for the legacy reactive path. `SE,OSUPubKeyID` is NOT sent. |
| **Rose / Rap** | flat `Rose` (`Rap,*`) | ✅ `Rap,Ticket` | yes | nonce drifts at restore-mode entry (reactive fallback) |
| **Savage** | **nested**: `JasmineIR1DeviceInfo` + `YonkersDeviceInfo` (no flat `Savage,Nonce`) | ✅ **`Yonkers,Ticket`** | yes | A19 Savage is a Yonkers part. The flat `Savage,Nonce` lookup silently dropped it until the `Savage` `PrefetchableUpdater` grew a `variants` list (Yonkers nested-shape first, flat-Savage fallback) mirroring `get_device_generated_firmware_data`. |
| **T200 / BMU** | bare-name fields (unchanged) | ✅ `BMU,Ticket` | yes | stable |
| **Centauri** | `Centauri` (`Wireless1,*`), has `Wireless1,Nonce` + `RestoreBootNonce` | ✅ **`Wireless1,Ticket`** | yes | Restore updates it (`usr/lib/updaters/libCentauriUpdater.dylib`). Ticket `@Wireless1,Ticket` (RE: `libauthinstall.dylib` + `libCentauriUpdater.dylib`). Personalized like Rose/Rap (new `add_centauri_tags`) **plus** two fields restored always sends that PreflightInfo doesn't expose: `Wireless1,UID_MODE` (False) and `Wireless1,FdrRootCaDigest` (b''). Without those two, TSS returns an opaque "internal error". |
| **Vinyl / eUICC** | `Vinyl` (`eUICC,*`), nested `Gold`/`Main` nonces | ✅ **`eUICC,Ticket`** | yes | Fires its own device-generated request during restore (`libVinylUpdater.dylib`). `add_vinyl_prefetch_tags` shim feeds the nested `eUICC,Gold.Nonce`/`eUICC,Main.Nonce` into `add_vinyl_tags`. Cache lookup uses a **composite nonce** (`nonce_path` = both nonces concatenated) so a stale Main can't false-hit. |
| **Baseband** | `Baseband` (`Cellular1,*`) | ✅ **`Cellular1,Ticket`** | yes | A19 fires a device-generated `Cellular1,Ticket` (ramrod capture). New `add_cellular_tags` (Rose/Centauri-style over `Cellular1,*`). TSS signs it from the `PreflightInfo.Baseband` fields alone — the `Cellular1,Bb*ManifestKeyHash` fields are included when present but `firmware_preflight_info` was None on this unit and TSS signed without them. (NOT the legacy `Bb*` AP-batch path.) |

### Definitive list of restore firmware-updater plugins (`usr/lib/updaters/`)

The authoritative set of peripherals `restored` fires firmware updates for is the plugin list, NOT pymobiledevice3's reactive branches (on iOS 18+ the generic `get_device_generated_firmware_data` path serves any of them):

```
libAce3Updater  libAppleTCONUpdater  libAppleTCONTwoStageUpdater  libAppleTconUARPUpdater
libCentauriUpdater  libPS190Updater  libRoseUpdater  libSavageUpdater_iOS
libSavageRestoreInfo_iOS  libSEUpdater  libT200Updater  libVinylUpdater
```

All 7 `PreflightInfo.DeviceInfo` peripherals are now prefetched. Ace3/PS190/TCON have updater plugins but no `DeviceInfo` entry on this SoC; Cryptex1 / Cryptex1LocalPolicy fire device-generated requests but aren't in `DeviceInfo` (no pre-restore nonce, and Cryptex1LocalPolicy is an `@ApImg4Ticket` the peripheral batch must exclude) — all un-prefetchable.

**Net on iPhone Air:** all **7** `DeviceInfo` peripheral tickets sign in a SINGLE combined POST — **SE (SE2), Rose, Savage→Yonkers, T200, Centauri, Vinyl (eUICC), Baseband (Cellular1)**. Cache HIT depends on nonce stability: SE + T200 hit; Rose/Savage/Centauri (and likely eUICC/Cellular1) rotate at restore-mode entry → graceful reactive fallback.

### Code changes
1. the `Savage` `PrefetchableUpdater` uses a `variants` list + the loop resolves `preflight_subkey` (nested-dict navigation) so the Yonkers shape isn't dropped.
2. `_prefetch_combined_batch` falls back to `_prefetch_per_chip` on combined-POST failure, so one rejected chip never denies the others their tickets.
3. New `add_se2_tags` (@SE2,Ticket) — SE entry retargeted to `SE2,Ticket`. Legacy `add_se_tags` retained for the reactive pre-SE2 path.
4. New `add_centauri_tags` (@Wireless1,Ticket) incl. the `Wireless1,UID_MODE` + `Wireless1,FdrRootCaDigest` fields restored synthesizes.
5. New `add_vinyl_prefetch_tags` (@eUICC,Ticket) + **composite-nonce** support (`nonce_path` / `devgen_nonce_path`, resolved by `_resolve_nonce`/`_dig`) for the Gold+Main nonce pair.
6. New `add_cellular_tags` (@Cellular1,Ticket) for A19 device-generated baseband.

### How SE + Centauri were cracked (ramrod diff)
Ran a reactive restore (no `--tss-batch`) on the A19, captured each peripheral's `get_device_generated_firmware_data (<chip>): {...}` log line (the device's own `DeviceGeneratedRequest` + `DeviceGeneratedTags.ResponseTags`), and field-diffed against what our helpers built. SE's `ResponseTags` revealed `SE2,Ticket`; Centauri's diff revealed the two synthesized fields. This is the canonical use of `references/diff-against-ramrod.py.template`.

## Verified on iPhone 18,5 / V159AP / A19 Pro (ChipID 0x8150) / iOS 27.0 / build 24A5355q

Dry-run **plus a full live `restore update --tss-batch`** (succeeded end-to-end). The existing
`PREFETCHABLE_UPDATERS` needed **no change** — all prefetchable peripherals on this SoC sign in
**one** combined POST, and the live restore measured the cache outcome:

```
prefetched up-front : 4 ['SE', 'Savage', 'T200', 'Baseband']
cache hits          : 2 ['T200', 'SE']
nonce-drift misses  : 2 ['Savage', 'Baseband']   → graceful reactive fallback
>> gs.apple.com POSTs saved during restore: 2
```

Same stability profile as iPhone 18,4: **SE + T200 hold across the mode transition; Savage
(Yonkers) + Baseband (Cellular1) rotate.**

`PreflightInfo.DeviceInfo` exposed: **Ace3, Baseband, SE, Savage, T200** (no Rose / Centauri /
Vinyl — correctly skipped).

| Chip | `DeviceInfo` shape | TSS ticket | In batch? | Notes |
|---|---|---|---|---|
| **SE** | flat `SE` (`SE,ChipID` int 56, `SE,Nonce` 20B) | ✅ **`SE2,Ticket`** | yes | A19 Pro uses SE2, same as iPhone Air. |
| **Savage** | both nested `YonkersDeviceInfo` **and** flat `Savage,*` present | ✅ **`Yonkers,Ticket`** | yes | Yonkers variant resolves first and wins (mirrors `get_device_generated_firmware_data`). |
| **T200 / BMU** | bare-name fields | ✅ `BMU,Ticket` | yes | stable. |
| **Baseband** | `Baseband` (`Cellular1,*`) | ✅ **`Cellular1,Ticket`** | yes | signs from `PreflightInfo.Baseband` alone (`firmware_preflight_info` not needed). |
| **Ace3** | `Ace3`: `TicketName='USBPortController1,Ticket'`, `ManifestPrefix='USBPortController'`, `LocalSigningID=False`, `RestoreSystemPartition` — **no nonce field** | `USBPortController1,Ticket` | **no** | New: present in `DeviceInfo` here (absent on 18,4). Carries **no `<X>,Nonce` / bare `Nonce`**, so the nonce-match prefetch can't track it. The live restore confirmed it fires its own reactive `get_device_generated_firmware_data (Ace3)` request (USB-C ACE3 port controller). Un-prefetchable via this mechanism; left out by design. |

Reactive-only chips observed firing during the live restore (all un-prefetchable, as expected):
**Ace3** (`USBPortController1,Ticket`, nonceless), **Cryptex1** (per-boot `Nonce` not exposed
pre-restore), **Cryptex1LocalPolicy** (an `@ApImg4Ticket` the peripheral batch must exclude).

**Net on iPhone 18,5:** **4** tickets — SE (SE2), Savage→Yonkers, T200 (BMU), Baseband
(Cellular1) — sign in a SINGLE combined POST. No new `add_*_tags` helper or table entry
required; the iPhone Air work already covers this SoC.

### Experiment: does entering recovery via RestoreService change drift? (NO)

Hypothesis: the standard `lockdown.enter_recovery()` path rotates the volatile nonces, and a
different recovery-entry path (`RestoreService.recovery` over RemoteXPC) might preserve them →
more cache hits. **Tested end-to-end and refuted.**

Ran the full live restore above with recovery entered via `RestoreService.enter_recovery()`
(monkeypatched `LockdownClient.enter_recovery`; the `recovery` command returned `success` and
drove the device into recovery normally). Result: **identical** outcome to the lockdown path —
SE + T200 hit, Savage + Baseband drift. The drift is intrinsic to the device crossing into
restore mode (the coprocessors re-latch their nonces for the new boot session as anti-replay),
**not** a function of which host command triggered the transition. Confirms the boot/mode-
transition model in the rows above; the entry path is irrelevant to prefetch cache hits.

## Within normal mode

Back-to-back PreflightInfo queries 10 minutes apart returned **identical** nonces for every chip including Rose. The rotation trigger is state-change (the normal↔restore mode boundary, and for Rose, also per-query inside restore), NOT wall-clock time. So a 30-minute sleep between prefetch and `boot_ramdisk` would not invalidate the cache — only entering recovery does.

## restoreserviced over RemoteXPC: device-specific, NOT universally closed

`com.apple.RestoreRemoteServices.restoreserviced` is advertised by remoted on a high port (49xxx) with `UsesRemoteXPC: true` and `Entitlement: com.apple.private.RestoreRemoteServices.restoreservice.remote`.

**On iPhone 12,1 / 18,4:** the XPC dispatcher rejected every request with `{'result': 'error'}`. A **480-shape probe** (11 envelope keys × 43 candidate commands + 8 payload variants) returned nothing useful. That earlier note read "closed door, settled" — but it was **device/build-specific, not universal**.

**On iPhone 18,5 / 27.0 (24A5355q): the service WORKS** (verified live via `RestoreService` in `services/restore_service.py`, over a tunneld RSD):
- `getnonces` → `{'result': 'nonces', 'apNonce': ..., 'sepNonce': ...}` (sepNonce came back all-`0xff`).
- `recovery` → `success`, and it actually drove the device into recovery for a full restore (see below).
- `getpreflightinfo` → connection dropped (`IncompleteReadError`); not usable as-is.

So restoreserviced is reachable from pymobiledevice3 on at least this unit. It still does **not** unlock peripheral prefetch: `getnonces` exposes only Ap/SEP (not the Rose/Savage/etc. coprocessor nonces), and `getpreflightinfo` — which might carry the peripheral DeviceInfo — drops the connection. Cryptex1's own per-boot nonce remains unreachable through the working commands. Worth re-probing per new device/build rather than assuming closed.

## What this means for adding new chips

When you onboard a new device (different SoC, newer iOS), follow this decision tree:

1. **Does `PreflightInfo.DeviceInfo` contain the chip?** → if yes, it's a candidate.
2. **Does the DeviceInfo entry contain a comma-prefixed nonce field?** (`<X>,Nonce`) → makes onboarding trivial.
3. **Does it contain a bare `Nonce` field?** (T200-style) → still doable, but you need to explicitly map the bare name to the chip's TSS prefix when adding to `PREFETCHABLE_UPDATERS`.
4. **Is there an `add_<chip>_tags` helper in `tss.py`?** → if yes, use it. If no, write one mirroring `add_veridian_tags` (simplest existing).
5. **Add to `PREFETCHABLE_UPDATERS`, dry-run, then validate live.** See SKILL.md.

If the chip is NOT in `PreflightInfo.DeviceInfo` and it fires reactive DataRequestMsgs during restore, it joins the **un-prefetchable** category alongside Cryptex1.

## Observed rotation behavior across multiple restores

Five restores (#1–#5) on the same device, all same build:

```
SE,Nonce                    : f0394231...   stable across all 5 restores within a boot
T200/BMU,Nonce              : 886ea4fb...   stable across all 5 restores within a boot
Rose Rap,Nonce              : different every restore + every per-query within restore mode
Savage,Nonce                : different every restore (rotates at restore-mode entry)
Cryptex1,Nonce              : different every restore (rotates per boot)
```

SE and T200 are the only stable chips on this device. The ~2 cache hits per restore in the live testing reflect this.
