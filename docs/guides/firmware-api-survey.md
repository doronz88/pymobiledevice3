# Surveying a new iOS build for host-facing APIs

When a new iOS build ships, pymobiledevice3 needs to know which device services
appeared, disappeared, or changed. This guide is the repeatable recipe I use to
answer "what did Apple add that we should talk to?" from two extracted IPSW
filesystems, without a device. It was written while diffing
`iPhone18,4_26.0_23A341` against `iPhone18,4_27.0_24A435`.

Everything here is static analysis. Treat the output as a list of leads: every
lead still has to be confirmed against a real device (`pymobiledevice3 remote
browse`, `lockdown start-service`, or the service itself) before it is
implemented.

## Inputs

- Two extracted root filesystems for the **same device model**, old and new
  (for example `~/dev/research/ipsw/<model>_<version>_<build>_Restore/`).
  Same model matters: daemon lists differ per hardware class and would drown
  the diff in noise.
- The Xcode DDI that matches the new build. On macOS it is at
  `/Library/Developer/DeveloperDiskImages/iOS_DDI/Restore/*.dmg` (two variants
  per platform; either one works for the daemon list). Check
  `version.plist` next to it for `ProductBuildVersion`.
- A checkout of this repo, to compare against what is already implemented.

Set these once:

```sh
OLD=~/dev/research/ipsw/iPhone18,4_26.0_23A341_Restore
NEW=~/dev/research/ipsw/iPhone18,4_27.0_24A435_Restore
```

## 1. Lockdown services

Since iOS 17 there is no `/System/Library/Lockdown/Services.plist` on disk.
The service table is an XML plist embedded inside `/usr/libexec/lockdownd`.
Extract it from both builds and diff:

```python
# lockdown_services.py <lockdownd> <out.plist>
import plistlib, re, sys
data = open(sys.argv[1], 'rb').read()
blobs = [b for b in re.findall(rb'<\?xml version="1.0" encoding="UTF-8"\?>.*?</plist>', data, re.S)
         if b'com.apple.afc' in b]
plistlib.dump(plistlib.loads(blobs[0]), open(sys.argv[2], 'wb'), fmt=plistlib.FMT_XML)
```

```sh
python3 lockdown_services.py $OLD/usr/libexec/lockdownd old-lockdown.plist
python3 lockdown_services.py $NEW/usr/libexec/lockdownd new-lockdown.plist
diff old-lockdown.plist new-lockdown.plist
```

The table maps service names to how lockdownd launches them
(`XPCServiceName` or `ProgramArguments`), plus flags such as
`AllowUnactivatedService`. A service switching from `ProgramArguments` to
`XPCServiceName` means it grew a launchd plist of its own, which is where new
`RemoteServices` or IOKit launch triggers show up.

## 2. RemoteXPC services (RSD)

RSD advertises whatever launchd plists declare under a `RemoteServices` key.
Scan `System/Library/LaunchDaemons` and `System/Library/DeveloperModeLaunchDaemons`
(the latter only load with Developer Mode on):

```python
# ld_dump.py <root> <out.json>
import json, os, plistlib, sys
root, out = sys.argv[1], {}
for sub in ('System/Library/LaunchDaemons', 'System/Library/DeveloperModeLaunchDaemons'):
    d = os.path.join(root, sub)
    for f in sorted(os.listdir(d)):
        with open(os.path.join(d, f), 'rb') as fh:
            pl = plistlib.load(fh)
        out[f] = {'dir': sub, 'Label': pl.get('Label'),
                  'Program': pl.get('Program') or (pl.get('ProgramArguments') or [None])[0],
                  'MachServices': sorted((pl.get('MachServices') or {}).keys()),
                  'RemoteServices': pl.get('RemoteServices')}
json.dump(out, open(sys.argv[2], 'w'), indent=1, default=str)
```

Diff the `RemoteServices` dictionaries by service name. The fields that decide
whether pymobiledevice3 can reach a service:

- `RequireEntitlement`: the host-side entitlement remoted checks. Values
  such as `AppleInternal` or `com.apple.private.*` are still reachable from
  our side; remoted trusts the paired host's declared entitlements. Note it,
  but do not discard the lead.
- `ExposedToUntrustedDevices`: `true` means reachable without pairing;
  a list such as `["PreSetup", "HasInternalSecurityPolicies"]` means only in
  those device states (internal builds, or before Setup Assistant finishes).
- `LimitExposedToDeviceType` / `LimitExposedFromDeviceType`: restricts by link
  type (`ncm-device` is our USB link) or by the peer's device class
  (`compute-node`).
- `ServiceProperties.Features` / `ServiceVersion`: the versioned capability
  list. A `Features` change on an existing service is as interesting as a new
  service.
- `UsesRemoteXPC: false` means a raw socket protocol (lockdown, CoreDeviceProxy),
  not XPC framing.

Also grep the daemon's `Program` for existence. A plist can declare a service
whose binary is only on internal builds (`/usr/appleinternal/...`); that lead
is dead on customer firmware.

## 3. CoreDevice services (DDI)

`com.apple.coredevice.*` services are **not** in the IPSW. They live in the
Xcode DDI, which is mounted onto the device at `/System/Developer`:

```sh
mkdir -p /tmp/ddi && hdiutil attach -readonly -nobrowse -mountpoint /tmp/ddi \
    /Library/Developer/DeveloperDiskImages/iOS_DDI/Restore/<first>.dmg
python3 ld_dump.py /tmp/ddi ddi.json   # adjust the script's dirs to Library/LaunchDaemons
hdiutil detach /tmp/ddi
```

Each CoreDevice daemon lists its `Features` (for example
`com.apple.coredevice.feature.installroot`). Diff those against the previous
Xcode's DDI and against `pymobiledevice3/remote/core_device/`. Keep an older DDI
around; Xcode replaces the one under `/Library/Developer` on update.

## 4. Instruments (DTX) channels

`DVTInstrumentsFoundation` and `DTServiceHub` ship in the OS itself under
`System/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework`, launched
from `DeveloperModeLaunchDaemons`. They are not in the DDI. Channel names are
plain strings:

```sh
F=System/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DVTInstrumentsFoundation
diff <(strings -n 8 $OLD/$F | grep '^com.apple.instruments.server.services.' | sort -u) \
     <(strings -n 8 $NEW/$F | grep '^com.apple.instruments.server.services.' | sort -u)
```

Compare with the `IDENTIFIER` constants under
`pymobiledevice3/services/dvt/instruments/`.

## 5. Per-daemon protocol diffs

For every daemon behind a service you care about, diff its strings. Three
filters cover most of the signal:

```sh
B=usr/libexec/remoted
# service names and notification names
diff <(strings -n 6 $OLD/$B | grep '^com\.apple\.' | sort -u) <(strings -n 6 $NEW/$B | grep '^com\.apple\.' | sort -u)
# CamelCase identifiers: plist keys, request names, RSD properties, MG keys (kMGQ*)
diff <(strings -n 4 $OLD/$B | grep -E '^[A-Z][A-Za-z0-9]{3,40}$' | sort -u) \
     <(strings -n 4 $NEW/$B | grep -E '^[A-Z][A-Za-z0-9]{3,40}$' | sort -u)
# log messages: they name the new behaviour in English
diff <(strings -n 8 $OLD/$B | sort -u) <(strings -n 8 $NEW/$B | sort -u) \
  | grep '^[<>]' | grep -vE '^[<>] (_|\$s|-\[|\+\[|__|<)' | grep -E '[A-Za-z]{4}.* '
```

Things to know when reading the output:

- Swift string literals of 15 bytes or fewer are inline immediates and never
  appear in `strings`. Codable keys such as `allowsPairSetup` come out of the
  **framework** (`RemotePairingDevice.framework`), not the daemon, and even
  there short ones are missing. Log messages are the reliable signal.
- ObjC daemons expose their request handlers as selector names
  (`-[Foo handleXRequest:]`) and their wire keys as plain strings.
- `kMGQ*` strings in lockdownd are MobileGestalt keys it can serve through
  `GetValue`; a new `kMGQ*` usually means a new lockdown key.
- Some daemons live in the cryptexes: look under
  `private/preboot/Cryptexes/{OS,App}/` (webinspectord is there).
- Binaries that shrink a lot between builds usually lost a linked library, not
  features. Check the `@(#)PROGRAM:... PROJECT:...` version tag first.

## 6. Coverage against pymobiledevice3

Everything this repo already talks to is referenced by name somewhere in the
package, so a name list is enough for a first pass:

```sh
grep -rhoE 'com\.apple\.[A-Za-z0-9_.-]+' pymobiledevice3/ | sort -u > pmd3-names.txt
# then for each service name from steps 1-3:
grep -qx "$name" pmd3-names.txt && echo COVERED || echo MISSING
```

"COVERED" only means the name appears; check the module to see whether the
new `Features` or request types are actually handled.

## 7. Confirm on a device

Static leads lie in three ways: the plist exists but the binary is internal-only,
the service is exposed but every request needs an entitlement the host cannot
satisfy, or the feature is gated by device state (Developer Mode, Setup done,
first unlock). Before writing code, verify against the exact build.

### Advertised is not the same as reachable

`remote rsd-info` prints the peer's `Services` list, but that list is generous:
remoted advertises a service and even hands out its TCP port for connections it
will not actually serve. The real gate is enforced one layer up, at the
RemoteXPC handshake by the target service. Three outcomes, and only the middle
one is a false lead you must discard by hand:

1. **Not advertised at all.** remoted filtered it. Rare; on a production iPhone
   the only OS services filtered were Mac/compute-hardware ones
   (`maccheckerboardd.remoteservice`, `chassisplatformhostd.cpk.gov.remote`).
2. **Advertised, port opens, handshake refused.** `start_remote_service()`
   succeeds (the stream opens) but a full `connect()` times out or reads 0 of 9
   header bytes. This is the entitlement/state gate rejecting you. It is *not*
   reachable.
3. **Advertised and handshake completes.** Actually reachable.

So probe with a full XPC `connect()`, never just `start_remote_service()`:

```python
conn = rsd.start_remote_service(name)
try:
    await asyncio.wait_for(conn.connect(), timeout=8)   # the real test
    print("reachable")
except (asyncio.TimeoutError, asyncio.IncompleteReadError):
    print("gated: advertised but the service refused the handshake")
```

A CoreDevice feature can also be advertised on a service that itself handshakes
fine, yet return `CoreDevice.ActionError` code 5 ("This operation cannot be
performed") for every request. Advertisement of a `Features` entry is not proof
the feature works on this device state.

### `RequireEntitlement` is a real gate, and what satisfies it

`RequireEntitlement` in the launchd plist is enforced by the service, checked
against the trust tier of your tunnel — not against the device's own
`AppleInternal` flag. On a production device (`AppleInternal = False` in
`rsd-info` properties), measured with a trusted RemotePairing tunnel:

- Satisfied by a trusted pairing (handshake OK): the CoreDevice services,
  `notification_proxy.remote`, `security.cryptexd.remote`
  (`com.apple.private.security.cryptexd.remote`),
  `mobile.storage_mounter_proxy.bridge`
  (`com.apple.private.mobile_storage.remote.allowedSPI`), and the `.trusted`
  variant `sysdiagnose.remote.trusted`.
- Refused, because they need something a production device genuinely lacks:
  `AppleInternal` (`private.siriappintentsd.orchestrator`),
  internal security policies (the untrusted `sysdiagnose.remote`),
  `com.apple.timed.remote`, `private.ptdremoteaccess` (`internal.ptdremoted`,
  whose binary is not even present in a customer filesystem), and
  `ReportCrash.antenna-access` (`osanalytics.logTransfer`).

The lesson: `AppleInternal` and other host/device entitlements are real gates
that reject the handshake; a trusted pairing does *not* elevate you to internal.
But a private `com.apple.private.*` entitlement whose intended holder is the
paired host (cryptexd, storage bridge) is satisfied by pairing. Read the gate,
then confirm which tier it needs by connecting.

### Commands

```sh
pymobiledevice3 remote rsd-info          # advertised Services + peer Properties
pymobiledevice3 remote service <name>    # open a RemoteXPC/lockdown service, probe it
pymobiledevice3 developer core-device get-device-info   # a known-good CoreDevice call
```

Record the negative results too. A service that opens its port but refuses the
handshake, or a feature that returns `CoreDevice.ActionError`, is a finished
investigation, not a TODO. Some gates cannot be exercised without changing
device state you should not change casually: the iOS 27 pairing path now
rejects PairSetup unless Developer Mode is on, but confirming the *rejection*
means turning Developer Mode off, which forces a reboot. Note such gates as
binary-confirmed and leave them unexercised rather than disrupt the device.
