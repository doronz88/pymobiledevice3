---
search:
  boost: 0.5
---

# Python API

Besides the CLI, `pymobiledevice3` is a library. Everything the CLI does is built on the same
public classes you can use directly from your own (async) code.

!!! note "The API is asyncio-based"
    Connection helpers and service methods are coroutines. Run them inside an event loop —
    e.g. with `asyncio.run(main())`.

## 1. Connect to a device

Every service is created on top of a **service provider**. There are three ways to get one — pick
based on the iOS version and the service you need:

| Connection | Python entry point | iOS | Root? | Use when |
| --- | --- | --- | --- | --- |
| Lockdown (USB / Wi-Fi) | `create_using_usbmux` | all | no | Classic services: AFC, app install, syslog, diagnostics, backup, profiles |
| RSD — best no-root tunnel | `PreferredRsdTunnel` | 17+ | no | **Default** for developer/DVT: auto-picks the native tunnel on macOS, the userspace tunnel elsewhere |
| RSD — native (macOS) | `NativeRemotedTunnel` | 17+ | no | macOS only: piggybacks Apple's `remoted`; faster host->device, coexists with Xcode |
| RSD — userspace | `UserspaceRsdTunnel` | 17+ | no | Cross-platform in-process tunnel; the tunnel address is reachable only from this process |
| RSD — `tunneld` | `get_tunneld_devices` | 17+ | yes (daemon) | You need a shared/persistent tunnel, or an external tool (e.g. `lldb`) must reach the device |

Rule of thumb: **need a developer/DVT service on iOS 17+? use `PreferredRsdTunnel` (it picks the best
no-root transport for the host); everything else goes over lockdown.** Classic lockdown services work over USB on every iOS version
(and developer services did too, before Apple's iOS 17 refactor moved them behind RSD). A lockdown
connection is a `LockdownClient`; a tunnel connection is a `RemoteServiceDiscoveryService`. The
sections below show each path.

### Over USB (lockdown)

```python
import asyncio
from pymobiledevice3.lockdown import create_using_usbmux


async def main():
    async with await create_using_usbmux() as lockdown:
        print(lockdown.all_values)  # full device info dict


asyncio.run(main())
```

`create_using_usbmux(serial=...)` targets a specific device; omit it to pick the first one.

### iOS 17+ developer services (tunnel)

Developer/DVT services on iOS 17+ require an RSD tunnel.

**Preferred: `PreferredRsdTunnel`.** It picks the best no-root transport for the host — the native
tunnel on macOS (piggybacks Apple's `remoted`: faster host->device, lower latency, and it coexists
with Xcode), the in-process userspace tunnel elsewhere — and falls back automatically if the first
choice is unavailable. **No `sudo` and no separate `tunneld` daemon.** It is a closeable async
context manager that yields a connected `RemoteServiceDiscoveryService`:

```python
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel


async def main():
    # serial=None -> first device; prefer_native=False forces the userspace tunnel even on macOS
    async with PreferredRsdTunnel(serial=None) as rsd:
        print(rsd.product_version)
        # `rsd` now drives any developer service / DvtProvider
```

macOS embedders who want to be explicit can use `NativeRemotedTunnel` (from
`pymobiledevice3.remote.native_tunnel`) directly; `UserspaceRsdTunnel` (from
`pymobiledevice3.remote.userspace_tunnel`) is the cross-platform in-process tunnel. All three expose
the same async-context-manager / `aopen()` + `aclose()` shape. Caveats: one userspace tunnel per
process, and the userspace tunnel's device address is reachable only from this process (don't hand it
to external tools such as `lldb`) — the native tunnel's address is kernel-routable, so it does not
have that limitation.

The CLI's `--userspace` flag uses the same machinery through the convenience wrapper
`establish_userspace_rsd()`, which opens the tunnel and keeps it alive for the process lifetime
(handy for scripts; embedders should prefer `UserspaceRsdTunnel` for explicit teardown):

```python
from pymobiledevice3.remote.userspace_tunnel import establish_userspace_rsd

rsd = await establish_userspace_rsd()  # connected RemoteServiceDiscoveryService
```

**Alternative: reuse a running `tunneld`.** If a privileged `tunneld` is already running, discover
its published tunnels instead:

```python
from pymobiledevice3.tunneld.api import get_tunneld_devices


async def main():
    rsds = await get_tunneld_devices()
    try:
        rsd = rsds[0]
        print(rsd.udid, rsd.product_version)
    finally:
        for rsd in rsds:
            await rsd.close()
```

You can also wrap an explicit address with `RemoteServiceDiscoveryService((host, port))` and use it
as an async context manager. See [iOS 17+ tunnels](ios17-tunnels.md) for how the tunnel is
established.

## 2. The service pattern

Nearly every service subclasses `LockdownService`, takes a service provider, and is an **async
context manager** (a few, like `CrashReportsManager` and `DvtProvider`, wrap other services
instead). Once you have that pattern, the services all work the same way:

```python
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.os_trace import OsTraceService


async def main():
    async with await create_using_usbmux() as lockdown:
        async for entry in OsTraceService(lockdown=lockdown).syslog():
            print(entry.pid, entry.image_name, entry.message)
```

## 3. Worked examples

### Stream syslog

```python
from pymobiledevice3.services.os_trace import OsTraceService

async for entry in OsTraceService(lockdown=lockdown).syslog():
    print(f"[{entry.level.name}] {entry.image_name}: {entry.message}")
```

### List installed apps

```python
from pymobiledevice3.services.installation_proxy import InstallationProxyService

apps = await InstallationProxyService(lockdown=lockdown).get_apps()
for bundle_id, info in apps.items():
    print(bundle_id, info.get("CFBundleShortVersionString"))
```

### Browse files over AFC

```python
from pymobiledevice3.services.afc import AfcService

afc = AfcService(lockdown=lockdown)
print(await afc.listdir("/"))
```

### Run a DVT (developer) service

DVT services go through a `DvtProvider`, which needs a tunnel-backed service provider on iOS 17+:

```python
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

# `rsd` is a tunnel-backed service provider (see "Connect to a device" above)
async with DvtProvider(rsd) as dvt:
    process_control = ProcessControl(dvt)
    pid = await process_control.launch("com.apple.mobilesafari")
    print("launched pid", pid)
```

## 4. Finding the right service

There are ~30 services under `pymobiledevice3/services/`. A few common ones:

| Task | Class | Module |
| --- | --- | --- |
| Syslog / oslog / process list | `OsTraceService` | `services.os_trace` |
| App install / list / uninstall | `InstallationProxyService` | `services.installation_proxy` |
| File access (media / app containers) | `AfcService` | `services.afc` |
| Diagnostics, reboot, IORegistry | `DiagnosticsService` | `services.diagnostics` |
| SpringBoard icons / wallpaper / orientation | `SpringBoardServicesService` | `services.springboard` |
| Crash reports | `CrashReportsManager` | `services.crash_reports` |
| Mount the Developer Disk Image | `MobileImageMounterService` | `services.mobile_image_mounter` |
| DVT instruments (iOS 17+ via tunnel) | `DvtProvider` | `services.dvt.instruments.dvt_provider` |

For the full surface, see the [API reference](../api/index.md) and the
[Writing CLI commands](writing-commands-with-service-provider.md) guide, which shows how the CLI
wires service providers into commands.

## 5. Faster imports on Python 3.15+

On Python 3.15+ the CLI enables [PEP 810 lazy imports](https://peps.python.org/pep-0810/) for
itself, scoped so that only pymobiledevice3's own imports are deferred — roughly halving its
startup time. As a library, pymobiledevice3 never changes your process's import semantics:
importing `pymobiledevice3.*` from your application stays eager.

If you own the process, you can opt in to the same behavior. It saves ~0.2-0.3s on the heaviest
entry points (e.g. `pymobiledevice3.remote.userspace_tunnel`), and the filter keeps every other
package eager — process-wide laziness is known to break some import hooks:

```python
import sys


def _lazy_filter(importing: str, imported: str, fromlist: object = None) -> bool:
    return importing.partition(".")[0] == "pymobiledevice3"


if hasattr(sys, "set_lazy_imports"):  # Python 3.15+
    sys.set_lazy_imports("all")
    sys.set_lazy_imports_filter(_lazy_filter)
```

Run this before importing any pymobiledevice3 module. On older Pythons it is a no-op.
