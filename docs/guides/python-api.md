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
| RSD — userspace tunnel | `UserspaceRsdTunnel` | 17+ | no | **Default** for developer/DVT from your own code or CI; the tunnel is in-process only |
| RSD — `tunneld` | `get_tunneld_devices` | 17+ | yes (daemon) | You need a shared/persistent tunnel, or an external tool (e.g. `lldb`) must reach the device |

Rule of thumb: **need a developer/DVT service on iOS 17+? use a tunnel (userspace by default);
everything else goes over lockdown.** Classic lockdown services work over USB on every iOS version
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

**Preferred: a no-root, in-process tunnel.** `UserspaceRsdTunnel` brings the tunnel up inside your
own process over a pure-Python network stack — **no `sudo` and no separate `tunneld` daemon**. It is
a closeable async context manager that yields a connected `RemoteServiceDiscoveryService`:

```python
from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel


async def main():
    # serial=None -> first USB device; autopair pairs on the fly if needed
    async with UserspaceRsdTunnel(serial=None, autopair=True) as rsd:
        print(rsd.product_version)
        # `rsd` now drives any developer service / DvtProvider
```

It also exposes an explicit `aopen()` / `aclose()` handle if you can't use a context manager.
Caveats: one tunnel per process, and the device address is reachable only from this process — don't
hand it to external tools such as `lldb`.

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
