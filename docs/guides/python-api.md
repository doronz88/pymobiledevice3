---
search:
  boost: 0.5
---

# Python API

Besides the CLI, `pymobiledevice3` is a library. Everything the CLI does is built on the same
public classes you can use directly from your own code.

Install it into your project's environment (`pip install pymobiledevice3` or
`uv add pymobiledevice3`), connect the device over USB, and accept the *Trust This Computer*
prompt the first time you connect. See [Installation](../installation.md) for platform notes.

!!! note "The API is asyncio-based"
    Connection helpers and service methods are coroutines. Run them inside an event loop,
    e.g. with `asyncio.run(main())`.

## 1. Connect to a device

Every service is created on top of a **service provider**, the object that knows how to reach the
device. There are two kinds: a **lockdown** connection (`LockdownClient`, over usbmux), and an
**RSD** connection (`RemoteServiceDiscoveryService`, RemoteServiceDiscovery over an iOS 17+
tunnel). Pick based on the iOS version and the service you need:

| Connection | Python entry point | iOS | Root? | Use when |
| --- | --- | --- | --- | --- |
| Lockdown (USB / Wi-Fi) | `create_using_usbmux` | all | no | Classic services: AFC, app install, syslog, diagnostics, backup, profiles |
| RSD, best no-root tunnel | `PreferredRsdTunnel` | 17+ | no | **Default** for developer/DVT: the userspace tunnel, falling back to the native tunnel for iOS 17.0-17.3 on macOS |
| RSD, native (macOS) | `NativeRemotedTunnel` | 17+ | no | macOS only: piggybacks Apple's `remoted`; faster host->device, but evicts and is evicted by `remoted`'s own connection ([#1994](https://github.com/doronz88/pymobiledevice3/issues/1994)) |
| RSD, userspace | `UserspaceRsdTunnel` | 17+ | no | Cross-platform in-process tunnel; the tunnel address is reachable only from this process |
| RSD, `tunneld` | `get_tunneld_devices` | 17+ | yes (daemon) | You need a shared/persistent tunnel, or an external tool (e.g. `lldb`) must reach the device |

Rule of thumb: **need a developer/DVT service on iOS 17+? Use `PreferredRsdTunnel`, which picks
the best no-root transport for the host. Everything else goes over lockdown.** Classic lockdown
services work over USB on every iOS version (developer services did too, until iOS 17 moved them
behind RSD). The sections below show each path.

### Over USB (lockdown)

```python
import asyncio

from pymobiledevice3.lockdown import create_using_usbmux


async def main():
    async with await create_using_usbmux() as lockdown:
        print(lockdown.all_values)  # full device info dict


asyncio.run(main())
```

`create_using_usbmux(serial=...)` targets a specific device by UDID; omit it to pick the first one.

### iOS 17+ developer services (tunnel)

Developer/DVT services on iOS 17+ require an RSD tunnel.

**Preferred: `PreferredRsdTunnel`.** It uses the in-process userspace tunnel and, on macOS, falls
back automatically to the native tunnel (piggybacking Apple's `remoted`) for iOS 17.0-17.3, which
the userspace tunnel cannot serve. **No `sudo` and no separate `tunneld` daemon.** It is an async
context manager that yields a connected `RemoteServiceDiscoveryService`:

```python
import asyncio

from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel


async def main():
    # serial=None -> first device; prefer_native=True tries the macOS native tunnel first
    async with PreferredRsdTunnel(serial=None) as rsd:
        print(rsd.udid, rsd.product_version)
        # `rsd` now drives any developer service / DvtProvider


asyncio.run(main())
```

To choose the transport explicitly, use `UserspaceRsdTunnel` (from
`pymobiledevice3.remote.userspace_tunnel`, cross-platform) or `NativeRemotedTunnel` (from
`pymobiledevice3.remote.native_tunnel`, macOS only). All three tunnel classes take `serial=` and
work either as async context managers or through explicit `aopen()` / `aclose()` calls. Caveats:

- One userspace tunnel per process, and its device address is reachable only from this process,
  so don't hand it to external tools such as `lldb`.
- The native tunnel's address is kernel-routable, so it has no such limitation. But on that
  tunnel the device keeps a single RSD connection, which ours and `remoted`'s keep evicting from
  each other; this can leave Xcode/`devicectl` without the device.

The CLI's `--userspace` flag goes through `establish_userspace_rsd()`, which opens a userspace
tunnel and keeps it alive until the process exits. It suits short scripts that never tear the
tunnel down; embedders should prefer `UserspaceRsdTunnel` for explicit teardown:

```python
from pymobiledevice3.remote.userspace_tunnel import establish_userspace_rsd


async def main():
    rsd = await establish_userspace_rsd()  # connected RemoteServiceDiscoveryService
    print(rsd.product_version)
```

**Alternative: reuse a running `tunneld`.** If a privileged `tunneld` is already running, discover
its published tunnels instead:

```python
import asyncio

from pymobiledevice3.tunneld.api import get_tunneld_devices


async def main():
    rsds = await get_tunneld_devices()
    try:
        rsd = rsds[0]
        print(rsd.udid, rsd.product_version)
    finally:
        for rsd in rsds:
            await rsd.close()


asyncio.run(main())
```

You can also wrap an explicit address with `RemoteServiceDiscoveryService((host, port))` and use it
as an async context manager. See [iOS 17+ tunnels](ios17-tunnels.md) for how the tunnel is
established.

## 2. The service pattern

Nearly every service subclasses `LockdownService`, takes a service provider, and is an **async
context manager**: entering it opens the service connection and leaving it closes it. A few, like
`CrashReportsManager` and `DvtProvider`, wrap other services instead. Once you know this pattern,
the services all work the same way:

```python
import asyncio

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.os_trace import OsTraceService


async def main():
    async with await create_using_usbmux() as lockdown, OsTraceService(lockdown) as os_trace:
        async for entry in os_trace.syslog():
            print(entry.pid, entry.image_name, entry.message)


asyncio.run(main())
```

The same service classes accept an RSD as well, so `OsTraceService(rsd)` works over a tunnel too.

## 3. Worked examples

These snippets go inside an `async def` like `main()` above, with `lockdown` an open service
provider.

### Stream syslog

```python
from pymobiledevice3.services.os_trace import OsTraceService

async with OsTraceService(lockdown) as os_trace:
    async for entry in os_trace.syslog():
        print(f"[{entry.level.name}] {entry.image_name}: {entry.message}")
```

### List installed apps

```python
from pymobiledevice3.services.installation_proxy import InstallationProxyService

async with InstallationProxyService(lockdown) as installation_proxy:
    apps = await installation_proxy.get_apps()
for bundle_id, info in apps.items():
    print(bundle_id, info.get("CFBundleShortVersionString"))
```

### Browse files over AFC

AFC (Apple File Conduit) gives access to the device's media directory:

```python
from pymobiledevice3.services.afc import AfcService

async with AfcService(lockdown) as afc:
    print(await afc.listdir("/"))
```

### Run a DVT (developer) service

DVT services go through a `DvtProvider`. On iOS 17+ it needs an RSD from a tunnel. It also
needs Developer Mode enabled (iOS 16+), and on iOS < 17 the Developer Disk Image mounted
(`pymobiledevice3 mounter auto-mount`). Each instrument is itself an async context manager:

```python
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

# `rsd` is a tunnel-backed service provider (see "Connect to a device" above)
async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as process_control:
    pid = await process_control.launch("com.apple.mobilesafari")
    print("launched pid", pid)
```

## 4. Finding the right service

There are dozens of services under `pymobiledevice3/services/`. A few common ones:

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

For the full surface, see the [API reference](../api/index.md). The
[Writing CLI commands](writing-commands-with-service-provider.md) guide shows how the CLI wires
service providers into commands.

## 5. Faster imports on Python 3.15+

On Python 3.15+ the CLI enables [PEP 810 lazy imports](https://peps.python.org/pep-0810/) for
itself, scoped so that only pymobiledevice3's own imports are deferred, which roughly halves its
startup time. As a library, pymobiledevice3 never changes your process's import semantics:
importing `pymobiledevice3.*` from your application stays eager.

If you own the process, you can opt in to the same behavior. It saves ~0.2-0.3s on the heaviest
entry points (e.g. `pymobiledevice3.remote.userspace_tunnel`), and the filter keeps every other
package eager, since process-wide laziness is known to break some import hooks:

```python
import sys


def _lazy_filter(importing: str, imported: str, fromlist: object = None) -> bool:
    return importing.partition(".")[0] == "pymobiledevice3"


if hasattr(sys, "set_lazy_imports"):  # Python 3.15+
    sys.set_lazy_imports("all")
    sys.set_lazy_imports_filter(_lazy_filter)
```

Run this before importing any pymobiledevice3 module. On older Pythons it is a no-op.
