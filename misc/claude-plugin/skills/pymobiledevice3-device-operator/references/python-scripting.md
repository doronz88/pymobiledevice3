# Writing Python Scripts Against The Library

## Use This File

Read this file before writing Python code that drives a device through
`pymobiledevice3` as a library rather than through the CLI.

## Do Not Trust Memorized API Shapes

The library migrated to asyncio **incrementally over many releases**, converting more of
the API surface each version — so code written from memory or from older examples on the
web very often uses a stale synchronous shape of an API that is a coroutine today. It
will look plausible and fail at runtime. Verify every entry point against the current
source or docs before using it:

- In a checkout: `docs/guides/python-api.md`, then the service module itself.
- Without a checkout: <https://doronz88.github.io/pymobiledevice3/guides/python-api/>
  (the site also serves `llms.txt` for bulk ingestion).

Everything is asyncio-based: connection helpers and service methods are coroutines, run
inside `asyncio.run(...)`.

## Connect (pick by iOS version and service)

- Classic services (AFC, apps, syslog, diagnostics, backup, profiles) — lockdown, all
  iOS versions, no root:

  ```python
  import asyncio
  from pymobiledevice3.lockdown import create_using_usbmux

  async def main():
      async with await create_using_usbmux() as lockdown:  # serial=... to target
          print(lockdown.all_values)

  asyncio.run(main())
  ```

- Developer/DVT services on iOS 17+ — no-root in-process userspace tunnel:

  ```python
  from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel

  async with UserspaceRsdTunnel(serial=None, autopair=True) as rsd:
      ...  # rsd is a connected RemoteServiceDiscoveryService
  ```

  `establish_userspace_rsd()` is the keep-alive convenience wrapper for scripts. One
  tunnel per process; the address is unreachable from other processes (use `tunneld` +
  `get_tunneld_devices()` from `pymobiledevice3.tunneld.api` when an external tool such
  as `lldb` must reach the device).

## The Service Pattern

Nearly every service subclasses `LockdownService`, takes a service provider, and is an
async context manager:

```python
from pymobiledevice3.services.os_trace import OsTraceService

async for entry in OsTraceService(lockdown=lockdown).syslog():
    print(entry.pid, entry.image_name, entry.message)
```

DVT services go through a `DvtProvider` over a tunnel-backed provider:

```python
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

async with DvtProvider(rsd) as dvt:
    pid = await ProcessControl(dvt).launch("com.apple.mobilesafari")
```

## Finding The Right Service

~30 services live under `pymobiledevice3/services/`; the task→class table is in
`docs/guides/python-api.md` section 4. When the CLI already does what the script needs,
read the matching module under `pymobiledevice3/cli/` — it shows the exact service calls
to reuse.
