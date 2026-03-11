# DTX — Distributed Transport eXchange

DTX is Apple's binary RPC protocol used by Instruments and XCTest to
communicate with on-device daemons such as
`com.apple.instruments.server.services.deviceinfo`.

This package provides a clean-room Python asyncio implementation of the full
DTX stack.

---

## Quick start

```python
import asyncio
import logging
from pymobiledevice3.dtx import DTXDynamicService
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.tunneld.api import get_tunneld_devices

async def main():
    rsd = (await get_tunneld_devices())[0]
    opts = {
        "StartSuspendedKey": False,
        "KillExisting": True,
    }
    async with rsd:
        async with DvtProvider(rsd) as provider:
            svc: DTXDynamicService = await provider.dtx.open_channel(
                "com.apple.instruments.server.services.processcontrol"
            )
            svc.outputReceived_fromProcess_atTime_ = lambda output, pid, timestamp: logging.info("[process:%d] %s %s", pid, timestamp, output.rstrip())
            pid = await svc.launchSuspendedProcessWithDevicePath_bundleIdentifier_environment_arguments_options_("", "com.example.MyBundleId", {}, [], opts)
            logging.info("Launched process with PID %d", pid)
            await asyncio.sleep(5)
            await svc.killPid_(pid)

asyncio.run(main())
```

---

## Strongly-typed service

Subclass `DTXService` to get type-safe outgoing calls and automatic incoming
dispatch:

```python
from pymobiledevice3.dtx import (
    DTXService, DTXChannel,
    dtx_method, dtx_on_invoke, dtx_on_notification,
    PInt32,
)

class DeviceInfoService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.deviceinfo"

    @dtx_method                    # selector inferred: runningProcesses → "runningProcesses"
    async def runningProcesses(self) -> list:
        ...

    @dtx_method("systemInformation")   # explicit ObjC selector
    async def system_information(self) -> dict:
        ...

    @dtx_on_notification
    async def _on_notification(self, payload) -> None:
        print("notification:", payload)

# Open the channel using the class itself:
svc: DeviceInfoService = await conn.open_service(DeviceInfoService)
procs = await svc.runningProcesses()
```

---

## `@dtx_method` options

| Form | Behaviour |
| ------ | ----------- |
| `@dtx_method` | selector inferred from the Python method name |
| `@dtx_method("setConfig:")` | explicit ObjC selector |
| `@dtx_method(expects_reply=False)` | fire-and-forget |
| `@dtx_method("setConfig:", expects_reply=False)` | both |

---

## `@dtx_on_invoke` options

| Form | Behaviour |
| ------ | ----------- |
| `@dtx_on_invoke` | selector inferred from the Python method name |
| `@dtx_on_invoke("_XCT_logMessage:")` | explicit ObjC selector |
| `@dtx_on_dispatch` | catch-all for unmatched selectors |

---

## Primitive types

By default, Python values passed as arguments are serialised with
NSKeyedArchiver (as a BUFFER primitive). To send a raw integer or string
instead, wrap with one of the Primitive wrappers:

| Class | Alias | Wire type |
| ------- | ------- | ----------- |
| `PrimitiveNull` | `PNull` | 10 — positional NULL |
| `PrimitiveString` | `PStr` | 1 — length-prefixed UTF-8 |
| `PrimitiveBuffer` | `PBuf` | 2 — raw bytes (no archiving) |
| `PrimitiveInt32` | `PInt32` | 3 — u32 |
| `PrimitiveInt64` | `PInt64` | 6 — u64 |
| `PrimitiveDouble` | `PDouble` | 9 — IEEE-754 double |

```python
await svc.invoke("requestChannelWithCode:identifier:", PInt32(42), "my.service")
```

If you annotate a `@dtx_method` stub parameter with a Primitive type, the
coercion is applied automatically at call time:

```python
@dtx_method("_requestChannelWithCode:identifier:")
async def request_channel(self, channel_code: PInt32, identifier: str) -> None:
    ...
```
