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
from pymobiledevice3.dtx import DTXConnection

async def main():
    import socket
    sock = socket.create_connection(("127.0.0.1", 9999))  # tunnel / lockdown
    async with await DTXConnection.from_socket(sock) as conn:
        # open_channel returns a DTXDynamicService by default
        svc = await conn.open_channel(
            "com.apple.instruments.server.services.deviceinfo"
        )
        result = await svc.do_invoke("runningProcesses")
        print(result)

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
await svc.do_invoke("requestChannelWithCode:identifier:", PInt32(42), "my.service")
```

If you annotate a `@dtx_method` stub parameter with a Primitive type, the
coercion is applied automatically at call time:

```python
@dtx_method("_requestChannelWithCode:identifier:")
async def request_channel(self, channel_code: PInt32, identifier: str) -> None:
    ...
```
