"""DTX (Developer Tools eXchange) — public API.

Import everything you need from here::

    from pymobiledevice3.dtx import (
        DTXConnection, DTXService, DTXChannel,
        dtx_method, dtx_on_invoke, dtx_on_notification,
        PInt32, PStr,
        DTXNsError,
    )

For protocol internals and the full class hierarchy see the sub-modules:
``primitives``, ``ns_types``, ``message``, ``channel``, ``service``, ``connection``.
"""

from __future__ import annotations

from .channel import DTXChannel

# Connection & channel
from .connection import DTXConnection

# Context
from .context import DTX_GLOBAL_CTX, DTXContext

# Exceptions
from .message import DTXNsError, DTXProtocolError

# Common NS types returned by services
from .ns_types import NSURL, NSUUID, NSError

# Primitive argument types
from .primitives import (
    PBuf,
    PDouble,
    PInt32,
    PInt64,
    PNull,
    PrimitiveBuffer,
    PrimitiveDouble,
    PrimitiveInt32,
    PrimitiveInt64,
    PrimitiveNull,
    PrimitiveString,
    PStr,
)

# Service base classes & decorators
from .service import (
    DTX_SERVICE_T,
    DTXDynamicService,
    DTXProxyService,
    DTXService,
    dtx_method,
    dtx_on_data,
    dtx_on_dispatch,
    dtx_on_invoke,
    dtx_on_notification,
)

__all__ = [
    "DTX_GLOBAL_CTX",
    "DTX_SERVICE_T",
    "NSURL",
    "NSUUID",
    "DTXChannel",
    "DTXConnection",
    "DTXContext",
    "DTXDynamicService",
    "DTXNsError",
    "DTXProtocolError",
    "DTXProxyService",
    "DTXService",
    "NSError",
    "PBuf",
    "PDouble",
    "PInt32",
    "PInt64",
    "PNull",
    "PStr",
    "PrimitiveBuffer",
    "PrimitiveDouble",
    "PrimitiveInt32",
    "PrimitiveInt64",
    "PrimitiveNull",
    "PrimitiveString",
    "dtx_method",
    "dtx_on_data",
    "dtx_on_dispatch",
    "dtx_on_invoke",
    "dtx_on_notification",
]
