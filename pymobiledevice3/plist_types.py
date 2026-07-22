"""Type aliases describing what a property list can carry.

``plistlib`` can only serialise a fixed set of leaf types plus ``list`` and
``dict`` containers of them.  These aliases capture exactly that set so the
send/receive plist API can state, in the type system, what is plist-serialisable
and what is not.

Two directions are modelled separately, because they need opposite variance:

* :data:`PlistValue` / :data:`PlistDict` describe *received* data — concrete,
  mutable ``dict`` / ``list`` containers the caller can index and mutate.
* :data:`PlistSendable` describes *sendable* data — built on the covariant
  ``Mapping`` / ``Sequence`` protocols so a caller may pass an already-typed
  ``dict[str, list[str]]`` (or any other concrete nesting) without a spurious
  variance error, while still rejecting non-serialisable leaves.

Note that ``None`` is intentionally absent from both: ``plistlib.dumps`` raises
``TypeError`` on ``None``, so a ``None`` value inside a plist payload is always a
bug — the send-side types are meant to surface exactly that.
"""

import datetime
import plistlib
from collections.abc import Mapping, Sequence
from typing import Union

# --- Received data: concrete, mutable, precisely typed -----------------------

# A single property-list value: one of the plistlib leaf types, or a list/dict
# nesting more of the same.  Recursive alias — resolved lazily by the type
# checker; the runtime only ever stores the (unevaluated) forward references.
PlistValue = Union[
    bool,
    int,
    float,
    str,
    bytes,
    bytearray,
    datetime.datetime,
    plistlib.UID,
    "list[PlistValue]",
    "dict[str, PlistValue]",
]

# The common case: a plist whose root is a dictionary (every lockdown/usbmux
# request and response is one of these).
PlistDict = dict[str, PlistValue]

# --- Sendable data: covariant containers so concrete nestings are accepted ---

# Like PlistValue, but its containers are the covariant ``Mapping`` / ``Sequence``
# protocols.  This lets a caller pass a ``dict[str, list[str]]``,
# ``list[dict[str, Any]]``, etc. without the invariance errors that the concrete
# ``dict`` / ``list`` arms of PlistValue would raise — while still rejecting a
# non-serialisable leaf such as ``None`` or an arbitrary object.
PlistSendableValue = Union[
    bool,
    int,
    float,
    str,
    bytes,
    bytearray,
    datetime.datetime,
    plistlib.UID,
    Sequence["PlistSendableValue"],
    Mapping[str, "PlistSendableValue"],
]

# What may be handed to the *send* side: a dictionary- or list-rooted plist.
PlistSendable = Union[Mapping[str, PlistSendableValue], Sequence[PlistSendableValue]]
