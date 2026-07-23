"""Bridge between construct-typing 0.7.x (the Python 3.9 floor) and >= 0.8.0.

construct-typing 0.8.0 (Python >= 3.10) replaced ``csfield(Const(...))`` with
``csfield_const(subcon, value)`` for constant struct fields; the 0.7.x release pinned on Python 3.9
has no ``csfield_const``. :func:`const_field` picks the form the installed version supports so struct
definitions stay version-agnostic instead of repeating the ``try/except`` shim in every module.
"""

from typing import Any

from construct import Const, Construct
from construct_typed import csfield

try:
    from construct_typed import csfield_const  # pyright: ignore[reportAttributeAccessIssue]
except ImportError:  # construct-typing < 0.8.0
    csfield_const = None


def const_field(subcon: "Construct[Any, Any]", value: Any) -> Any:
    """Declare a constant :mod:`construct_typed` dataclass field portably across construct-typing
    versions.

    On construct-typing >= 0.8.0 this delegates to ``csfield_const``; on 0.7.x it falls back to
    ``csfield(Const(...))``. Both make the field ``init=False`` at runtime (the constant is not a
    constructor argument), but the return is typed ``Any`` because the two backends' stubs disagree —
    callers annotate the field with its real value type and pyright cannot see the ``init=False``, so
    the non-default fields that follow need a ``# pyright: ignore[reportGeneralTypeIssues]``.
    """
    if csfield_const is not None:
        return csfield_const(subcon, value)
    return csfield(Const(value, subcon))
