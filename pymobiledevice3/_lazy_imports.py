"""
Opt the current process into PEP 810 lazy imports, scoped to pymobiledevice3's own imports.

Importing this module is a deliberate side effect: on Python 3.15+ every module-level import
performed *by a pymobiledevice3 module* becomes potentially lazy, so heavy dependency chains
(pykdebugparser, fastapi, IPython, qh3, ...) load on first use instead of at CLI startup
(roughly 2x faster command dispatch and ``--help``). The filter below keeps third-party
modules' own imports eager: process-wide laziness is known to break import hooks in other
packages (e.g. pytest's assertion rewriter trips over a lazy ``fnmatch`` proxy).

On Python < 3.15 importing this module is a no-op. Only process entry points should import it
(``pymobiledevice3.__main__``, ``tests/conftest.py``) -- library consumers are never affected.
"""

import sys
from typing import Callable, Optional

_LAZY_TOP_LEVEL_MODULES = ("pymobiledevice3", "__main__")


def _lazy_filter(importing: str, imported: str, fromlist: object = None) -> bool:
    """Keep an import lazy only when a pymobiledevice3 module (or the CLI ``__main__``) performs it."""
    return importing.partition(".")[0] in _LAZY_TOP_LEVEL_MODULES


# getattr keeps pyright (pinned to the 3.9 floor) away from attributes typeshed gates on 3.15.
_set_lazy_imports: Optional[Callable[[str], None]] = getattr(sys, "set_lazy_imports", None)
_set_lazy_imports_filter: Optional[Callable[[Callable[[str, str, object], bool]], None]] = getattr(
    sys, "set_lazy_imports_filter", None
)

if _set_lazy_imports is not None and _set_lazy_imports_filter is not None:  # Python 3.15+ (PEP 810)
    _set_lazy_imports("all")
    _set_lazy_imports_filter(_lazy_filter)
