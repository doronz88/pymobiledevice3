import subprocess
import sys

from pymobiledevice3._lazy_imports import _lazy_filter

LAZY_IMPORTS_SUPPORTED = hasattr(sys, "set_lazy_imports")  # Python 3.15+ (PEP 810)


def test_lazy_filter_keeps_pymobiledevice3_imports_lazy() -> None:
    assert _lazy_filter("pymobiledevice3", "typer")
    assert _lazy_filter("pymobiledevice3.cli.developer.dvt.core_profile_session", "pykdebugparser.pykdebugparser")
    # `python -m pymobiledevice3` executes __main__.py under the module name "__main__"
    assert _lazy_filter("__main__", "pymobiledevice3.cli.cli_common")


def test_lazy_filter_leaves_foreign_imports_eager() -> None:
    # Laziness inside arbitrary packages breaks import hooks (e.g. pytest's assertion rewriter)
    assert not _lazy_filter("_pytest.assertion.rewrite", "fnmatch")
    assert not _lazy_filter("conftest", "pymobiledevice3.lockdown")
    # Only a whole leading component counts, not a name prefix
    assert not _lazy_filter("pymobiledevice3_fork.module", "os")


def test_cli_entry_enables_scoped_lazy_imports() -> None:
    """Importing the CLI entry module must flip the process to filtered lazy mode on 3.15+."""
    # Subprocess because sys.set_lazy_imports() is process-global state
    if LAZY_IMPORTS_SUPPORTED:
        checks = "assert sys.get_lazy_imports() == 'all'; assert sys.get_lazy_imports_filter() is not None"
    else:
        checks = "assert not hasattr(sys, 'get_lazy_imports')"
    code = f"import sys; import pymobiledevice3.__main__; {checks}"
    subprocess.run([sys.executable, "-c", code], check=True)
