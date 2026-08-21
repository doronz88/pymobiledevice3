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


def test_dtx_decode_registers_ns_classes_under_lazy_imports() -> None:
    """A DTX payload must decode via NSKeyedUnarchiver without a caller pre-touching ns_types.

    Regression: under PEP 810 lazy imports the NSKeyedArchive class registration in
    pymobiledevice3.dtx.ns_types ran only as an import side effect, which never fired
    for decode paths (e.g. `sysmon`) that reach archiver.unarchive without using an
    ns_types name -- every DT*TapMessage then failed to unarchive and fell back to a raw
    plist dict. Run in a subprocess so process-global lazy state and the class map are
    pristine, importing only the decode entry point (dtx.message).
    """
    code = (
        "import pymobiledevice3._lazy_imports\n"  # enable filtered lazy imports on 3.15+ (no-op below)
        "import plistlib\n"
        "from pymobiledevice3.dtx.message import DTXMessage, DTXMessageType\n"
        "U = plistlib.UID\n"
        "archive = {'$version': 100000, '$archiver': 'NSKeyedArchiver', '$top': {'root': U(1)},\n"
        "    '$objects': ['$null',\n"
        "        {'DTTapMessagePlist': U(2), '$class': U(8)},\n"
        "        {'NS.keys': [U(3), U(4)], 'NS.objects': [U(5), U(6)], '$class': U(7)},\n"
        "        'k', 'tv', 0, 65536,\n"
        "        {'$classname': 'NSMutableDictionary',\n"
        "         '$classes': ['NSMutableDictionary', 'NSDictionary', 'NSObject']},\n"
        "        {'$classname': 'DTSysmonTapMessage',\n"
        "         '$classes': ['DTSysmonTapMessage', 'DTTapMessage', 'NSObject']}]}\n"
        "data = plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)\n"
        "msg = DTXMessage(type=next(iter(DTXMessageType)), payload_data=memoryview(data))\n"
        "assert msg.payload == {'k': 0, 'tv': 65536}, msg.payload\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_xctest_decode_registers_classes_under_lazy_imports() -> None:
    """XCTest result payloads must decode once the XCTest DTX service module is in use.

    Same regression as the DTX case, one layer up: xctest_types registered its proxy
    classes (XCTIssue, XCActivityRecord, ...) only as an import side effect, but those
    types are decoded by the DTX machinery without any xctest_types name being touched,
    so under lazy imports they fell back to a raw plist dict. Using a name from the
    decode-entry module (dtx_services) must be enough to register them.
    """
    code = (
        "import pymobiledevice3._lazy_imports\n"
        "import plistlib\n"
        "from pymobiledevice3.services.dvt.testmanaged.dtx_services import XCTestManager_IDEInterface\n"
        "XCTestManager_IDEInterface  # use the name -> resolve dtx_services body -> register\n"
        "from pymobiledevice3.dtx.message import DTXMessage, DTXMessageType\n"
        "U = plistlib.UID\n"
        "archive = {'$version': 100000, '$archiver': 'NSKeyedArchiver', '$top': {'root': U(1)},\n"
        "    '$objects': ['$null', {'$class': U(2)},\n"
        "        {'$classname': 'XCTIssue', '$classes': ['XCTIssue', 'NSObject']}]}\n"
        "data = plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)\n"
        "msg = DTXMessage(type=next(iter(DTXMessageType)), payload_data=memoryview(data))\n"
        "assert type(msg.payload).__name__ == 'XCTIssue', msg.payload\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
