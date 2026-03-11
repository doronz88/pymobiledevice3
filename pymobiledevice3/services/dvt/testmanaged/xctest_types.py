"""XCTest-specific NSKeyedArchive type proxies.

These classes represent plist-level data structures exchanged during an XCTest
session.  They live here rather than in :mod:`~pymobiledevice3.dtx`
because they are not part of the DTX protocol itself — they are XCTest payload
types that happen to travel over DTX.

Exported
--------
- :class:`XCTCapabilities`
- :class:`XCTestConfiguration`
- :class:`XCTTestIdentifier`
- :class:`XCTIssue`
- :class:`XCTSourceCodeContext`
- :class:`XCTSourceCodeLocation`
- :class:`XCActivityRecord`
- :class:`XCTAttachment`
- :class:`XCTestCaseRunConfiguration`
"""

from __future__ import annotations

import copy
import plistlib
from dataclasses import dataclass, field
from typing import Any, ClassVar, Optional

from bpylist2 import archiver


class XCTCapabilities:
    """Proxy for XCTest's ``XCTCapabilities`` dictionary wrapper."""

    def __init__(self, capabilities: dict):
        self.capabilities = capabilities

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        archive_obj.encode("capabilities-dictionary", self.capabilities)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> XCTCapabilities:
        return XCTCapabilities(archive_obj.decode("capabilities-dictionary"))

    def __repr__(self) -> str:
        return f"XCTCapabilities({self.capabilities})"


class XCTestConfiguration:
    """Proxy for ``XCTestConfiguration`` — the launch config sent to the test runner."""

    _default: ClassVar = {
        "aggregateStatisticsBeforeCrash": {"XCSuiteRecordsKey": {}},
        "automationFrameworkPath": "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework",
        "baselineFileRelativePath": None,
        "baselineFileURL": None,
        "defaultTestExecutionTimeAllowance": None,
        "disablePerformanceMetrics": False,
        "emitOSLogs": False,
        "formatVersion": plistlib.UID(2),
        "gatherLocalizableStringsData": False,
        "initializeForUITesting": True,
        "maximumTestExecutionTimeAllowance": None,
        "productModuleName": "WebDriverAgentRunner",
        "randomExecutionOrderingSeed": None,
        "reportActivities": True,
        "reportResultsToIDE": True,
        "systemAttachmentLifetime": 2,
        "targetApplicationArguments": [],
        "targetApplicationBundleID": None,
        "targetApplicationEnvironment": None,
        "targetApplicationPath": "/whatever-it-does-not-matter/but-should-not-be-empty",
        "testApplicationDependencies": {},
        "testApplicationUserOverrides": None,
        "testBundleRelativePath": None,
        "testExecutionOrdering": 0,
        "testTimeoutsEnabled": False,
        "testsDrivenByIDE": False,
        "testsMustRunOnMainThread": True,
        "testsToRun": None,
        "testsToSkip": None,
        "treatMissingBaselinesAsFailures": False,
        "userAttachmentLifetime": 0,
        "preferredScreenCaptureFormat": 2,
        "IDECapabilities": XCTCapabilities({
            "expected failure test capability": True,
            "test case run configurations": True,
            "test timeout capability": True,
            "test iterations": True,
            "request diagnostics for specific devices": True,
            "delayed attachment transfer": True,
            "skipped test capability": True,
            "daemon container sandbox extension": True,
            "ubiquitous test identifiers": True,
            "XCTIssue capability": True,
        }),
    }

    def __init__(self, kv: dict):
        assert "testBundleURL" in kv
        assert "sessionIdentifier" in kv
        self._config = copy.deepcopy(self._default)
        self._config.update(kv)

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        for k, v in self._config.items():
            archive_obj.encode(k, v)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        return archive_obj.object


# Register with bpylist2 archiver so incoming payloads are decoded correctly.
archiver.update_class_map({
    "XCTestConfiguration": XCTestConfiguration,
    "XCTCapabilities": XCTCapabilities,
})


# ---------------------------------------------------------------------------
# XCTest runtime types — decoded from NSKeyedArchive payloads during test runs
# ---------------------------------------------------------------------------


@dataclass
class XCTTestIdentifier:
    """Decoded proxy for ``XCTTestIdentifier``.

    ``components`` is the ordered list of name parts, e.g.
    ``["DemoAppUITests", "testFail"]``.  Use :attr:`test_class` /
    :attr:`test_method` as shortcuts.
    """

    components: list[str] = field(default_factory=list)

    @property
    def test_class(self) -> str:
        return self.components[0] if self.components else ""

    @property
    def test_method(self) -> Optional[str]:
        return self.components[1] if len(self.components) > 1 else None

    def __str__(self) -> str:
        return "/".join(self.components)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> XCTTestIdentifier:
        raw = archive_obj.decode("c")
        components = list(raw) if raw else []
        return XCTTestIdentifier(components=components)


@dataclass
class XCTSourceCodeLocation:
    """Decoded proxy for ``XCTSourceCodeLocation``."""

    file_url: Any  # NSURL instance or None
    line_number: int

    @property
    def file_path(self) -> Optional[str]:
        """Return the local file path (strips ``file://`` prefix)."""
        if self.file_url is None:
            return None
        url = getattr(self.file_url, "relative", None) or ""
        return url.removeprefix("file://")

    def __str__(self) -> str:
        return f"{self.file_path or '?'}:{self.line_number}"

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> XCTSourceCodeLocation:
        file_url = archive_obj.decode("file-url")
        line_number = archive_obj.decode("line-number") or 0
        return XCTSourceCodeLocation(file_url=file_url, line_number=int(line_number))


@dataclass
class XCTSourceCodeContext:
    """Decoded proxy for ``XCTSourceCodeContext``."""

    location: Optional[XCTSourceCodeLocation]

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> XCTSourceCodeContext:
        location = archive_obj.decode("location")
        return XCTSourceCodeContext(location=location)


@dataclass
class XCTIssue:
    """Decoded proxy for ``XCTIssue`` / ``XCTMutableIssue``.

    ``compact_description`` is the short human-readable failure message
    (e.g. ``"((false) is true) failed"``).
    """

    compact_description: str
    detailed_description: Optional[str]
    source_code_context: Optional[XCTSourceCodeContext]
    issue_type: int = 0

    def __str__(self) -> str:
        loc = ""
        if self.source_code_context and self.source_code_context.location:
            loc = f" at {self.source_code_context.location}"
        return f"XCTIssue({self.compact_description!r}{loc})"

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> XCTIssue:
        compact = archive_obj.decode("compact-description") or ""
        detailed = archive_obj.decode("detailed-description")
        ctx = archive_obj.decode("source-code-context")
        issue_type = archive_obj.decode("type") or 0
        return XCTIssue(
            compact_description=str(compact) if compact else "",
            detailed_description=str(detailed) if detailed else None,
            source_code_context=ctx,
            issue_type=int(issue_type),
        )


@dataclass
class XCActivityRecord:
    """Decoded proxy for ``XCActivityRecord`` — a single activity step in a test."""

    title: str
    activity_type: str
    uuid: Any  # NSUUID or None
    start: Any  # NSDate or None
    finish: Any  # NSDate or None
    attachments: list[Any] = field(default_factory=list)

    def __str__(self) -> str:
        return f"XCActivityRecord({self.title!r}, type={self.activity_type!r})"

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> XCActivityRecord:
        title = archive_obj.decode("title") or ""
        activity_type = archive_obj.decode("activityType") or ""
        uuid = archive_obj.decode("uuid")
        start = archive_obj.decode("start")
        finish = archive_obj.decode("finish")
        attachments = archive_obj.decode("attachments") or []
        return XCActivityRecord(
            title=str(title) if title else "",
            activity_type=str(activity_type) if activity_type else "",
            uuid=uuid,
            start=start,
            finish=finish,
            attachments=list(attachments) if attachments else [],
        )


@dataclass
class XCTAttachment:
    """Decoded proxy for ``XCTAttachment`` — a file attachment (screenshot, logs, etc.)."""

    name: str
    uniformTypeIdentifier: str
    timestamp: Any  # NSDate or None
    data: Optional[bytes] = None
    additional_data: dict = field(default_factory=dict)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> XCTAttachment:
        name = archive_obj.decode("name") or ""
        uti = archive_obj.decode("uniformTypeIdentifier") or ""
        timestamp = archive_obj.decode("timestamp")
        data = archive_obj.decode("data")
        # Capture any additional fields that may be present
        additional_data = {}
        for key in ("metadata", "file-path", "file-url"):
            val = archive_obj.decode(key)
            if val is not None:
                additional_data[key] = val
        return XCTAttachment(
            name=str(name) if name else "",
            uniformTypeIdentifier=str(uti) if uti else "",
            timestamp=timestamp,
            data=data if isinstance(data, bytes) else None,
            additional_data=additional_data,
        )


@dataclass
class XCTestCaseRunConfiguration:
    """Decoded proxy for ``XCTestCaseRunConfiguration``."""

    iteration: int
    configuration: dict = field(default_factory=dict)

    @staticmethod
    def decode_archive(
        archive_obj: archiver.ArchivedObject,
    ) -> XCTestCaseRunConfiguration:
        iteration = archive_obj.decode("iteration") or 1
        configuration = archive_obj.decode("configuration") or {}
        return XCTestCaseRunConfiguration(
            iteration=int(iteration),
            configuration=dict(configuration) if configuration else {},
        )


archiver.update_class_map({
    "XCTTestIdentifier": XCTTestIdentifier,
    "XCTSourceCodeLocation": XCTSourceCodeLocation,
    "XCTSourceCodeContext": XCTSourceCodeContext,
    "XCTIssue": XCTIssue,
    "XCTMutableIssue": XCTIssue,
    "XCActivityRecord": XCActivityRecord,
    "XCTAttachment": XCTAttachment,
    "XCTestCaseRunConfiguration": XCTestCaseRunConfiguration,
})
