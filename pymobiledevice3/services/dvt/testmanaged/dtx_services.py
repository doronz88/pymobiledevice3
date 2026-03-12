"""DTXService subclasses for the XCTest / testmanagerd protocol.

These classes model the service endpoints used when driving XCUITest runs:

* :class:`XCTestCaseResult` — result record for a single test case
* :class:`XCUITestListener` — base class for XCUITest lifecycle callbacks
* :class:`XCTestManager_IDEInterface` — IDE-side handler for ``_XCT_*`` calls
* :class:`XCTestDriverInterface` — outgoing test-plan control calls
* :class:`XCTestManager_DaemonConnectionInterface` — session init / authorisation
* :class:`ProcessControlService` — launches the test runner process
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

from pymobiledevice3.dtx import NSUUID, DTXService, NSError, dtx_method, dtx_on_invoke
from pymobiledevice3.services.dvt.testmanaged.xctest_types import (
    XCActivityRecord,
    XCTCapabilities,
    XCTestCaseRunConfiguration,
    XCTestConfiguration,
    XCTIssue,
    XCTTestIdentifier,
)

logger = logging.getLogger(__name__)

XCODE_VERSION = 36  # Xcode version reported to testmanagerd (value is not significant)


# ---------------------------------------------------------------------------
# Listener protocol
# ---------------------------------------------------------------------------


@dataclass
class XCTestCaseResult:
    test_class: str
    method: str
    status: str  # "passed" | "failed" | "skipped"
    duration: float


class XCUITestListener:
    """Base class for XCUITest lifecycle callbacks.

    Override whichever methods you care about.  All methods may be either
    synchronous or ``async``.  The default implementations are no-ops.
    """

    # --- plan ---------------------------------------------------------------

    async def did_begin_executing_test_plan(self) -> None:
        """Invoked when the test runner begins executing the test plan."""

    async def did_finish_executing_test_plan(self) -> None:
        """Invoked when the test runner has finished the entire test plan."""

    # --- bundle (protocol initialization) -----------------------------------

    async def test_bundle_ready(self) -> None:
        """Invoked when the test bundle signals readiness (old protocol)."""

    async def test_bundle_ready_with_capabilities(self, capabilities: XCTCapabilities) -> Optional[XCTestConfiguration]:
        """Invoked when the test bundle signals readiness with capabilities (new protocol).

        The default implementation ignores the capabilities and returns ``None``
        (which results in the default :class:`XCTestConfiguration` being used).
        Override to inspect the capabilities and optionally return a custom
        :class:`XCTestConfiguration` to use for the test run.
        """

    async def test_bundle_ready_with_protocol_version(self, protocol_version: int, minimum_version: int) -> None:
        """Invoked when the test bundle reports its protocol version."""

    # --- suite lifecycle ---------------------------------------------------

    async def test_suite_did_start(self, suite: str, started_at: str) -> None:
        """Invoked when a test suite starts."""

    async def test_suite_did_finish(
        self,
        suite: str,
        finished_at: str,
        run_count: int,
        failures: int,
        unexpected: int,
        test_duration: float,
        total_duration: float,
        skipped: int,
        expected_failures: int,
        uncaught_exceptions: int,
    ) -> None:
        """Invoked when a test suite finishes."""

    # --- case lifecycle ---------------------------------------------------

    async def test_case_did_start(
        self, test_class: str, method: str, configuration: Optional[XCTestCaseRunConfiguration] = None
    ) -> None:
        """Invoked when a single test case starts."""

    async def test_case_did_finish(self, result: XCTestCaseResult) -> None:
        """Invoked when a single test case finishes."""

    async def test_case_did_fail(self, test_class: str, method: str, message: str, file: str, line: int) -> None:
        """Invoked when a test case records a failure."""

    async def test_case_did_stall(self, test_class: str, method: str, file: str, line: int) -> None:
        """Invoked when a test case stalls on the main thread."""

    # --- case activities --------------------------------------------------

    async def test_case_will_start_activity(self, test_class: str, method: str, activity: XCActivityRecord) -> None:
        """Invoked when a test case is about to start an activity."""

    async def test_case_did_finish_activity(self, test_class: str, method: str, activity: XCActivityRecord) -> None:
        """Invoked when a test case finishes an activity."""

    async def test_method_did_measure_metric(
        self, test_class: str, method: str, metric: str, file: str, line: int
    ) -> None:
        """Invoked when a test method measures a performance metric."""

    # --- logging ---------------------------------------------------------

    async def log_message(self, message: str) -> None:
        """Invoked for informational log messages from the runner."""

    async def log_debug_message(self, message: str) -> None:
        """Invoked for debug log messages from the runner."""

    # --- protocol --------------------------------------------------------

    async def exchange_protocol_version(self, current: int, minimum: int) -> None:
        """Invoked when the runner negotiates protocol versions."""

    # --- XCTest (modern iOS 14+ lifecycle) --------------------------------

    async def did_begin_initializing_for_ui_testing(self) -> None:
        """Invoked when initialization for UI testing begins."""

    async def did_form_plan(self, data: Any) -> None:
        """Invoked when the test runner forms a test plan."""

    async def get_progress_for_launch(self, token: Any) -> None:
        """Invoked to get progress for a launch operation."""

    async def initialization_for_ui_testing_did_fail(self, error: NSError) -> None:
        """Invoked when UI testing initialization fails."""

    async def did_fail_to_bootstrap(self, error: NSError) -> None:
        """Invoked when the test runner fails to bootstrap."""


# ---------------------------------------------------------------------------
# DTXService class definitions
# ---------------------------------------------------------------------------


class XCTestManager_IDEInterface(DTXService):
    """Local (IDE-side) service — handles incoming ``_XCT_*`` calls from the runner."""

    IDENTIFIER = "XCTestManager_IDEInterface"

    def _listener(self) -> Optional[XCUITestListener]:
        return self._ctx.get("xcuitest_listener")

    # --- logging --------------------------------------------------------

    @dtx_on_invoke
    async def _XCT_logDebugMessage_(self, message: str) -> None:
        logger.debug("[IDE] logDebugMessage: %s", message)
        li = self._listener()
        if li is not None:
            await li.log_debug_message(message)

    @dtx_on_invoke
    async def _XCT_logMessage_(self, message: str) -> None:
        logger.info("[IDE] logMessage: %s", message)
        li = self._listener()
        if li is not None:
            await li.log_message(message)

    # --- protocol negotiation -------------------------------------------

    @dtx_on_invoke
    async def _XCT_exchangeCurrentProtocolVersion_minimumVersion_(self, current: int, minimum: int) -> None:
        logger.debug("[IDE] exchangeCurrentProtocolVersion: %s minimum: %s", current, minimum)
        li = self._listener()
        if li is not None:
            await li.exchange_protocol_version(current, minimum)

    # --- bundle ready ---------------------------------------------------

    @dtx_on_invoke
    async def _XCT_testBundleReady(self) -> None:
        logger.info("[IDE] testBundleReady")
        li = self._listener()
        if li is not None:
            await li.test_bundle_ready()

    @dtx_on_invoke
    async def _XCT_testBundleReadyWithProtocolVersion_minimumVersion_(
        self, protocol_version: int, minimum_version: int
    ) -> None:
        logger.info(
            "[IDE] testBundleReadyWithProtocolVersion: %s minimumVersion: %s",
            protocol_version,
            minimum_version,
        )
        li = self._listener()
        if li is not None:
            await li.test_bundle_ready_with_protocol_version(protocol_version, minimum_version)

    # --- runner ready ---------------------------------------------------

    @dtx_on_invoke
    async def _XCT_testRunnerReadyWithCapabilities_(self, capabilities: XCTCapabilities) -> XCTestConfiguration:
        logger.info("[IDE] testRunnerReadyWithCapabilities: %s", capabilities.capabilities)
        li = self._listener()
        xctestconfig = self._ctx["xctest_config"]
        if li is not None:
            xctestconfig = await li.test_bundle_ready_with_capabilities(capabilities) or xctestconfig
        return xctestconfig

    # --- test plan lifecycle --------------------------------------------

    @dtx_on_invoke
    async def _XCT_didBeginExecutingTestPlan(self) -> None:
        logger.info("[IDE] didBeginExecutingTestPlan")
        li = self._listener()
        if li is not None:
            await li.did_begin_executing_test_plan()

    @dtx_on_invoke
    async def _XCT_didFinishExecutingTestPlan(self) -> None:
        logger.info("[IDE] didFinishExecutingTestPlan")
        event: Optional[asyncio.Event] = self._ctx.get("test_done_event")
        if event is not None:
            event.set()
        li = self._listener()
        if li is not None:
            await li.did_finish_executing_test_plan()

    # --- suite lifecycle ------------------------------------------------

    @dtx_on_invoke
    async def _XCT_testSuite_didStartAt_(self, suite: str, started_at: str) -> None:
        logger.info("[IDE] testSuite: %r didStartAt: %s", suite, started_at)
        li = self._listener()
        if li is not None:
            await li.test_suite_did_start(suite, started_at)

    @dtx_on_invoke
    async def _XCT_testSuite_didFinishAt_runCount_withFailures_unexpected_testDuration_totalDuration_(
        self,
        suite: str,
        finished_at: str,
        run_count: int,
        failures: int,
        unexpected: int,
        test_duration: float,
        total_duration: float,
    ) -> None:
        logger.info(
            "[IDE] testSuite: %r didFinishAt: %s run=%d fail=%d dur=%.3fs",
            suite,
            finished_at,
            run_count,
            failures,
            total_duration,
        )
        li = self._listener()
        if li is not None:
            await li.test_suite_did_finish(
                suite=suite,
                finished_at=finished_at,
                run_count=run_count,
                failures=failures,
                unexpected=unexpected,
                test_duration=test_duration,
                total_duration=total_duration,
                skipped=0,
                expected_failures=0,
                uncaught_exceptions=0,
            )

    # --- case lifecycle -------------------------------------------------

    @dtx_on_invoke
    async def _XCT_testCaseDidStartForTestClass_method_(self, test_class: str, method: str) -> None:
        logger.info("[IDE] testCaseDidStart: %s/%s", test_class, method)
        li = self._listener()
        if li is not None:
            await li.test_case_did_start(test_class, method)

    @dtx_on_invoke
    async def _XCT_testCaseDidFinishForTestClass_method_withStatus_duration_(
        self, test_class: str, method: str, status: str, duration: float
    ) -> None:
        logger.info(
            "[IDE] testCaseDidFinish: %s/%s status=%s dur=%.3fs",
            test_class,
            method,
            status,
            duration,
        )
        li = self._listener()
        if li is not None:
            await li.test_case_did_finish(XCTestCaseResult(test_class, method, status, duration))

    @dtx_on_invoke
    async def _XCT_testCaseDidFailForTestClass_method_withMessage_file_line_(
        self, test_class: str, method: str, message: str, file: str, line: int
    ) -> None:
        logger.warning(
            "[IDE] testCaseDidFail: %s/%s '%s' at %s:%d",
            test_class,
            method,
            message,
            file,
            line,
        )
        li = self._listener()
        if li is not None:
            await li.test_case_did_fail(test_class, method, message, file, line)

    @dtx_on_invoke
    async def _XCT_testCase_method_didStallOnMainThreadInFile_line_(
        self, test_class: str, method: str, file: str, line: int
    ) -> None:
        logger.warning("[IDE] testCaseDidStall: %s/%s at %s:%d", test_class, method, file, line)
        li = self._listener()
        if li is not None:
            await li.test_case_did_stall(test_class, method, file, line)

    # --- modern (identifier-based) lifecycle — iOS 14+ -------------------

    @dtx_on_invoke
    async def _XCT_didBeginInitializingForUITesting(self) -> None:
        logger.debug("[IDE] didBeginInitializingForUITesting")
        li = self._listener()
        if li is not None:
            await li.did_begin_initializing_for_ui_testing()

    @dtx_on_invoke
    async def _XCT_didFormPlanWithData_(self, data: Any) -> None:
        logger.debug("[IDE] didFormPlanWithData: %s", data)
        li = self._listener()
        if li is not None:
            await li.did_form_plan(data)

    @dtx_on_invoke
    async def _XCT_getProgressForLaunch_(self, token: Any) -> None:
        logger.debug("[IDE] getProgressForLaunch: %s", token)
        li = self._listener()
        if li is not None:
            await li.get_progress_for_launch(token)

    @dtx_on_invoke
    async def _XCT_initializationForUITestingDidFailWithError_(self, error: NSError) -> None:
        logger.error("[IDE] initializationForUITestingDidFailWithError: %s", error)
        li = self._listener()
        if li is not None:
            await li.initialization_for_ui_testing_did_fail(error)

    @dtx_on_invoke
    async def _XCT_didFailToBootstrapWithError_(self, error: NSError) -> None:
        logger.error("[IDE] didFailToBootstrapWithError: %s", error)
        li = self._listener()
        if li is not None:
            await li.did_fail_to_bootstrap(error)

    @dtx_on_invoke
    async def _XCT_testSuiteWithIdentifier_didStartAt_(self, identifier: XCTTestIdentifier, started_at: str) -> None:
        suite = identifier.test_class
        logger.info("[IDE] testSuiteWithIdentifier: %r didStartAt: %s", identifier, started_at)
        if not suite or suite == "All tests":
            return
        li = self._listener()
        if li is not None:
            await li.test_suite_did_start(suite, started_at)

    @dtx_on_invoke
    async def _XCT_testMethod_ofClass_didMeasureMetric_file_line_(
        self, method: str, test_class: str, metric: str, file: str, line: int
    ) -> None:
        logger.info(
            "[IDE] testMethod: %s ofClass: %s didMeasureMetric: %s at %s:%d",
            method,
            test_class,
            metric,
            file,
            line,
        )
        li = self._listener()
        if li is not None:
            await li.test_method_did_measure_metric(test_class, method, metric, file, line)

    @dtx_on_invoke
    async def _XCT_testSuiteWithIdentifier_didFinishAt_runCount_skipCount_failureCount_expectedFailureCount_uncaughtExceptionCount_testDuration_totalDuration_(
        self,
        identifier: XCTTestIdentifier,
        finished_at: str,
        run_count: int,
        skip_count: int,
        failure_count: int,
        expected_failure_count: int,
        uncaught_exception_count: int,
        test_duration: float,
        total_duration: float,
    ) -> None:
        suite = identifier.test_class
        logger.info(
            "[IDE] testSuiteWithIdentifier: %r didFinishAt: %s run=%d skip=%d fail=%d exp_fail=%d, unc=%d dur=%.3fs total=%.3fs",
            identifier,
            finished_at,
            run_count,
            skip_count,
            failure_count,
            expected_failure_count,
            uncaught_exception_count,
            test_duration,
            total_duration,
        )
        if not suite or suite == "All tests":
            return
        li = self._listener()
        if li is not None:
            await li.test_suite_did_finish(
                suite=suite,
                finished_at=finished_at,
                run_count=run_count,
                failures=failure_count,
                unexpected=failure_count - expected_failure_count,
                test_duration=test_duration,
                total_duration=total_duration,
                skipped=skip_count,
                expected_failures=expected_failure_count,
                uncaught_exceptions=uncaught_exception_count,
            )

    @dtx_on_invoke
    async def _XCT_testCaseDidStartWithIdentifier_testCaseRunConfiguration_(
        self, identifier: XCTTestIdentifier, config: XCTestCaseRunConfiguration
    ) -> None:
        test_class = identifier.test_class
        method = identifier.test_method or ""
        logger.info("[IDE] testCaseDidStart: %s/%s (iter=%d)", test_class, method, config.iteration)
        li = self._listener()
        if li is not None:
            await li.test_case_did_start(test_class, method)

    @dtx_on_invoke
    async def _XCT_testCaseWithIdentifier_didFinishWithStatus_duration_(
        self, identifier: XCTTestIdentifier, status: str, duration: float
    ) -> None:
        test_class = identifier.test_class
        method = identifier.test_method or ""
        logger.info(
            "[IDE] testCaseDidFinish: %s/%s status=%s dur=%.3fs",
            test_class,
            method,
            status,
            duration,
        )
        li = self._listener()
        if li is not None:
            await li.test_case_did_finish(XCTestCaseResult(test_class, method, status, duration))

    @dtx_on_invoke
    async def _XCT_testCaseWithIdentifier_didRecordIssue_(self, identifier: XCTTestIdentifier, issue: XCTIssue) -> None:
        test_class = identifier.test_class
        method = identifier.test_method or ""
        message = issue.compact_description
        file = ""
        line = 0
        if issue.source_code_context and issue.source_code_context.location:
            loc = issue.source_code_context.location
            file = loc.file_path or ""
            line = loc.line_number
        logger.warning(
            "[IDE] testCaseDidRecordIssue: %s/%s '%s' at %s:%d",
            test_class,
            method,
            message,
            file,
            line,
        )
        li = self._listener()
        if li is not None:
            await li.test_case_did_fail(test_class, method, message, file, line)

    @dtx_on_invoke
    async def _XCT_testCaseWithIdentifier_willStartActivity_(
        self, identifier: XCTTestIdentifier, activity: XCActivityRecord
    ) -> None:
        logger.debug("[IDE] testCase: %s willStartActivity: %s", identifier, activity)
        li = self._listener()
        if li is not None:
            await li.test_case_will_start_activity(identifier.test_class, identifier.test_method or "", activity)

    @dtx_on_invoke
    async def _XCT_testCaseWithIdentifier_didFinishActivity_(
        self, identifier: XCTTestIdentifier, activity: XCActivityRecord
    ) -> None:
        logger.debug("[IDE] testCase: %s didFinishActivity: %s", identifier, activity)
        li = self._listener()
        if li is not None:
            await li.test_case_did_finish_activity(identifier.test_class, identifier.test_method or "", activity)

    @dtx_on_invoke
    async def _XCT_testCase_method_didFinishActivity_(
        self, test_class: str, method: str, activity: XCActivityRecord
    ) -> None:
        logger.debug("[IDE] testCase: %s/%s didFinishActivity: %s", test_class, method, activity)
        li = self._listener()
        if li is not None:
            await li.test_case_did_finish_activity(test_class, method, activity)

    @dtx_on_invoke
    async def _XCT_testCase_method_willStartActivity_(
        self, test_class: str, method: str, activity: XCActivityRecord
    ) -> None:
        logger.debug("[IDE] testCase: %s/%s willStartActivity: %s", test_class, method, activity)
        li = self._listener()
        if li is not None:
            await li.test_case_will_start_activity(test_class, method, activity)


class XCTestDriverInterface(DTXService):
    """Remote (driver-side) service — outgoing test-plan control calls."""

    IDENTIFIER = "XCTestDriverInterface"

    @dtx_method("_IDE_startExecutingTestPlanWithProtocolVersion:")
    async def start_executing_test_plan(self, protocol_version: int) -> None: ...


class XCTestManager_DaemonConnectionInterface(DTXService):
    """Remote (daemon-side) service — session init and test process authorisation."""

    IDENTIFIER = "XCTestManager_DaemonConnectionInterface"

    @dtx_method
    async def _IDE_initiateControlSessionWithCapabilities_(self, capabilities: XCTCapabilities) -> XCTCapabilities: ...

    @dtx_method
    async def _IDE_initiateControlSessionWithProtocolVersion_(self, protocol_version: int) -> XCTCapabilities: ...

    @dtx_method
    async def _IDE_initiateSessionWithIdentifier_capabilities_(
        self, session_identifier: NSUUID, capabilities: XCTCapabilities
    ) -> XCTCapabilities: ...

    @dtx_method
    async def _IDE_initiateSessionWithIdentifier_forClient_atPath_protocolVersion_(
        self, session_identifier: NSUUID, client: str, path: str, protocol_version: int
    ) -> Any: ...

    @dtx_method
    async def _IDE_authorizeTestSessionWithProcessID_(self, pid: int) -> bool: ...

    @dtx_method
    async def _IDE_initiateControlSessionForTestProcessID_protocolVersion_(
        self, pid: int, protocol_version: int
    ) -> bool: ...

    @dtx_method
    async def _IDE_initiateControlSessionForTestProcessID_(self, pid: int) -> bool: ...

    async def init_ctrl_session(self, product_major_version: int) -> Any:
        if product_major_version >= 17:
            return await self._IDE_initiateControlSessionWithCapabilities_(XCTCapabilities({}))
        elif product_major_version >= 11:
            return await self._IDE_initiateControlSessionWithProtocolVersion_(XCODE_VERSION)
        return None

    async def init_session(
        self,
        product_major_version: int,
        session_identifier: NSUUID,
        xctest_config: XCTestConfiguration,
    ) -> Any:
        if product_major_version >= 17:
            return await self._IDE_initiateSessionWithIdentifier_capabilities_(
                session_identifier, xctest_config._config["IDECapabilities"]
            )
        elif product_major_version >= 11:
            return await self._IDE_initiateSessionWithIdentifier_forClient_atPath_protocolVersion_(
                session_identifier,
                "not-very-important",
                "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild",
                XCODE_VERSION,
            )
        return None

    async def authorize_test(self, product_major_version: int, pid: int) -> bool:
        if product_major_version >= 12:
            return await self._IDE_authorizeTestSessionWithProcessID_(pid)
        elif product_major_version >= 10:
            return await self._IDE_initiateControlSessionForTestProcessID_protocolVersion_(pid, XCODE_VERSION)
        else:
            return await self._IDE_initiateControlSessionForTestProcessID_(pid)


class ProcessControlService(DTXService):
    """Remote instruments process-control service — launches the test runner."""

    IDENTIFIER = "com.apple.instruments.server.services.processcontrol"

    @dtx_method("launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:")
    async def launch_suspended_process(
        self,
        device_path: str,
        bundle_identifier: str,
        environment: dict,
        arguments: list,
        options: dict,
    ) -> int: ...

    @dtx_on_invoke
    async def outputReceived_fromProcess_atTime_(self, output: str, pid: int, timestamp: int) -> None:
        logger.debug("[process:%d] %s", pid, output.rstrip())
