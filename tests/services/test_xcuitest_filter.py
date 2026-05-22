"""Reproduction test for GitHub issue #1678 — TestConfig.tests_to_run filter silently ignored.

https://github.com/doronz88/pymobiledevice3/issues/1678

Summary
-------
When ``TestConfig(tests_to_run=...)`` is used on iOS 17+, the filter is silently ignored and
the full test suite runs instead of just the requested subset.  The issue is that
``XCTestConfiguration`` serialises ``testsToRun`` as plain ``NSString`` objects (via Python
``set``/``str``), but iOS 17+ XCTest matches filters against ``XCTTestIdentifier`` objects.
``XCTTestIdentifier`` has a ``decode_archive`` but no ``encode_archive``, so the outgoing
payload never contains proper ``XCTTestIdentifier`` archive nodes.

Test structure
--------------
1. ``test_baseline_no_filter``  - run the full bundle, collect every test that fires.
   This establishes the baseline set of test names for the bundle.

2. ``test_filter_with_plain_strings``  - pass ``tests_to_run`` as a list of plain
   ``str`` identifiers.  Assert that the runner reports "Selected tests" (not "All tests")
   as the top-level suite, and that *only* the requested test(s) ran.

3. ``test_filter_with_xct_identifiers``  - same as above, but wraps the identifier in an
   ``XCTTestIdentifier`` instance, confirming that objects are also handled correctly.

Configuration
-------------
Tests are parametrized via ``tests/services/xcuitest.json`` (not tracked by git).
Copy ``xcuitest.json.example`` and fill in your own values.  The config entries used
by these tests must include:

.. code-block:: json

    {
        "id":              "my_app",
        "runner_bundle_id": "com.example.MyApp.xctrunner",
        "target_bundle_id": "com.example.MyApp",
        "filter_test":      "MyAppUITests/testSomething",
        "all_tests":        ["MyAppUITests/testSomething", "MyAppUITests/testOther"],
        "runner_env":       {},
        "timeout":          60.0
    }

Usage
-----
    # iOS 17+ via tunneld:
    pytest tests/services/test_xcuitest_filter_repro.py -s --tunnel '' -v

    # iOS 14-16 via USB:
    pytest tests/services/test_xcuitest_filter_repro.py -s -v
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import pytest
import pytest_asyncio

from pymobiledevice3.services.dvt.testmanaged.xctest_types import (
    XCTestConfiguration,
    XCTTestIdentifier,
)
from pymobiledevice3.services.dvt.testmanaged.xcuitest import (
    TestConfig as _TestConfig,
)
from pymobiledevice3.services.dvt.testmanaged.xcuitest import (
    XCTestCaseResult,
    XCUITestListener,
    XCUITestService,
)

logger = logging.getLogger(__name__)

# Default timeout for each run (seconds); overridden per-config via xcuitest.json.
RUN_TIMEOUT = 120.0


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------


class _RecordingListener(XCUITestListener):
    """Captures test lifecycle events so tests can assert on them."""

    def __init__(self) -> None:
        self.suite_starts: list[str] = []
        self.suite_finishes: list[str] = []
        self.test_cases_started: list[str] = []
        self.test_cases_finished: list[str] = []
        self.log_messages: list[str] = []
        self.ready_event = asyncio.Event()
        # Tracks the outermost top-level suite name reported by the runner.
        # "All tests"      → filter NOT applied
        # "Selected tests" → filter WAS applied (iOS 17+ XCTest)
        self.top_level_suite: Optional[str] = None

    async def did_begin_executing_test_plan(self) -> None:
        logger.info("[listener] did_begin_executing_test_plan")

    async def did_finish_executing_test_plan(self) -> None:
        logger.info("[listener] did_finish_executing_test_plan")

    async def test_bundle_ready(self) -> None:
        self.ready_event.set()

    async def test_bundle_ready_with_capabilities(self, capabilities) -> Optional[XCTestConfiguration]:
        self.ready_event.set()
        return None

    async def test_bundle_ready_with_protocol_version(self, protocol_version, minimum_version) -> None:
        self.ready_event.set()

    async def test_suite_did_start(self, suite: str, started_at: str) -> None:
        logger.info("[listener] suite_start: %r", suite)
        self.suite_starts.append(suite)
        # NOTE: dtx_services.py filters out "All tests" (and the empty-string
        # root suite) before calling this method, so "All tests" never arrives
        # here.  "Selected tests" is NOT filtered, so it arrives when a
        # testsToRun filter was honoured by the runner.
        if self.top_level_suite is None and suite == "Selected tests":
            self.top_level_suite = suite

    async def test_suite_did_finish(
        self,
        suite,
        finished_at,
        run_count,
        failures,
        unexpected,
        test_duration,
        total_duration,
        skipped,
        expected_failures,
        uncaught_exceptions,
    ) -> None:
        logger.info("[listener] suite_finish: %r  run_count=%s", suite, run_count)
        self.suite_finishes.append(suite)

    async def test_case_did_start(self, test_class: str, method: str) -> None:
        identifier = f"{test_class}/{method}"
        logger.info("[listener] case_start: %s", identifier)
        self.test_cases_started.append(identifier)

    async def test_case_did_finish(self, result: XCTestCaseResult) -> None:
        identifier = f"{result.test_class}/{result.method}"
        logger.info("[listener] case_finish: %s  status=%s", identifier, result.status)
        self.test_cases_finished.append(identifier)

    async def test_case_did_fail(self, test_class, method, message, file, line) -> None:
        logger.warning("[listener] case_fail: %s/%s  msg=%r", test_class, method, message)

    async def log_message(self, message: str) -> None:
        self.log_messages.append(message)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def xcuitest_svc(service_provider) -> XCUITestService:
    """Create an XCUITestService, skipping if DVT is unavailable."""
    from pymobiledevice3.exceptions import InvalidServiceError
    from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider

    try:
        async with DvtProvider(service_provider):
            pass
    except InvalidServiceError:
        pytest.skip("DVT provider not accessible — is a developer image mounted?")
    return XCUITestService(service_provider)


async def _run_with_listener(
    svc: XCUITestService,
    cfg: _TestConfig,
    *,
    timeout: float = RUN_TIMEOUT,
) -> _RecordingListener:
    """Run the test suite and return the populated listener."""
    listener = _RecordingListener()
    await svc.run(cfg, timeout=timeout, listener=listener)
    return listener


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_baseline_no_filter(xcuitest_svc: XCUITestService, xcuitest_cfg: dict[str, Any]) -> None:
    """Baseline: run the full bundle without any filter.

    Asserts:
    - The plan finishes without timeout.
    - At least one test case was executed.
    - The top-level suite is not "Selected tests" (no filter applied).
    - All expected tests ran (if ``all_tests`` is provided in the config).
    """
    timeout = xcuitest_cfg.get("timeout", RUN_TIMEOUT)
    cfg = await _TestConfig.create_for(
        xcuitest_svc.lockdown,
        runner_bundle_id=xcuitest_cfg["runner_bundle_id"],
        target_bundle_id=xcuitest_cfg["target_bundle_id"],
    )
    assert cfg.tests_to_run is None

    listener = await _run_with_listener(xcuitest_svc, cfg, timeout=timeout)

    print("\n=== Baseline run (no filter) ===")
    print(f"  Top-level suite  : {listener.top_level_suite!r}")
    print(f"  Suite starts     : {listener.suite_starts}")
    print(f"  Tests started    : {listener.test_cases_started}")
    print(f"  Tests finished   : {listener.test_cases_finished}")

    assert listener.test_cases_started, "No test cases started — bundle may be empty or runner failed"

    assert listener.top_level_suite is None, (
        f"Without a filter, 'Selected tests' should NOT appear; got {listener.top_level_suite!r}"
    )

    all_tests = xcuitest_cfg.get("all_tests")
    if all_tests:
        ran = set(listener.test_cases_started)
        expected = set(all_tests)
        assert ran == expected, (
            f"Expected all bundle tests to run without a filter.\n"
            f"  Missing: {expected - ran}\n"
            f"  Extra:   {ran - expected}"
        )


@pytest.mark.asyncio
async def test_filter_with_plain_strings(xcuitest_svc: XCUITestService, xcuitest_cfg: dict[str, Any]) -> None:
    """Verify filter via tests_to_run=[str] works after the fix for issue #1678.

    Previously this silently ran the full bundle because:
    - testsToRun was serialised as NSSet<NSString> (ignored by iOS 17+ runners)
    - testIdentifiersToRun was absent from XCTestConfiguration

    After the fix, both testsToRun (legacy) and testIdentifiersToRun
    (XCTTestIdentifierSet with XCTTestIdentifier objects) are populated.
    """
    filter_test = xcuitest_cfg.get("filter_test")
    if not filter_test:
        pytest.skip("'filter_test' not set in xcuitest config")

    timeout = xcuitest_cfg.get("timeout", RUN_TIMEOUT)
    cfg = await _TestConfig.create_for(
        xcuitest_svc.lockdown,
        runner_bundle_id=xcuitest_cfg["runner_bundle_id"],
        target_bundle_id=xcuitest_cfg["target_bundle_id"],
    )
    cfg.tests_to_run = [filter_test]

    listener = await _run_with_listener(xcuitest_svc, cfg, timeout=timeout)

    print("\n=== Filter run (plain strings) ===")
    print(f"  Requested filter : {filter_test!r}")
    print(f"  Top-level suite  : {listener.top_level_suite!r}")
    print(f"  Tests started    : {listener.test_cases_started}")
    print(f"  Tests finished   : {listener.test_cases_finished}")

    assert listener.top_level_suite == "Selected tests", (
        f"Filter was NOT applied: top-level suite is {listener.top_level_suite!r} "
        f"instead of 'Selected tests'. This reproduces issue #1678 — "
        f"tests_to_run={cfg.tests_to_run!r} was silently ignored."
    )
    assert listener.test_cases_started == [filter_test], (
        f"Only {filter_test!r} should have run, but runner executed: {listener.test_cases_started}"
    )


@pytest.mark.asyncio
async def test_filter_with_xct_identifiers(xcuitest_svc: XCUITestService, xcuitest_cfg: dict[str, Any]) -> None:
    """Verify that passing XCTTestIdentifier objects in tests_to_run also works.

    This confirms that:
    - XCTTestIdentifier.encode_archive is implemented
    - XCTTestIdentifier is hashable
    - When XCTTestIdentifier objects are passed, they are converted to
      strings via str() and then to XCTTestIdentifierSet — filter applies.
    """
    filter_test = xcuitest_cfg.get("filter_test")
    if not filter_test:
        pytest.skip("'filter_test' not set in xcuitest config")

    components = filter_test.split("/")
    identifier = XCTTestIdentifier(components=components)

    assert hasattr(identifier, "encode_archive"), "XCTTestIdentifier is missing encode_archive"
    assert callable(identifier.__hash__), "XCTTestIdentifier is not hashable"

    timeout = xcuitest_cfg.get("timeout", RUN_TIMEOUT)
    cfg = await _TestConfig.create_for(
        xcuitest_svc.lockdown,
        runner_bundle_id=xcuitest_cfg["runner_bundle_id"],
        target_bundle_id=xcuitest_cfg["target_bundle_id"],
    )
    cfg.tests_to_run = [identifier]

    listener = await _run_with_listener(xcuitest_svc, cfg, timeout=timeout)

    print("\n=== Filter run (XCTTestIdentifier) ===")
    print(f"  Requested filter : {identifier!r}")
    print(f"  Top-level suite  : {listener.top_level_suite!r}")
    print(f"  Tests started    : {listener.test_cases_started}")

    assert listener.top_level_suite == "Selected tests", (
        f"Filter still NOT applied with XCTTestIdentifier objects: top-level suite is {listener.top_level_suite!r}."
    )
    assert listener.test_cases_started == [filter_test], (
        f"Only {filter_test!r} should have run, but got: {listener.test_cases_started}"
    )
