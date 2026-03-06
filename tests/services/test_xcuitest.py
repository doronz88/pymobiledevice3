"""Integration test for XCUITest execution via the DTX implementation.

Run with:
    pytest tests/services/test_xcuitest.py -s --tunnel '' -v

Configurations (runner + target bundle IDs, optional env and timeout) are
read from ``tests/services/xcuitest.json``
(see ``xcuitest.json.example`` for the expected format).
Each entry in that JSON array becomes a separate parametrized test run.

Override the config file path:
    pytest --xcuitest-config /path/to/config.json ...
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import Any

import pytest

from pymobiledevice3.services.dvt.testmanaged.xcuitest import (
    TestConfig as _TestConfig,
)
from pymobiledevice3.services.dvt.testmanaged.xcuitest import (
    XCTestCaseResult,
    XCUITestListener,
    XCUITestService,
)


class _RecordingListener(XCUITestListener):
    """Captures lifecycle events for assertion in tests."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.runner_ready_event = asyncio.Event()

    async def did_begin_executing_test_plan(self) -> None:
        self.events.append("begin_plan")

    async def did_finish_executing_test_plan(self) -> None:
        self.events.append("finish_plan")

    async def test_suite_did_start(self, suite: str, started_at: str) -> None:
        self.events.append(f"suite_start:{suite}")

    async def test_suite_did_finish(
        self, suite, finished_at, run_count, failures, unexpected, test_duration, total_duration
    ) -> None:
        self.events.append(f"suite_finish:{suite}")

    async def test_case_did_start(self, test_class: str, method: str) -> None:
        self.events.append(f"case_start:{test_class}/{method}")

    async def test_case_did_finish(self, result: XCTestCaseResult) -> None:
        self.events.append(f"case_finish:{result.test_class}/{result.method}:{result.status}")

    async def test_case_did_fail(self, test_class, method, message, file, line) -> None:
        self.events.append(f"case_fail:{test_class}/{method}")

    async def log_message(self, message: str) -> None:
        self.events.append(f"log:{message[:60]}")

    # --- overrides to signal test readiness for test_xcuitest_runner_ready ---

    async def test_bundle_ready(self):
        self.runner_ready_event.set()
        return await super().test_bundle_ready()

    async def test_bundle_ready_with_capabilities(self, capabilities):
        self.runner_ready_event.set()
        return await super().test_bundle_ready_with_capabilities(capabilities)

    async def test_bundle_ready_with_protocol_version(self, protocol_version, minimum_version):
        self.runner_ready_event.set()
        return await super().test_bundle_ready_with_protocol_version(protocol_version, minimum_version)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_cfg(
    xcuitest_service: XCUITestService,
    xcuitest_cfg: dict[str, Any],
) -> _TestConfig:
    cfg = await _TestConfig.create_for(
        xcuitest_service.lockdown,
        xcuitest_cfg["runner_bundle_id"],
        xcuitest_cfg.get("target_bundle_id"),
    )
    cfg.runner_app_env = xcuitest_cfg.get("runner_env") or None
    return cfg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_xcuitest_runner_ready(
    xcuitest_service: XCUITestService,
    xcuitest_cfg: dict[str, Any],
) -> None:
    """Assert the XCUITest runner reaches the ready state (full handshake verified).

    We do not wait for test-plan completion; verifying
    ``_XCT_testRunnerReadyWithCapabilities_`` fires is sufficient to validate
    the entire DTX connection and proxy setup.
    """
    listener = _RecordingListener()
    cfg = await _make_cfg(xcuitest_service, xcuitest_cfg)
    timeout = xcuitest_cfg.get("timeout", 30.0)

    task = asyncio.create_task(
        xcuitest_service.run(
            cfg,
            timeout=timeout,
            listener=listener,
        )
    )
    try:
        await asyncio.wait_for(listener.runner_ready_event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pytest.fail("_XCT_testRunnerReadyWithCapabilities_ was not received within 90s")
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError, TimeoutError, Exception):
            await task

    print(f"\n[listener events] {listener.events}")


@pytest.mark.asyncio
async def test_xcuitest_full_completion(
    xcuitest_service: XCUITestService,
    xcuitest_cfg: dict[str, Any],
) -> None:
    """Assert the test plan runs to completion.

    Key regression test: the runner must receive the XCTestConfiguration reply
    on the correct channel code, load the test bundle, run all tests, and fire
    ``_XCT_didFinishExecutingTestPlan``.
    """
    listener = _RecordingListener()
    cfg = await _make_cfg(xcuitest_service, xcuitest_cfg)
    await xcuitest_service.run(cfg, timeout=xcuitest_cfg.get("timeout", 30.0), listener=listener)
    print(f"\n[listener events] {listener.events}")
    assert "finish_plan" in listener.events, f"Test plan did not finish. Events: {listener.events}"
