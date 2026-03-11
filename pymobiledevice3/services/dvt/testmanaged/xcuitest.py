"""XCUITest execution via the new DTX protocol implementation.

Typical usage::

    async with XCUITestService(lockdown) as svc:
        cfg = await TestConfig.create_for(lockdown, runner_bundle_id="com.example.MyAppUITests.xctrunner", target_bundle_id="com.example.MyApp")
        await svc.run(cfg, timeout=300.0)
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass
from typing import Optional, cast

from packaging.version import Version

from pymobiledevice3.dtx import (
    NSURL,
    NSUUID,
)
from pymobiledevice3.dtx.service import DTXProxyService as _DTXProxyService
from pymobiledevice3.dtx_proxy_service import DtxProxyService
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import AppNotInstalledError, ConnectionTerminatedError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider as InstrumentsDvtProvider
from pymobiledevice3.services.dvt.testmanaged.dtx_services import (  # noqa: F401 — re-exported
    ProcessControlService,
    XCTestCaseResult,
    XCTestDriverInterface,
    XCTestManager_DaemonConnectionInterface,
    XCTestManager_IDEInterface,
    XCUITestListener,
)
from pymobiledevice3.services.dvt.testmanaged.xctest_types import (
    XCTestConfiguration,
)
from pymobiledevice3.services.installation_proxy import InstallationProxyService

logger = logging.getLogger(__name__)
XCODE_VERSION = 36


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class _TestManagerProvider(DtxServiceProvider):
    """DTX transport to ``testmanagerd``.

    Registers the three XCTest service classes so the connection can
    instantiate them when either side opens a channel.
    """

    SERVICE_NAME = "com.apple.testmanagerd.lockdown.secure"
    RSD_SERVICE_NAME = "com.apple.dt.testmanagerd.remote"
    OLD_SERVICE_NAME = "com.apple.testmanagerd.lockdown"


class ProxyIdeToDaemonService(DtxProxyService[XCTestManager_IDEInterface, XCTestManager_DaemonConnectionInterface]):
    pass


class ProxyIdeToDriverService(DtxProxyService[XCTestManager_IDEInterface, XCTestDriverInterface]):
    async def _acquire_channel(self) -> _DTXProxyService:
        # Wait for the runner to open the reverse dtxproxy channel.
        logger.debug("Waiting for XCTestDriverInterface from runner ...")

        try:
            remote_svc = await self.dtx.wait_for_proxied_service(XCTestDriverInterface, remote=True, timeout=30.0)
        except asyncio.TimeoutError:
            raise RuntimeError("Timed out waiting for XCTestDriverInterface — runner did not connect") from None
        else:
            return remote_svc.dtxproxy


class ProcessControlChannel(DtxService[ProcessControlService]):
    """Opens the ProcessControl service channel on the DVT connection."""


class XCUITestService:
    """Orchestrates an XCUITest run using :class:`DTXConnection`.

    Service name selection is handled by :class:`_TestManagerProvider` and
    :class:`_DvtProvider` via :meth:`~DtxServiceProvider.service_name_for`,
    which mirrors the pattern used across the codebase:

    - RSD (iOS 17+ / tunnel) → ``RSD_SERVICE_NAME``
    - iOS ≥ 14.0 over lockdown → ``SERVICE_NAME``
    - iOS < 14.0 → ``OLD_SERVICE_NAME`` with SSL-context strip

    Usage::

        svc = XCUITestService(service_provider)
        await svc.run("com.example.MyAppUITests.xctrunner",
                      env={"AUT_BundleID": "com.example.MyApp"})
    """

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self.lockdown = lockdown

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        cfg: TestConfig,
        timeout: Optional[float] = None,
        test_done_event: Optional[asyncio.Event] = None,
        listener: Optional[XCUITestListener] = None,
    ) -> None:
        """Run the XCUITest wait for completion.

        :param cfg: TestConfig with test runner and target app information, as well as test selection.
        :param timeout: Seconds to wait for ``_XCT_didFinishExecutingTestPlan``
            after the test plan starts.  ``TimeoutError`` is raised on expiry.
        :param listener: Optional :class:`XCUITestListener` instance to receive
            lifecycle events (test suite/case start/finish, failures, etc.).
        """
        test_done = test_done_event or asyncio.Event()

        sid = NSUUID.uuid4()
        xctest_config = cfg.to_xctestconfiguration(sid, self.lockdown)
        product_major_version = Version(self.lockdown.product_version).major
        bundle_id = cfg.runner_app_info["CFBundleIdentifier"]
        env = cfg.runner_app_env
        args = cfg.runner_app_args
        xctest_path = f"/tmp/{str(sid).upper()}.xctestconfiguration"

        dvt_provider = InstrumentsDvtProvider(self.lockdown)
        control_test_manager_provider = _TestManagerProvider(self.lockdown)
        main_test_manager_provider = _TestManagerProvider(self.lockdown)

        async with dvt_provider, control_test_manager_provider, main_test_manager_provider:
            # Inject per-run context into the TM connections after connect().
            for tm_prov in (control_test_manager_provider, main_test_manager_provider):
                tm_prov.dtx.ctx["xctest_config"] = xctest_config
                tm_prov.dtx.ctx["test_done_event"] = test_done
                if listener is not None:
                    tm_prov.dtx.ctx["xcuitest_listener"] = listener

            # Open control and main dtxproxy channels.
            ctrl_proxy = ProxyIdeToDaemonService(control_test_manager_provider)
            main_proxy = ProxyIdeToDaemonService(main_test_manager_provider)
            process_control_channel = ProcessControlChannel(dvt_provider)
            driver_ch = ProxyIdeToDriverService(main_test_manager_provider)

            async with ctrl_proxy, main_proxy, process_control_channel:
                ctrl_daemon = cast(
                    XCTestManager_DaemonConnectionInterface,
                    ctrl_proxy.service.remote_service,
                )
                main_daemon = cast(
                    XCTestManager_DaemonConnectionInterface,
                    main_proxy.service.remote_service,
                )

                logger.debug("Initializing ctrl session ...")
                ctrl_result = await ctrl_daemon.init_ctrl_session(product_major_version)
                logger.debug("ctrl session result: %r", ctrl_result)

                logger.debug("Initializing main session (session-id=%s) ...", sid)
                main_result = await main_daemon.init_session(product_major_version, sid, xctest_config)
                logger.debug("main session result: %r", main_result)

                # Launch the test runner process.
                launch_args, launch_env, launch_options = _generate_launch_args(
                    product_major_version, sid, cfg.runner_app_info, xctest_path, env, args
                )
                pid = await process_control_channel.service.launch_suspended_process(
                    "", bundle_id, launch_env, launch_args, launch_options
                )
                logger.debug("Launched test runner pid=%d", pid)

                if product_major_version < 17:
                    await asyncio.sleep(1)

                logger.debug("Authorizing test session for pid=%d ...", pid)
                auth = await ctrl_daemon.authorize_test(product_major_version, pid)
                logger.debug("authorize_test result: %r", auth)

                # Wait for the runner to open the reverse dtxproxy channel.
                logger.debug("Waiting for XCTestDriverInterface from runner ...")

                async with driver_ch:
                    driver_iface = driver_ch.remote_service
                    logger.debug("Starting test plan execution ...")
                    await driver_iface.start_executing_test_plan(XCODE_VERSION)

                    timeout_str = f"{timeout:.1f}s" if timeout is not None else "unlimited time"
                    logger.debug("Waiting for test completion (timeout=%s) ...", timeout_str)

                    # Race test-done event against the runner connection dropping.
                    # When the test runner terminates itself (e.g. because a test
                    # case calls Terminate on the xctrunner process), the DTX TCP
                    # connection is reset before _XCT_didFinishExecutingTestPlan
                    # can be sent.  In that case _disconnected fires first and we
                    # raise ConnectionTerminatedError rather than hanging.
                    done_fut = asyncio.ensure_future(test_done.wait())
                    disc_fut = asyncio.ensure_future(main_test_manager_provider.dtx.wait_disconnected())
                    try:
                        done_set, _ = await asyncio.wait(
                            {done_fut, disc_fut},
                            timeout=timeout,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                    finally:
                        done_fut.cancel()
                        disc_fut.cancel()
                        with suppress(asyncio.CancelledError, Exception):
                            await asyncio.gather(done_fut, disc_fut, return_exceptions=True)

                    if not done_set:
                        raise TimeoutError(f"Test did not finish within {timeout_str}")
                    if not test_done.is_set():
                        raise ConnectionTerminatedError(
                            "Runner DTX connection closed before _XCT_didFinishExecutingTestPlan"
                            " — the test runner likely terminated itself mid-plan"
                        )


@dataclass
class TestConfig:
    runner_app_info: dict

    runner_app_env: Optional[dict] = None
    runner_app_args: Optional[list] = None

    target_app_info: Optional[dict] = None
    target_app_env: Optional[dict] = None
    target_app_args: Optional[list] = None
    tests_to_run: Optional[list] = None
    tests_to_skip: Optional[list] = None

    @staticmethod
    async def create_for(
        service_provider: LockdownServiceProvider, runner_bundle_id: str, target_bundle_id: Optional[str] = None
    ) -> TestConfig:
        """Helper to create a TestConfig with the required runner_app_info and optional target_app_info."""
        runner_app_info: dict
        target_app_info: Optional[dict] = None

        async with InstallationProxyService(lockdown=service_provider) as install_service:
            apps = await install_service.get_apps(
                bundle_identifiers=[runner_bundle_id] + ([target_bundle_id] if target_bundle_id else [])
            )
            if runner_bundle_id not in apps:
                raise AppNotInstalledError(f"No app with bundle id {runner_bundle_id} found")
            runner_app_info = apps[runner_bundle_id]
            if target_bundle_id:
                if target_bundle_id not in apps:
                    raise AppNotInstalledError(f"No app with bundle id {target_bundle_id} found")
                target_app_info = apps[target_bundle_id]

        return TestConfig(runner_app_info=runner_app_info, target_app_info=target_app_info)

    def to_xctestconfiguration(
        self, session_identifier: NSUUID, service_provider: LockdownServiceProvider
    ) -> XCTestConfiguration:
        assert self.runner_app_info, "runner_app_info must be set"

        cfg = {}
        exec_name: str = self.runner_app_info["CFBundleExecutable"]
        assert exec_name.endswith("-Runner"), f"Invalid CFBundleExecutable: {exec_name}"
        config_name = exec_name[: -len("-Runner")]

        cfg["testBundleURL"] = NSURL(None, f"file://{self.runner_app_info['Path']}/PlugIns/{config_name}.xctest")

        cfg["automationFrameworkPath"] = "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework"
        if Version(service_provider.product_version).major >= 17:
            cfg["automationFrameworkPath"] = (
                "/System/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework"
            )

        if self.target_app_info is not None:
            assert self.target_app_info != self.runner_app_info, (
                "target_app_info must be different from runner_app_info"
            )
            cfg["productModuleName"] = config_name
            cfg["targetApplicationBundleID"] = self.target_app_info.get("CFBundleIdentifier")
            cfg["targetApplicationPath"] = self.target_app_info.get("Path")
            cfg["targetApplicationEnvironment"] = self.target_app_env or {}
            cfg["targetApplicationArguments"] = self.target_app_args or []
            assert cfg["targetApplicationPath"], "targetApplicationPath must be set if target_app_info is provided"
            assert cfg["targetApplicationBundleID"], (
                "targetApplicationBundleID must be set if target_app_info is provided"
            )

        return XCTestConfiguration({
            "testBundleURL": NSURL(None, f"file://{self.runner_app_info['Path']}/PlugIns/{config_name}.xctest"),
            "sessionIdentifier": session_identifier,
            "testsToRun": self.tests_to_run or set(),
            "testsToSkip": self.tests_to_skip or set(),
            "testsMustRunOnMainThread": True,
            "reportResultsToIDE": True,
            "reportActivities": True,
            "testApplicationDependencies": None,
            **cfg,
        })


def _generate_launch_args(
    product_major_version: int,
    test_session_identifier: NSUUID,
    app_info: dict,
    xctest_path: str,
    test_runner_env: Optional[dict] = None,
    test_runner_args: Optional[list] = None,
) -> tuple[list, dict, dict]:
    """Return *(app_args, app_env, app_options)* for launching the test runner.

    Extracted from the old ``launch_test_app`` method so that it can be
    shared between :class:`XCUITestService` and lower-level probe tests.
    """
    app_container = app_info["Container"]
    app_path = app_info["Path"]
    exec_name = app_info["CFBundleExecutable"]
    assert exec_name.endswith("-Runner"), f"Invalid CFBundleExecutable: {exec_name}"
    target_name = exec_name[: -len("-Runner")]

    app_env = {
        "CA_ASSERT_MAIN_THREAD_TRANSACTIONS": "0",
        "CA_DEBUG_TRANSACTIONS": "0",
        "DYLD_FRAMEWORK_PATH": app_path + "/Frameworks:",
        "DYLD_LIBRARY_PATH": app_path + "/Frameworks",
        "MTC_CRASH_ON_REPORT": "1",
        "NSUnbufferedIO": "YES",
        "SQLITE_ENABLE_THREAD_ASSERTIONS": "1",
        "WDA_PRODUCT_BUNDLE_IDENTIFIER": "",
        "XCTestBundlePath": f"{app_path}/PlugIns/{target_name}.xctest",
        "XCTestConfigurationFilePath": app_container + xctest_path,
        "XCODE_DBG_XPC_EXCLUSIONS": "com.apple.dt.xctestSymbolicator",
        "XCTestSessionIdentifier": str(test_session_identifier).upper(),
    }

    if product_major_version >= 11:
        app_env["DYLD_INSERT_LIBRARIES"] = "/Developer/usr/lib/libMainThreadChecker.dylib"
        app_env["OS_ACTIVITY_DT_MODE"] = "YES"
    if product_major_version >= 17:
        app_env["DYLD_FRAMEWORK_PATH"] = f"${app_env['DYLD_FRAMEWORK_PATH']}/System/Developer/Library/Frameworks:"
        app_env["DYLD_LIBRARY_PATH"] = f"${app_env['DYLD_LIBRARY_PATH']}:/System/Developer/usr/lib"
        app_env["XCTestConfigurationFilePath"] = ""  # sent as return value of _XCT_testRunnerReadyWithCapabilities
        app_env["XCTestManagerVariant"] = "DDI"

    if test_runner_env:
        app_env.update(test_runner_env)

    app_args = [
        "-NSTreatUnknownArgumentsAsOpen",
        "NO",
        "-ApplePersistenceIgnoreState",
        "YES",
    ]
    app_args.extend(test_runner_args or [])

    app_options: dict = {"StartSuspendedKey": False}
    if product_major_version >= 12:
        app_options["ActivateSuspended"] = True

    return app_args, app_env, app_options
