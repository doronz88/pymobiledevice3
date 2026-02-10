import logging
import threading
import time
from typing import Any, Optional

from bpylist2 import archiver
from packaging.version import Version

from pymobiledevice3.exceptions import AppNotInstalledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.dvt_testmanaged_proxy import DvtTestmanagedProxyService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.remote_server import (
    NSURL,
    NSUUID,
    Channel,
    MessageAux,
    RemoteServer,
    XCTCapabilities,
    XCTestConfiguration,
)

logger = logging.getLogger(__name__)


class ReverseRemoteService:
    def __init__(self, service: RemoteServer, channel: int):
        self.service = service
        self.channel = channel
        self.logger = logger.getChild(self.__class__.__name__)

    def __on_method_call__(self, selector: str, args: Optional[MessageAux] = None):
        _selector = selector.replace(":", "_")
        if not hasattr(self, _selector):
            logger.debug(
                "%s: unhandled method call: selector='%s', _selector='%s', args='%s'",
                self.__class__.__name__,
                selector,
                _selector,
                args,
            )
            self.service.send_reply_error(self.channel, self.service.cur_remote_message)
            return
        ret = getattr(self, _selector)(args)
        self.service.send_reply(self.channel, self.service.cur_remote_message, ret)


class XCUITestListener(ReverseRemoteService):
    """dtxproxy:XCTestDriverInterface:XCTestManager_IDEInterface"""

    def __init__(self, service: DvtTestmanagedProxyService, channel: int, test_configuration: XCTestConfiguration):
        super().__init__(service, channel)
        self.test_config = test_configuration

    def __on_method_call__(self, selector: str, args: Optional[MessageAux] = None):
        return super().__on_method_call__(selector.removeprefix("_XCT_"), args)

    def logDebugMessage_(self, args: Optional[MessageAux] = None):
        self.logger.debug("logDebugMessage: %s", args[0].value.strip())

    def testRunnerReadyWithCapabilities_(self, args: Optional[MessageAux] = None):
        self.logger.info("testRunnerReadyWithCapabilities: %s", args[0].value)
        return self.test_config

    def didFinishExecutingTestPlan(self, args: Optional[MessageAux] = None):
        self.logger.info("didFinishExecutingTestPlan")


class XCUITestPlanConsumer:
    def __init__(
        self,
        pid: int,
        pctrl: ProcessControl,
        ctrl_dvt: DvtTestmanagedProxyService,
        ctrl_chan: Channel,
        main_dvt: DvtTestmanagedProxyService,
        main_chan: Channel,
        test_configuration: XCTestConfiguration,
    ):
        self.pid = pid
        self.pctrl = pctrl
        self.ctrl_dvt = ctrl_dvt
        self.ctrl_chan = ctrl_chan
        self.main_dvt = main_dvt
        self.main_chan = main_chan
        self.xctest_config = test_configuration
        self.listener: Optional[XCUITestListener] = None
        self.__running__ = False
        self.__closing__ = False
        self.completed = threading.Event()

    def set_listener(self, listener: XCUITestListener):
        self.listener = listener

    def consume(self):
        if self.listener is None:
            self.listener = XCUITestListener(self.main_dvt, self.main_chan, self.xctest_config)
        try:
            self.__running__ = True
            while self.__running__:
                key, value = self.main_dvt.recv_plist(self.main_chan)
                if key == "_XCT_didFinishExecutingTestPlan":
                    self.__closing__ = True
                self.listener.__on_method_call__(key, value)
        except (ConnectionAbortedError, ConnectionResetError):
            if not self.__closing__:
                logger.warning("connection aborted")
            return
        except (InterruptedError, KeyboardInterrupt):
            return
        finally:
            self.stop()
            self.completed.set()

    def stop(self):
        if not self.__running__:
            return

        self.__closing__ = True
        self.__running__ = False

        logger.info("Killing UITest with pid %d ...", self.pid)
        self.pctrl.kill(self.pid)
        self.main_dvt.close()
        self.ctrl_dvt.close()


class XCUITestService:
    IDENTIFIER = "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface"
    XCODE_VERSION = 36  # not important
    __TESTDRIVERINTERFACE_CHANNEL__ = -1  # a special channel that is reserved for "XCTestDriverInterface"

    def __init__(self, service_provider: LockdownServiceProvider):
        self.service_provider = service_provider
        self.pctl = self.init_process_control()
        self.product_major_version = Version(service_provider.product_version).major

    def start(
        self,
        bundle_id: str,
        test_runner_env: Optional[dict] = None,
        test_runner_args: Optional[list] = None,
    ) -> XCUITestPlanConsumer:
        session_identifier = NSUUID.uuid4()
        app_info = get_app_info(self.service_provider, bundle_id)

        xctest_configuration = generate_xctestconfiguration(
            app_info, session_identifier, self.product_major_version, test_runner_env, test_runner_args
        )
        xctest_path = f"/tmp/{str(session_identifier).upper()}.xctestconfiguration"  # yapf: disable

        if self.product_major_version < 17:
            self.setup_xcuitest(bundle_id, xctest_path, xctest_configuration)

        ctrl_dvt, ctrl_chan, main_dvt, main_chan = self.init_ide_channels(
            session_identifier, xctest_configuration._config["IDECapabilities"]
        )

        pid = self.launch_test_app(
            session_identifier, app_info, bundle_id, xctest_path, test_runner_env, test_runner_args
        )
        logger.info("Runner started with pid:%d, waiting for testBundleReady", pid)

        if self.product_major_version < 17:
            time.sleep(1)

        self.authorize_test_process_id(ctrl_chan, pid)
        # acknoledge that we will have this service listening on our channel
        main_dvt.serve_channel("dtxproxy:XCTestDriverInterface:XCTestManager_IDEInterface", main_chan)
        self.start_executing_test_plan_with_protocol_version(main_dvt, self.XCODE_VERSION)

        # TODO: boradcast message is not handled
        # TODO: RemoteServer.receive_message is not thread safe and will block if no message received
        return XCUITestPlanConsumer(pid, self.pctl, ctrl_dvt, ctrl_chan, main_dvt, main_chan, xctest_configuration)

    def run(
        self,
        bundle_id: str,
        test_runner_env: Optional[dict] = None,
        test_runner_args: Optional[list] = None,
    ):
        consumer = self.start(bundle_id, test_runner_env, test_runner_args)
        consumer.consume()

    def init_process_control(self):
        dvt_proxy = DvtSecureSocketProxyService(lockdown=self.service_provider)
        dvt_proxy.perform_handshake()
        return ProcessControl(dvt_proxy)

    def init_ide_channels(self, session_identifier: NSUUID, ide_capabilities: XCTCapabilities):
        """
        Initialize the two channels required by XcodeIDE to control the test session. The first channel is used to authorize the test process, and the second channel is used to manage the test.

        return: (ctrl_dvt, ctrl_chan, main_dvt, main_chan)
         - ctrl_dvt: the DvtTestmanagedProxyService instance for the control channel
         - ctrl_chan: the Channel instance for the control channel
         - main_dvt: the DvtTestmanagedProxyService instance for the main channel
         - main_chan: the Channel instance for the main channel
        """
        # XcodeIDE require two connections
        ctrl_dvt = DvtTestmanagedProxyService(lockdown=self.service_provider)
        ctrl_dvt.perform_handshake()

        logger.info("make channel %s", self.IDENTIFIER)
        ctrl_chan = ctrl_dvt.make_channel(self.IDENTIFIER)
        if self.product_major_version >= 17:
            ctrl_dvt.send_message(
                ctrl_chan,
                "_IDE_initiateControlSessionWithCapabilities:",
                MessageAux().append_obj(XCTCapabilities({})),
            )
            reply = ctrl_chan.receive_plist()
            logger.info("ctrl_conn handshake capabilities: %s", reply)
        elif self.product_major_version >= 11:
            ctrl_dvt.send_message(
                ctrl_chan,
                "_IDE_initiateControlSessionWithProtocolVersion:",
                MessageAux().append_obj(self.XCODE_VERSION),
            )
            reply = ctrl_chan.receive_plist()
            logger.info("ctrl_conn handshake xcode version: %s", reply)

        main_dvt = DvtTestmanagedProxyService(lockdown=self.service_provider)
        main_dvt.perform_handshake()
        main_chan = main_dvt.make_channel(self.IDENTIFIER)
        if self.product_major_version >= 17:
            main_dvt.send_message(
                channel=main_chan,
                selector="_IDE_initiateSessionWithIdentifier:capabilities:",
                args=MessageAux().append_obj(session_identifier).append_obj(ide_capabilities),
            )
            reply = main_chan.receive_plist()
            logger.info("main_conn handshake capabilities: %s", reply)
        else:
            main_dvt.send_message(
                channel=main_chan,
                selector="_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:",
                args=MessageAux()
                .append_obj(session_identifier)
                .append_obj("not-very-import-part")  # this part is not important
                .append_obj("/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild")
                .append_obj(self.XCODE_VERSION),
            )
            reply = main_chan.receive_plist()
            logger.info("main_conn handshake xcode version: %s", reply)
        return ctrl_dvt, ctrl_chan, main_dvt, main_chan

    def setup_xcuitest(
        self,
        bundle_id: str,
        xctest_path: str,
        xctest_configuration: XCTestConfiguration,
    ):
        """push xctestconfiguration to app VendDocuments"""
        with HouseArrestService(lockdown=self.service_provider, bundle_id=bundle_id, documents_only=False) as afc:
            for name in afc.listdir("/tmp"):
                if name.endswith(".xctestconfiguration"):
                    logger.debug("remove /tmp/%s", name)
                    afc.rm("/tmp/" + name)
            afc.set_file_contents(xctest_path, archiver.archive(xctest_configuration))

    def start_executing_test_plan_with_protocol_version(self, dvt: DvtTestmanagedProxyService, protocol_version: int):
        dvt.send_message(
            self.__TESTDRIVERINTERFACE_CHANNEL__,
            "_IDE_startExecutingTestPlanWithProtocolVersion:",
            MessageAux().append_obj(protocol_version),
            expects_reply=False,
        )

    def authorize_test_process_id(self, chan: Channel, pid: int):
        selector = None
        aux = MessageAux()
        if self.product_major_version >= 12:
            selector = "_IDE_authorizeTestSessionWithProcessID:"
            aux.append_obj(pid)
        elif self.product_major_version >= 10:
            selector = "_IDE_initiateControlSessionForTestProcessID:protocolVersion:"
            aux.append_obj(pid)
            aux.append_obj(self.XCODE_VERSION)
        else:
            selector = "_IDE_initiateControlSessionForTestProcessID:"
            aux.append_obj(pid)
        chan.send_message(selector, aux)
        reply = chan.receive_plist()
        if isinstance(reply, bool) and reply is True:
            logger.info("authorizing test session for pid %d successful %r", pid, reply)
        else:
            raise RuntimeError(f"Failed to authorize test process id: {reply}")

    def launch_test_app(
        self,
        test_session_identifier: NSUUID,
        app_info: dict,
        bundle_id: str,
        xctest_path: str,
        test_runner_env: Optional[dict] = None,
        test_runner_args: Optional[list] = None,
    ) -> int:
        app_container = app_info["Container"]
        app_path = app_info["Path"]
        exec_name = app_info["CFBundleExecutable"]
        # # logger.info('CFBundleExecutable: %s', exec_name)
        # # CFBundleName always endswith -Runner
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
            "XCTestBundlePath": f"{app_info['Path']}/PlugIns/{target_name}.xctest",
            "XCTestConfigurationFilePath": app_container + xctest_path,
            "XCODE_DBG_XPC_EXCLUSIONS": "com.apple.dt.xctestSymbolicator",
            # the following maybe no needed
            # 'MJPEG_SERVER_PORT': '',
            # 'USE_PORT': '',
            # 'LLVM_PROFILE_FILE': app_container + '/tmp/%p.profraw', # %p means pid
            "XCTestSessionIdentifier": str(test_session_identifier).upper(),
        }

        if self.product_major_version >= 11:
            app_env["DYLD_INSERT_LIBRARIES"] = "/Developer/usr/lib/libMainThreadChecker.dylib"
            app_env["OS_ACTIVITY_DT_MODE"] = "YES"
        if self.product_major_version >= 17:
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
        app_options = {"StartSuspendedKey": False}
        if self.product_major_version >= 12:
            app_options["ActivateSuspended"] = True

        # go-ios uses the following to spawn a new process for the test runner.
        # async def launch_app_async():
        #     async with AppServiceService(self.service_provider) as app_service:
        #         resp = await app_service.launch_application(bundle_id, arguments=app_args, environment=app_env, extra_options=app_options, kill_existing=True)
        #         return int(resp["processToken"]["processIdentifier"])
        # pid = asyncio.run(launch_app_async())
        return self.pctl.launch(
            bundle_id,
            arguments=app_args,
            environment=app_env,
            extra_options=app_options,
        )


def get_app_info(service_provider: LockdownClient, bundle_id: str) -> dict[str, Any]:
    with InstallationProxyService(lockdown=service_provider) as install_service:
        apps = install_service.get_apps(bundle_identifiers=[bundle_id])
        if not apps:
            raise AppNotInstalledError(f"No app with bundle id {bundle_id} found")
        return apps[bundle_id]


def generate_xctestconfiguration(
    target_app_info: dict,
    session_identifier: NSUUID,
    product_major_version: int,
    target_app_env: Optional[dict] = None,
    target_app_args: Optional[list] = None,
    tests_to_run: Optional[list] = None,
    tests_to_skip: Optional[list] = None,
) -> XCTestConfiguration:
    exec_name: str = target_app_info["CFBundleExecutable"]
    assert exec_name.endswith("-Runner"), f"Invalid CFBundleExecutable: {exec_name}"
    config_name = exec_name[: -len("-Runner")]

    automation_framework_path = "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework"
    if product_major_version >= 17:
        automation_framework_path = "/System/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework"

    return XCTestConfiguration({
        "testBundleURL": NSURL(None, f"file://{target_app_info['Path']}/PlugIns/{config_name}.xctest"),
        "sessionIdentifier": session_identifier,
        "productModuleName": config_name,
        "targetApplicationBundleID": target_app_info.get("CFBundleIdentifier"),
        "targetApplicationPath": target_app_info.get("Path"),
        "targetApplicationEnvironment": target_app_env or {},
        "targetApplicationArguments": target_app_args or [],
        "testsToRun": tests_to_run or set(),
        "testsToSkip": tests_to_skip or set(),
        "testsMustRunOnMainThread": True,
        "reportResultsToIDE": True,
        "reportActivities": True,
        "automationFrameworkPath": automation_framework_path,
        "testApplicationDependencies": None,
    })
