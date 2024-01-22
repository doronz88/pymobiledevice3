import logging
import time
from typing import Any, Mapping, Optional

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
from pymobiledevice3.services.remote_server import NSURL, NSUUID, Channel, ChannelFragmenter, MessageAux, \
    XCTestConfiguration, dtx_message_header_struct, dtx_message_payload_header_struct

logger = logging.getLogger(__name__)


class XCUITestService:
    IDENTIFIER = "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface"
    XCODE_VERSION = 36  # not important

    def __init__(self, service_provider: LockdownServiceProvider):
        self.service_provider = service_provider
        self.pctl = self.init_process_control()
        self.product_major_version = Version(service_provider.product_version).major

    def run(
        self,
        bundle_id: str,
        test_runner_env: Optional[dict] = None,
        test_runner_args: Optional[list] = None,
    ):
        # Test OK with
        # - iPhone SE (iPhone8,4) 15.8
        #
        # Test Failed with
        # - iPhone 12 Pro (iPhone13,3) 17.2
        #
        # TODO: it seems the protocol changed when iOS>=17
        session_identifier = NSUUID.uuid4()
        app_info = get_app_info(self.service_provider, bundle_id)

        xctest_configuration = generate_xctestconfiguration(
            app_info, session_identifier, bundle_id, test_runner_env, test_runner_args
        )
        xctest_path = f"/tmp/{str(session_identifier).upper()}.xctestconfiguration"  # yapf: disable

        self.setup_xcuitest(bundle_id, xctest_path, xctest_configuration)
        dvt1, chan1, dvt2, chan2 = self.init_ide_channels(session_identifier)

        pid = self.launch_test_app(
            app_info, bundle_id, xctest_path, test_runner_env, test_runner_args
        )
        logger.info("Runner started with pid:%d, waiting for testBundleReady", pid)

        time.sleep(1)
        self.authorize_test_process_id(chan1, pid)
        self.start_executing_test_plan_with_protocol_version(dvt2, self.XCODE_VERSION)

        # TODO: boradcast message is not handled
        # TODO: RemoteServer.receive_message is not thread safe and will block if no message received
        try:
            self.dispatch(dvt2, chan2)
        except KeyboardInterrupt:
            logger.info("Signal Interrupt catched")
        finally:
            logger.info("Killing UITest with pid %d ...", pid)
            self.pctl.kill(pid)
            dvt1.close()
            dvt2.close()

    def dispatch(self, dvt: DvtTestmanagedProxyService, chan: Channel):
        while True:
            self.dispatch_proxy(dvt, chan)

    def dispatch_proxy(self, dvt: DvtTestmanagedProxyService, chan: Channel):
        # Ref code:
        # https://github.com/danielpaulus/go-ios/blob/a49a3582ef4438fee794912c167d2cccf45d8efa/ios/testmanagerd/xcuitestrunner.go#L182
        # https://github.com/alibaba/tidevice/blob/main/tidevice/_device.py#L1117

        key, value = dvt.recv_plist(chan)
        value = value and value[0].value.strip()
        if key == "_XCT_logDebugMessage:":
            logger.debug("logDebugMessage: %s", value)
        elif key == "_XCT_testRunnerReadyWithCapabilities:":
            logger.info("testRunnerReadyWithCapabilities: %s", value)
            self.send_response_capabilities(dvt, chan, dvt.cur_message)
        else:
            # There are still unhandled messages
            # - _XCT_testBundleReadyWithProtocolVersion:minimumVersion:
            # - _XCT_didFinishExecutingTestPlan
            logger.info("unhandled %s %r", key, value)

    def send_response_capabilities(
        self, dvt: DvtTestmanagedProxyService, chan: Channel, cur_message: int
    ):
        pheader = dtx_message_payload_header_struct.build(
            dict(flags=3, auxiliaryLength=0, totalLength=0)
        )
        mheader = dtx_message_header_struct.build(
            dict(
                cb=dtx_message_header_struct.sizeof(),
                fragmentId=0,
                fragmentCount=1,
                length=dtx_message_payload_header_struct.sizeof(),
                identifier=cur_message,
                conversationIndex=1,
                channelCode=chan,
                expectsReply=int(0),
            )
        )
        msg = mheader + pheader
        dvt.service.sendall(msg)

    def init_process_control(self):
        dvt_proxy = DvtSecureSocketProxyService(lockdown=self.service_provider)
        dvt_proxy.perform_handshake()
        return ProcessControl(dvt_proxy)

    def init_ide_channels(self, session_identifier: NSUUID):
        # XcodeIDE require two connections
        dvt1 = DvtTestmanagedProxyService(lockdown=self.service_provider)
        dvt1.perform_handshake()

        logger.info("make channel %s", self.IDENTIFIER)
        chan1 = dvt1.make_channel(self.IDENTIFIER)
        if self.product_major_version >= 11:
            dvt1.send_message(
                chan1,
                "_IDE_initiateControlSessionWithProtocolVersion:",
                MessageAux().append_obj(self.XCODE_VERSION),
            )
            reply = chan1.receive_plist()
            logger.info("conn1 handshake xcode version: %s", reply)

        dvt2 = DvtTestmanagedProxyService(lockdown=self.service_provider)
        dvt2.perform_handshake()
        chan2 = dvt2.make_channel(self.IDENTIFIER)
        dvt2.send_message(
            channel=chan2,
            selector="_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:",
            args=MessageAux()
            .append_obj(session_identifier)
            .append_obj("not-very-import-part")  # this part is not important
            .append_obj("/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild")
            .append_obj(self.XCODE_VERSION),
        )
        reply = chan2.receive_plist()
        logger.info("conn2 handshake xcode version: %s", reply)
        return dvt1, chan1, dvt2, chan2

    def setup_xcuitest(
        self,
        bundle_id: str,
        xctest_path: str,
        xctest_configuration: XCTestConfiguration,
    ):
        """push xctestconfiguration to app VendDocuments"""
        with HouseArrestService(
            lockdown=self.service_provider, bundle_id=bundle_id, documents_only=False
        ) as afc:
            for name in afc.listdir("/tmp"):
                if name.endswith(".xctestconfiguration"):
                    logger.debug("remove /tmp/%s", name)
                    afc.rm("/tmp/" + name)
            afc.set_file_contents(xctest_path, archiver.archive(xctest_configuration))

    def start_executing_test_plan_with_protocol_version(self, dvt: DvtTestmanagedProxyService, protocol_version: int):
        ide_channel = Channel.create(-1, dvt)
        dvt.channel_messages[ide_channel] = ChannelFragmenter()
        dvt.send_message(
            ide_channel,
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
            raise RuntimeError("Failed to authorize test process id: %s" % reply)

    def launch_test_app(
        self,
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
        assert exec_name.endswith("-Runner"), (
            "Invalid CFBundleExecutable: %s" % exec_name
        )
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
            "XCTestBundlePath": f'{app_info["Path"]}/PlugIns/{target_name}.xctest',
            "XCTestConfigurationFilePath": app_container + xctest_path,
            "XCODE_DBG_XPC_EXCLUSIONS": "com.apple.dt.xctestSymbolicator",
            # the following maybe no needed
            # 'MJPEG_SERVER_PORT': '',
            # 'USE_PORT': '',
            # 'LLVM_PROFILE_FILE': app_container + '/tmp/%p.profraw', # %p means pid
        }
        if test_runner_env:
            app_env.update(test_runner_env)

        if self.product_major_version >= 11:
            app_env[
                "DYLD_INSERT_LIBRARIES"
            ] = "/Developer/usr/lib/libMainThreadChecker.dylib"
            app_env["OS_ACTIVITY_DT_MODE"] = "YES"

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

        pid = self.pctl.launch(
            bundle_id,
            arguments=app_args,
            environment=app_env,
            extra_options=app_options,
        )
        for message in self.pctl:
            logger.info("ProcessOutput: %s", message)
        return pid


def get_app_info(service_provider: LockdownClient, bundle_id: str) -> Mapping[str, Any]:
    with InstallationProxyService(lockdown=service_provider) as install_service:
        apps = install_service.get_apps(bundle_identifiers=[bundle_id])
        if not apps:
            raise AppNotInstalledError(f"No app with bundle id {bundle_id} found")
        return apps[bundle_id]


def generate_xctestconfiguration(
    app_info: dict,
    session_identifier: NSUUID,
    target_app_bundle_id: str = None,
    target_app_env: Optional[dict] = None,
    target_app_args: Optional[list] = None,
    tests_to_run: Optional[list] = None,
) -> XCTestConfiguration:
    exec_name: str = app_info["CFBundleExecutable"]
    assert exec_name.endswith("-Runner"), "Invalid CFBundleExecutable: %s" % exec_name
    config_name = exec_name[: -len("-Runner")]

    return XCTestConfiguration(
        {
            "testBundleURL": NSURL(
                None, f'file://{app_info["Path"]}/PlugIns/{config_name}.xctest'
            ),
            "sessionIdentifier": session_identifier,
            "targetApplicationBundleID": target_app_bundle_id,
            "targetApplicationEnvironment": target_app_env or {},
            "targetApplicationArguments": target_app_args or [],
            "testsToRun": tests_to_run or set(),
            "testsMustRunOnMainThread": True,
            "reportResultsToIDE": True,
            "reportActivities": True,
            "automationFrameworkPath": "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework",
        }
    )
