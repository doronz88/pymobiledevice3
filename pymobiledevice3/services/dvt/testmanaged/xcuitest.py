import logging
import time
from typing import Optional

from bpylist2 import archiver
from packaging.version import Version

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.dvt_testmanaged_proxy import DvtTestmanagedProxyService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.remote_server import (
    NSURL, NSUUID, Channel, ChannelFragmenter, MessageAux, XCTestConfiguration,
    dtx_message_header_struct, dtx_message_payload_header_struct)

logger = logging.getLogger(__name__)


class XCUITestService:
    IDENTIFIER = 'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface'
    XCODE_VERSION = 36 # not important

    def __init__(self,
                 service_provider: LockdownServiceProvider,
                 afc: AfcService,
                 app_info: dict):
        self.service_provider = service_provider
        self.afc = afc
        self.pctl = self.init_process_control()
        self.app_info = app_info
        self.product_major_version = Version(service_provider.product_version).major

    def run(self, 
            bundle_id: str,            
            test_runner_env: Optional[dict] = None, 
            test_runner_args: Optional[list] = None):
        # Test OK with
        # - iPhone SE (iPhone8,4) 15.8
        #
        # Test Failed with
        # - iPhone 12 Pro (iPhone13,3) 17.2
        #
        # TODO: it seems the protocol changed when iOS>=17
        session_identifier = NSUUID.uuid4()
        app_info = self.app_info.copy()

        xctest_configuration = self.generate_xctestconfiguration(app_info, session_identifier, bundle_id, test_runner_env, test_runner_args)
        xctest_path = f"/tmp/{str(session_identifier).upper()}.xctestconfiguration" # yapf: disable
        
        self.setup_xcuitest(app_info, xctest_path, xctest_configuration)
        self.init_ide_channels(session_identifier)
    
        pid = self.launch_test_app(app_info, bundle_id, xctest_path, test_runner_env, test_runner_args)
        logger.info("Runner started with pid:%d, waiting for testBundleReady", pid)

        time.sleep(1)
        self.authorize_test_process_id(self._chan1, pid)
        self.start_executing_test_plan_with_protocol_version(self._dvt2, self.XCODE_VERSION)

        # TODO: boradcast message is not handled
        # TODO: RemoteServer.receive_message is not thread safe and will block if no message received
        try:
            self.dispatch()
        except KeyboardInterrupt:
            logger.info("Signal Interrupt catched")
        finally:
            logger.info("Killing UITest with pid %d ...", pid)
            self.pctl.kill(pid)
            self.close()

    def dispatch(self):
        while True:
            self.dispatch_proxy()
        
    def dispatch_proxy(self):
        # Ref code:
        # https://github.com/danielpaulus/go-ios/blob/a49a3582ef4438fee794912c167d2cccf45d8efa/ios/testmanagerd/xcuitestrunner.go#L182
        # https://github.com/alibaba/tidevice/blob/main/tidevice/_device.py#L1117

        key, value = self._dvt2.recv_plist(self._chan2)
        value = value and value[0].value.strip()
        if key == "_XCT_logDebugMessage:":
            logger.debug("logDebugMessage: %s", value)
        elif key == "_XCT_testRunnerReadyWithCapabilities:":
            logger.info("testRunnerReadyWithCapabilities: %s", value)
            self.send_response_capabilities(self._dvt2, self._dvt2.cur_message)
        else:
            # There are still unhandled messages
            # - _XCT_testBundleReadyWithProtocolVersion:minimumVersion:
            # - _XCT_didFinishExecutingTestPlan
            logger.info("unhandled %s %r", key, value)

    def send_response_capabilities(self, dvt: DvtTestmanagedProxyService, cur_message: int):
        pheader = dtx_message_payload_header_struct.build(dict(flags=3, auxiliaryLength=0, totalLength=0))
        mheader = dtx_message_header_struct.build(dict(
            cb=dtx_message_header_struct.sizeof(),
            fragmentId=0,
            fragmentCount=1,
            length=dtx_message_payload_header_struct.sizeof(),
            identifier=cur_message,
            conversationIndex=1,
            channelCode=self._chan2,
            expectsReply=int(0)
        ))
        msg = mheader + pheader
        dvt.service.sendall(msg)

    def init_process_control(self):
        self._dvt3 = DvtSecureSocketProxyService(lockdown=self.service_provider)
        self._dvt3.perform_handshake()
        return ProcessControl(self._dvt3)
    
    def init_ide_channels(self, session_identifier: NSUUID):
        # XcodeIDE require two connections
        self._dvt1 = DvtTestmanagedProxyService(lockdown=self.service_provider)
        self._dvt1.perform_handshake()

        logger.info("make channel %s", self.IDENTIFIER)
        self._chan1 = self._dvt1.make_channel(self.IDENTIFIER)
        if self.product_major_version >= 11:
            self._dvt1.send_message(
                self._chan1,
                "_IDE_initiateControlSessionWithProtocolVersion:",
                MessageAux().append_obj(self.XCODE_VERSION))
            reply = self._chan1.receive_plist()
            logger.info("conn1 handshake xcode version: %s", reply)
        
        self._dvt2 = DvtTestmanagedProxyService(lockdown=self.service_provider)
        self._dvt2.perform_handshake()
        self._chan2 = self._dvt2.make_channel(self.IDENTIFIER)
        self._dvt2.send_message(
            channel=self._chan2,
            selector='_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:',
            args=MessageAux()
                .append_obj(session_identifier)
                .append_obj(str(session_identifier) + '-6722-000247F15966B083') # this part is not important
                .append_obj('/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild')
                .append_obj(self.XCODE_VERSION)
        )
        reply = self._chan2.receive_plist()
        logger.info("conn2 handshake xcode version: %s", reply)

    def setup_xcuitest(self, session_identifier: NSUUID, xctest_path: str, xctest_configuration: XCTestConfiguration) -> NSUUID:
        """ push xctestconfiguration to app VendDocuments """
        for name in self.afc.listdir("/tmp"):
            if name.endswith(".xctestconfiguration"):
                logger.debug("remove /tmp/%s", name)
                self.afc.rm("/tmp/" + name)
        self.afc.set_file_contents(xctest_path, archiver.archive(xctest_configuration))
        return session_identifier
    
    def start_executing_test_plan_with_protocol_version(self, dvt: DvtTestmanagedProxyService, protocol_version: int):
        ide_channel = Channel.create(-1, dvt)
        dvt.channel_messages[ide_channel] = ChannelFragmenter()
        dvt.send_message(ide_channel, 
                         "_IDE_startExecutingTestPlanWithProtocolVersion:",
                         MessageAux().append_obj(protocol_version),
                         expects_reply=False)

    def authorize_test_process_id(self, chan: Channel, pid: int):
        selector = None
        aux = MessageAux()
        if self.product_major_version >= 12:
            selector = '_IDE_authorizeTestSessionWithProcessID:'
            aux.append_obj(pid)
        elif self.product_major_version >= 10:
            selector = '_IDE_initiateControlSessionForTestProcessID:protocolVersion:'
            aux.append_obj(pid)
            aux.append_obj(self.XCODE_VERSION)
        else:
            selector = '_IDE_initiateControlSessionForTestProcessID:'
            aux.append_obj(pid)
        chan.send_message(selector, aux)
        reply = chan.receive_plist()
        if not isinstance(reply, bool) or reply != True:
            raise RuntimeError("Failed to authorize test process id: %s" % reply)
        logger.info("authorizing test session for pid %d successful %r", pid, reply)
    
    def launch_test_app(self,
                        app_info: dict,
                        bundle_id: str,
                        xctest_path: str,
                        test_runner_env: Optional[dict] = None,
                        test_runner_args: Optional[list] = None) -> int:
        app_container = app_info['Container']
        app_path = app_info['Path']
        exec_name = app_info['CFBundleExecutable']
        # # logger.info("CFBundleExecutable: %s", exec_name)
        # # CFBundleName always endswith -Runner
        assert exec_name.endswith("-Runner"), "Invalid CFBundleExecutable: %s" % exec_name
        target_name = exec_name[:-len("-Runner")]

        app_env = {
            'CA_ASSERT_MAIN_THREAD_TRANSACTIONS': '0',
            'CA_DEBUG_TRANSACTIONS': '0',
            'DYLD_FRAMEWORK_PATH': app_path + '/Frameworks:',
            'DYLD_LIBRARY_PATH': app_path + '/Frameworks',
            'MTC_CRASH_ON_REPORT': '1',
            'NSUnbufferedIO': 'YES',
            'SQLITE_ENABLE_THREAD_ASSERTIONS': '1',
            'WDA_PRODUCT_BUNDLE_IDENTIFIER': '',
            'XCTestBundlePath': f"{app_info['Path']}/PlugIns/{target_name}.xctest",
            'XCTestConfigurationFilePath': app_container + xctest_path,
            'XCODE_DBG_XPC_EXCLUSIONS': 'com.apple.dt.xctestSymbolicator',
            'MJPEG_SERVER_PORT': '',
            'USE_PORT': '',
            # maybe no needed
            'LLVM_PROFILE_FILE': app_container + "/tmp/%p.profraw", # %p means pid
        }
        if test_runner_env:
            app_env.update(test_runner_env)
        
        if  self.product_major_version >= 11:
            app_env['DYLD_INSERT_LIBRARIES'] = '/Developer/usr/lib/libMainThreadChecker.dylib'
            app_env['OS_ACTIVITY_DT_MODE'] = 'YES'
        
        app_args = [
            '-NSTreatUnknownArgumentsAsOpen', 'NO',
            '-ApplePersistenceIgnoreState', 'YES'
        ]
        app_args.extend(test_runner_args or [])
        app_options = {'StartSuspendedKey': False}
        if self.product_major_version >= 12:
            app_options['ActivateSuspended'] = True

        pid = self.pctl.launch(bundle_id, arguments=app_args, environment=app_env, extra_options=app_options)
        for message in self.pctl:
            logger.info("ProcessOutput: %s", message)
        return pid
 
    def close(self):
        self._dvt1.close()
        self._dvt2.close()
        self._dvt3.close()
    
    def generate_xctestconfiguration(self,
                                     app_info: dict,
                                     session_identifier: NSUUID, 
                                     target_app_bundle_id: str = None, 
                                     target_app_env: Optional[dict] = None,
                                     target_app_args: Optional[list] = None,
                                     tests_to_run: Optional[list] = None) -> XCTestConfiguration:
        exec_name: str = app_info['CFBundleExecutable']
        assert exec_name.endswith("-Runner"), "Invalid CFBundleExecutable: %s" % exec_name
        config_name = exec_name[:-len("-Runner")]

        return XCTestConfiguration({
            "testBundleURL": NSURL(None, f"file://{app_info['Path']}/PlugIns/{config_name}.xctest"),
            "sessionIdentifier": session_identifier,
            "targetApplicationBundleID": target_app_bundle_id,
            "targetApplicationEnvironment": target_app_env or {},
            "targetApplicationArguments": target_app_args or [],
            "testsToRun": tests_to_run or set(),
            "testsMustRunOnMainThread": True,
            "reportResultsToIDE": True,
            "reportActivities": True,
            "automationFrameworkPath": "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework",
        })