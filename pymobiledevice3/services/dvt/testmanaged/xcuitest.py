import logging
from typing import Optional

from bpylist2 import archiver
from packaging.version import Version

from pymobiledevice3.services.dvt.dvt_testmanaged_proxy import \
    DvtTestmanagedProxyService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.remote_server import NSURL, NSUUID, Channel, XCTestConfiguration, MessageAux
from pymobiledevice3.services.afc import AfcService


logger = logging.getLogger(__name__)


class XCUITestService:
    IDENTIFIER = 'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface'
    XCODE_VERSION = 29

    def __init__(self,
                 dvt: DvtTestmanagedProxyService, 
                 afc: AfcService, 
                 process_control: ProcessControl):
        self._dvt = dvt
        self._afc = afc
        self._pctl = process_control

    def run(self, 
            bundle_id: str,            
            test_runner_env: Optional[dict] = None, 
            test_runner_args: Optional[list] = None):
        
        session_identifier = NSUUID.uuid4()
        self.init_channels(session_identifier)
        # todo: lookup app_info
        app_info = {}
        xctest_configuration = self.generate_xctestconfiguration(app_info, session_identifier, bundle_id, test_runner_env, test_runner_args)
        pid = self.launch_test_app(app_info, bundle_id, session_identifier, xctest_configuration, test_runner_env, test_runner_args)
        self.authorize_test_process_id(pid)
        self.stream_process_messages()
    
    def init_channels(self, session_identifier: NSUUID):
        dvt = self._dvt
        logger.info("make channel %s", self.IDENTIFIER)
        self._chan1 = dvt.make_channel(self.IDENTIFIER)
        self._chan2 = dvt.make_channel(self.IDENTIFIER)
        self.device_major_version = Version(dvt.lockdown.product_version).major

        if self.device_major_version >= 11:
            self._dvt.send_message(
                self._chan1,
                "_IDE_initiateControlSessionWithProtocolVersion:",
                MessageAux().append_obj(self.XCODE_VERSION))
            result = self._chan1.receive_key_value()
            logger.info("chan1 first call result: %s", result)
        
        self._dvt.send_message(
            channel=self._chan2,
            selector='_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:',
            args=MessageAux()
                .append_obj(session_identifier)
                .append_obj(str(session_identifier) + '-6722-000247F15966B083') # Random suffix
                .append_obj('/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild')
                .append_obj(self.XCODE_VERSION),
            expects_reply=True
        )
        result = self._chan2.receive_key_value()
        logger.info("chan2 first call result(guess xcode version): %s", result) # TODO: check result

    def authorize_test_process_id(self, pid: int):
        selector = None
        aux = MessageAux()
        if self.device_major_version >= 12:
            selector = '_IDE_authorizeTestSessionWithProcessID:'
            aux.append_obj(pid)
        elif self.device_major_version >= 10:
            selector = '_IDE_initiateControlSessionForTestProcessID:protocolVersion:'
            aux.append_obj(pid)
            aux.append_obj(self.XCODE_VERSION)
        else:
            selector = '_IDE_initiateControlSessionForTestProcessID:'
            aux.append_obj(pid)
        result = self._chan1.send_message(selector, aux)
        logger.info("authorize_test_process_id result: %s", result)
    
    def launch_test_app(self,
                        app_info: dict,
                        bundle_id: str,
                        session_identifier: NSUUID,
                        xctest_configuration: XCTestConfiguration,
                        test_runner_env: Optional[dict] = None,
                        test_runner_args: Optional[list] = None):
        sign_identity = app_info.get("SignerIdentity", "")
        logger.info("SignIdentity: %r", sign_identity)

        app_container = app_info['Container']
        app_path = app_info['Path']
        exec_name = app_info['CFBundleExecutable']
        logger.info("CFBundleExecutable: %s", exec_name)
        # CFBundleName always endswith -Runner
        assert exec_name.endswith("-Runner"), "Invalid CFBundleExecutable: %s" % exec_name
        target_name = exec_name[:-len("-Runner")]

        xctest_path = f"/tmp/{target_name}-{str(session_identifier).upper()}.xctestconfiguration"  # yapf: disable
        xctest_content = archiver.archive(xctest_configuration)

        # TODO
        # fsync = self.app_sync(bundle_id, command="VendContainer")
        # for fname in fsync.listdir("/tmp"):
        #     if fname.endswith(".xctestconfiguration"):
        #         logger.debug("remove /tmp/%s", fname)
        #         fsync.remove("/tmp/" + fname)
        # fsync.push_content(xctest_path, xctest_content)

        archiver.archive(xctest_configuration)
        remote_path = f"/tmp/todo-{str(session_identifier).upper()}.xctestconfiguration"
        self._afc.set_file_contents(remote_path, archiver.archive(xctest_configuration))

        # push XCTestConfiguration to device
        # launch app with specified environment variables
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
        
        device_major_version = Version(self._dvt.lockdown.product_version).major
        if  device_major_version >= 11:
            app_env['DYLD_INSERT_LIBRARIES'] = '/Developer/usr/lib/libMainThreadChecker.dylib'
            app_env['OS_ACTIVITY_DT_MODE'] = 'YES'
        
        app_args = [
            '-NSTreatUnknownArgumentsAsOpen', 'NO',
            '-ApplePersistenceIgnoreState', 'YES'
        ]
        app_args.extend(test_runner_args or [])
        # app_options = {'StartSuspendedKey': False}
        # if device_major_version >= 12:
        #     app_options['ActivateSuspended'] = True
        pid = self._pctl.launch(bundle_id, arguments=app_args, environment=app_env)
        # TODO startObservingPid: for pid
        self._pctl._channel.startObservingPid_(MessageAux().append_obj(pid))
 
    def stream_process_messages(self):
        # output logMessage
        ...
    
    def generate_xctestconfiguration(self,
                                     app_info: dict,
                                     session_identifier: NSUUID, 
                                     target_app_bundle_id: str = None, 
                                     target_app_env: Optional[dict] = None,
                                     target_app_args: Optional[list] = None,
                                     tests_to_run: Optional[list] = None) -> XCTestConfiguration:
        return XCTestConfiguration({
            "testBundleURL": NSURL(None, f"file://"), # TODO
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