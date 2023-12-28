import logging
import uuid

import bpylist2
from packaging.version import Version

from pymobiledevice3.services.dvt.dvt_testmanaged_proxy import \
    DvtTestmanagedProxyService
from pymobiledevice3.services.remote_server import NSUUID, XCTestConfiguration, MessageAux

logger = logging.getLogger(__name__)


class XCUITestService:
    IDENTIFIER = 'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface'

    def __init__(self, dvt: DvtTestmanagedProxyService):
        self._dvt = dvt

    def run(self):
        dvt = self._dvt
        logger.info("make channel %s", self.IDENTIFIER)
        self._chan1 = dvt.make_channel(self.IDENTIFIER)
        self._chan2 = dvt.make_channel(self.IDENTIFIER)

        XCODE_VERSION = 29
        product_version = Version(self._dvt.lockdown.product_version)
        if product_version >= Version("11.0"):
            self._dvt.send_message(
                self._chan1,
                "_IDE_initiateControlSessionWithProtocolVersion:",
                MessageAux().append_obj(XCODE_VERSION))
            result = self._chan1.receive_key_value()
            logger.info("chan1 first call result: %s", result)
        
        # TODO: Generate XCTestConfiguration
        # handle _XCT_testRunnerReadyWithCapabilities: request
        
        session_identifier = NSUUID.uuid4()
        self._dvt.send_message(
            channel=self._chan2,
            selector='_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:',
            args=MessageAux()
                .append_obj(session_identifier)
                .append_obj(str(session_identifier) + '-6722-000247F15966B083') # Random suffix
                .append_obj('/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild')
                .append_obj(XCODE_VERSION),
            expects_reply=True
        )
        result = self._chan2.receive_key_value()
        logger.info("chan2 first call result(guess xcode version): %s", result) # TODO: check result

        if product_version >= Version("12.0"):
            pass
    
    def launch_test_app(self,
                        bundle_id: str,
                        session_identifier: NSUUID,
                        xctest_configuration: XCTestConfiguration):
        pass
