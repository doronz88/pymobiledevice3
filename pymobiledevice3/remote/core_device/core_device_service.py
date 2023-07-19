from typing import Any, Mapping

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type


class CoreDeviceService(RemoteService):
    def invoke(self, feature_identifier: str, input_: Mapping = None) -> Any:
        if input_ is None:
            input_ = {}
        response = self.service.send_receive_request({
            'CoreDevice.CoreDeviceDDIProtocolVersion': XpcInt64Type(0),
            'CoreDevice.action': {},

            'CoreDevice.coreDeviceVersion': {
                'components': [XpcUInt64Type(325), XpcUInt64Type(3), XpcUInt64Type(0),
                               XpcUInt64Type(0), XpcUInt64Type(0)],
                'originalComponentsCount': XpcInt64Type(2),
                'stringValue': '325.3'},
            'CoreDevice.deviceIdentifier': '7454ABFD-F789-4F99-9EE1-5FB8F7035ECE',
            'CoreDevice.featureIdentifier': feature_identifier,
            'CoreDevice.input': input_,
            'CoreDevice.invocationIdentifier': '14A17AB8-0576-4E73-94C6-C0282A4F66E3'})
        output = response.get('CoreDevice.output')
        if output is None:
            raise CoreDeviceError(f'Failed to invoke: {feature_identifier}. Got error: {response}')
        return output
