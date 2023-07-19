import uuid
from typing import Any, Mapping

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type


def _generate_core_device_version_dict(version: str) -> Mapping:
    version_components = version.split('.')
    return {'components': [XpcUInt64Type(component) for component in version_components],
            'originalComponentsCount': XpcInt64Type(len(version_components)),
            'stringValue': version}


CORE_DEVICE_VERSION = _generate_core_device_version_dict('325.3')


class CoreDeviceService(RemoteService):
    def invoke(self, feature_identifier: str, input_: Mapping = None) -> Any:
        if input_ is None:
            input_ = {}
        response = self.service.send_receive_request({
            'CoreDevice.CoreDeviceDDIProtocolVersion': XpcInt64Type(0),
            'CoreDevice.action': {},
            'CoreDevice.coreDeviceVersion': CORE_DEVICE_VERSION,
            'CoreDevice.deviceIdentifier': str(uuid.uuid4()),
            'CoreDevice.featureIdentifier': feature_identifier,
            'CoreDevice.input': input_,
            'CoreDevice.invocationIdentifier': str(uuid.uuid4())})
        output = response.get('CoreDevice.output')
        if output is None:
            raise CoreDeviceError(f'Failed to invoke: {feature_identifier}. Got error: {response}')
        return output
