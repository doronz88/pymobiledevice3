import uuid
from typing import Any, Optional

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type


def _generate_core_device_version_dict(version: str) -> dict[str, Any]:
    version_components = version.split(".")
    return {
        "components": [XpcUInt64Type(component) for component in version_components],
        "originalComponentsCount": XpcInt64Type(len(version_components)),
        "stringValue": version,
    }


CORE_DEVICE_VERSION = _generate_core_device_version_dict("629.3")


class CoreDeviceService(RemoteService):
    async def invoke(
        self,
        feature_identifier: Optional[str] = None,
        input_: Optional[dict[str, Any]] = None,
        action_identifier: Optional[str] = None,
    ) -> Any:
        if input_ is None:
            input_ = {}
        request = {
            "CoreDevice.CoreDeviceDDIProtocolVersion": XpcInt64Type(2),
            "CoreDevice.coreDeviceVersion": CORE_DEVICE_VERSION,
            "CoreDevice.deviceIdentifier": str(uuid.uuid4()),
            "CoreDevice.input": input_,
            "CoreDevice.invocationIdentifier": str(uuid.uuid4()),
        }
        if feature_identifier is not None:
            request["CoreDevice.featureIdentifier"] = feature_identifier
            request["CoreDevice.action"] = {}
        if action_identifier is not None:
            request["CoreDevice.actionIdentifier"] = action_identifier
        response = await self.service.send_receive_request(request)
        output = response.get("CoreDevice.output")
        if output is None:
            raise CoreDeviceError(f"Failed to invoke: {feature_identifier}. Got error: {response}")
        return output
