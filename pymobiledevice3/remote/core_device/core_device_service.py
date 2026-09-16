import uuid
from collections.abc import AsyncIterator
from typing import Any, Optional, cast

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

# Wire keys for the streaming feature protocol (streamapplist/streamprocesslist), verified
# against iOS 26 (CoreDeviceUtilities StreamingAction.swift: _StreamingActionInputContainer /
# _StreamProxy / _StreamProxy.SideChannelStatus).
#
# Request: CoreDevice.input wraps the normal params under "actualInput" plus a "streamProxy"
# carrying a client-generated "sideChannel" UUID that opens the side channel.
# Response: the daemon pushes a series of messages, each keyed by "...sideChannelStatus" whose
# value is a SideChannelStatus enum -- "pushing" ({"elements": [...]}), then a terminating
# "finishStreaming", or "receivedError" on failure. Every message echoes the side-channel UUID
# under "XPCSideChannel.uniqueIdentifier".
STREAM_INPUT_KEY = "actualInput"
STREAM_PROXY_KEY = "streamProxy"
STREAM_SIDE_CHANNEL_KEY = "sideChannel"
STREAM_STATUS_KEY = "CoreDevice.XPCMessageKey.sideChannelStatus"
STREAM_PUSHING_KEY = "pushing"
STREAM_ELEMENTS_KEY = "elements"
STREAM_FINISH_KEY = "finishStreaming"
STREAM_RECEIVED_ERROR_KEY = "receivedError"


def _core_device_error(feature_identifier: Optional[str], response: dict[str, Any]) -> CoreDeviceError:
    """Build a :class:`CoreDeviceError` from a failed ``invoke`` response.

    The daemon returns the failure under ``CoreDevice.error`` as a dict carrying
    ``code``, ``domain`` and a ready-to-read ``userInfo`` (the
    ``userInfoWithNSSecureCoding`` bplist is the same info, kept as a fallback).
    Surfacing the localized reason turns an opaque bplist dump into, e.g.,
    ``The device microphone or camera is currently in use.``.
    """
    raw_error = response.get("CoreDevice.error")
    if not isinstance(raw_error, dict):
        return CoreDeviceError(f"Failed to invoke: {feature_identifier}. Got error: {response}")

    error = cast(dict[str, Any], raw_error)
    code = error.get("code")
    domain = error.get("domain")
    raw_user_info = error.get("userInfo")
    user_info: dict[str, Any] = cast(dict[str, Any], raw_user_info) if isinstance(raw_user_info, dict) else {}
    description = user_info.get("NSLocalizedDescription")
    if not isinstance(description, str):
        description = _localized_description_from_archive(error.get("userInfoWithNSSecureCoding"))
    detail = description or "unknown error"
    return CoreDeviceError(
        f"Failed to invoke {feature_identifier}: {detail} (domain={domain}, code={code})",
        code=code if isinstance(code, int) else None,
        domain=domain if isinstance(domain, str) else None,
        user_info={**user_info, **({"NSLocalizedDescription": description} if description else {})},
    )


def _localized_description_from_archive(archive: Any) -> Optional[str]:
    """Best-effort ``NSLocalizedDescription`` from a ``userInfoWithNSSecureCoding`` bplist."""
    if not isinstance(archive, (bytes, bytearray)):
        return None
    try:
        import bpylist2.archiver

        decoded = bpylist2.archiver.unarchive(bytes(archive))
    except Exception:
        return None
    if not isinstance(decoded, dict):
        return None
    description = cast(dict[str, Any], decoded).get("NSLocalizedDescription")
    return description if isinstance(description, str) else None


class CoreDeviceService(RemoteService):
    async def invoke(
        self,
        feature_identifier: Optional[str] = None,
        input_: Optional[dict[str, Any]] = None,
        action_identifier: Optional[str] = None,
    ) -> Any:
        if feature_identifier is not None:
            self.rsd.require_feature(self.service_name, feature_identifier)
        if input_ is None:
            input_ = {}
        request: dict[str, Any] = {
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
            raise _core_device_error(feature_identifier, response)
        return output

    async def stream_invoke(
        self,
        feature_identifier: str,
        input_: Optional[dict[str, Any]] = None,
    ) -> AsyncIterator[Any]:
        """Invoke a streaming feature (e.g. streamapplist/streamprocesslist).

        Unlike ``invoke``, a streaming feature returns many responses over time: the daemon
        pushes ``SideChannelStatus.pushing`` batches over the side channel and ends with
        ``finishStreaming``. Each element is yielded individually.
        """
        self.rsd.require_feature(self.service_name, feature_identifier)
        if input_ is None:
            input_ = {}
        request: dict[str, Any] = {
            "CoreDevice.CoreDeviceDDIProtocolVersion": XpcInt64Type(2),
            "CoreDevice.coreDeviceVersion": CORE_DEVICE_VERSION,
            "CoreDevice.deviceIdentifier": str(uuid.uuid4()),
            "CoreDevice.featureIdentifier": feature_identifier,
            "CoreDevice.action": {},
            "CoreDevice.input": {
                STREAM_INPUT_KEY: input_,
                STREAM_PROXY_KEY: {STREAM_SIDE_CHANNEL_KEY: uuid.uuid4()},
            },
            "CoreDevice.invocationIdentifier": str(uuid.uuid4()),
        }
        async with self.service._request_lock:
            await self.service.send_request(request, wanting_reply=True)
            while True:
                response = await self.service.receive_response()
                status: Any = response.get(STREAM_STATUS_KEY)
                if status is None:
                    raise CoreDeviceError(
                        f"Failed to invoke streaming feature: {feature_identifier}. Got error: {response}"
                    )
                if STREAM_RECEIVED_ERROR_KEY in status:
                    raise CoreDeviceError(f"Stream {feature_identifier} failed: {status[STREAM_RECEIVED_ERROR_KEY]}")
                if STREAM_FINISH_KEY in status:
                    break
                for element in status[STREAM_PUSHING_KEY][STREAM_ELEMENTS_KEY]:
                    yield element
