from typing import Any, Optional, cast

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type


def _xpc_encodable(obj: Any) -> Any:
    """Wrap the plain ints of a plist-shaped value so the XPC encoder accepts it (bools stay bools)."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return XpcInt64Type(obj)
    if isinstance(obj, dict):
        return {key: _xpc_encodable(value) for key, value in cast(dict[str, Any], obj).items()}
    if isinstance(obj, list):
        return [_xpc_encodable(value) for value in cast(list[Any], obj)]
    return obj


class RestoreService(RemoteService):
    """
    Issue restore-time control commands to ``restoreserviced`` over RemoteXPC.

    Wraps the ``com.apple.RestoreRemoteServices.restoreserviced`` remote service, exposing commands
    used during the restore/recovery flow such as entering recovery, rebooting, and reading nonces
    and preflight information. This is a remote service reached over RSD and is used as an async
    context manager.

    Use one connection per command: on iOS 27.0 the daemon aborts ("Attempted to send non-reply msg
    on the reply channel") when it answers a second request on the same connection.
    """

    SERVICE_NAME = "com.apple.RestoreRemoteServices.restoreserviced"

    def __init__(self, lockdown: RemoteServiceDiscoveryService):
        super().__init__(lockdown, self.SERVICE_NAME)

    async def delay_recovery_image(self) -> None:
        """
        Request that the recovery image be delayed.

        Sends the ``delayrecoveryimage`` command, which is only honored on devices of ProductType
        ``0x1677b394`` and otherwise fails.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        await self.validate_command("delayrecoveryimage")

    async def enter_recovery(self) -> None:
        """
        Put the device into recovery mode.

        Sends the ``recovery`` command.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        await self.validate_command("recovery")

    async def reboot(self) -> None:
        """
        Reboot the device.

        Sends the ``reboot`` command.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        await self.validate_command("reboot")

    async def get_preflightinfo(self) -> dict[str, Any]:
        """
        Retrieve restore preflight information from the device.

        Sends the ``getpreflightinfo`` command.

        :returns: the device's preflight info response.
        """
        return await self.service.send_receive_request({"command": "getpreflightinfo"})

    async def get_device_side_preflightinfo(self, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """
        Run the updaters' preflight on the device and return what they report.

        Sends the ``getdevicesidepreflightinfo`` command. Without a payload the reply is the same
        per-updater ``DeviceInfo`` lockdown's ``PreflightInfo`` carries. With a ``payload`` of the
        form ``{"BuildIdentity": <identity>, "<Updater>": {<manifest tag>: <firmware bytes>}}`` the
        device also builds the TSS request of every updater named in it (``DeviceInfoRequests``)
        and reports its tags (``DeviceInfoTags``) — the same request restored sends during a restore.
        See :func:`pymobiledevice3.restore.preflight.build_tethered_preflight_payload`.

        :param payload: the tethered preflight payload, or None for the plain query.
        :returns: the ``preflightinfo`` dictionary of the reply.
        :raises PyMobileDevice3Exception: if the device reports an error.
        """
        request: dict[str, Any] = {"command": "getdevicesidepreflightinfo"}
        if payload is not None:
            request["payload"] = _xpc_encodable(payload)
        response = await self.service.send_receive_request(request)
        if response.get("result") != "preflightinfo":
            raise PyMobileDevice3Exception(f"getdevicesidepreflightinfo failed: {response}")
        return response["preflightinfo"]

    async def get_nonces(self) -> dict[str, Any]:
        """
        Retrieve the device's restore nonces.

        Sends the ``getnonces`` command.

        :returns: the response containing the ApNonce and SEPNonce.
        """
        return await self.service.send_receive_request({"command": "getnonces"})

    async def get_app_parameters(self) -> dict[str, Any]:
        """
        Retrieve restore app parameters from the device.

        Sends the ``getappparameters`` command.

        :returns: the device's app parameters response.
        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        return await self.validate_command("getappparameters")

    async def restore_lang(self, language: str) -> dict[str, Any]:
        """
        Set the restore language.

        Sends the ``restorelang`` command with the given language as its argument.

        :param language: the language identifier to set for the restore.
        :returns: the device's response to the command.
        """
        return await self.service.send_receive_request({"command": "restorelang", "argument": language})

    async def validate_command(self, command: str) -> dict[str, Any]:
        """
        Send a command and assert that the device reports success.

        Sends the given command and verifies the response ``result`` is ``"success"``.

        :param command: the restore command name to send.
        :returns: the device's response.
        :raises PyMobileDevice3Exception: if the response result is not ``"success"``.
        """
        response = await self.service.send_receive_request({"command": command})
        if response.get("result") != "success":
            raise PyMobileDevice3Exception(f"request command: {command} failed with error: {response}")
        return response
