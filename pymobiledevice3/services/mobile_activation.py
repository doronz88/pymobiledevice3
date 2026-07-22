#!/usr/bin/env python3
import dataclasses
import logging
import plistlib
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, Union

import click
import inquirer3
import requests
from requests.structures import CaseInsensitiveDict

from pymobiledevice3.exceptions import MobileActivationException
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

ACTIVATION_USER_AGENT_IOS = "iOS Device Activator (MobileActivation-20 built on Jan 15 2012 at 19:07:28)"
ACTIVATION_DEFAULT_URL = "https://albert.apple.com/deviceservices/deviceActivation"
ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL = "https://albert.apple.com/deviceservices/drmHandshake"
DEFAULT_HEADERS = {
    "Accept": "application/xml",
    "User-Agent": ACTIVATION_USER_AGENT_IOS,
    "Expect": "100-continue",
}

ACTIVATION_REQUESTS_SUBDIR = Path("offline_requests")
NONCE_CYCLE_INTERVAL = 60 * 5


@asynccontextmanager
async def _aclosing(resource):
    try:
        yield resource
    finally:
        await resource.aclose()


@dataclasses.dataclass
class Field:
    id: Optional[str]
    label: Optional[str]
    placeholder: Optional[str]
    secure: bool


@dataclasses.dataclass
class ActivationForm:
    title: Optional[str]
    description: Optional[str]
    fields: list[Field]
    server_info: dict[str, str]


class MobileActivationService:
    """
    Drive iOS device activation against Apple's activation servers via ``com.apple.mobileactivationd``.

    Orchestrates the full activation handshake: it gathers activation information from the device,
    exchanges it with Apple's activation and DRM-handshake endpoints over HTTP, optionally prompts
    the user for Apple ID credentials when the server requests them, and writes the resulting
    activation record back to the device. Both the modern session-based flow and the legacy
    lockdown flow are supported, with the session flow preferred when available.

    A fresh lockdown service connection is opened for each request rather than reusing one, so this
    class does not inherit from the shared service base.
    """

    SERVICE_NAME = "com.apple.mobileactivationd"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self.lockdown = lockdown
        self.logger = logging.getLogger(__name__)

    async def state(self):
        """
        Return the device's current activation state.

        Queries the activation daemon for the activation state, falling back to the lockdown
        ``ActivationState`` value if the daemon request fails.

        :returns: the activation state (e.g. ``"Unactivated"`` or ``"Activated"``).
        """
        try:
            return (await self.send_command("GetActivationStateRequest"))["Value"]
        except Exception:
            return await self.lockdown.get_value(key="ActivationState")

    async def wait_for_activation_session(self):
        """
        Block until the device produces a fresh activation session handshake.

        Repeatedly requests activation session info until the handshake request message changes,
        indicating the device is ready with a new session. Returns immediately if the device does
        not support the session-based flow.
        """
        try:
            blob = await self.create_activation_session_info()
        except Exception:
            return
        handshake_request_message = blob["HandshakeRequestMessage"]
        while handshake_request_message == blob["HandshakeRequestMessage"]:
            blob = await self.create_activation_session_info()

    @staticmethod
    def _get_activation_form_from_response(content: str) -> ActivationForm:
        root = ET.fromstring(content)
        navigation_bar = root.find("page/navigationBar")
        footer = root.find("page/tableView/section/footer")
        server_info_node = root.find("serverInfo")
        if navigation_bar is None or footer is None or server_info_node is None:
            raise MobileActivationException("Activation server response is invalid")
        title = navigation_bar.get("title")
        description = footer.text
        fields = []
        for editable in root.findall("page//editableTextRow"):
            fields.append(
                Field(
                    id=editable.get("id"),
                    label=editable.get("label"),
                    placeholder=editable.get("placeholder"),
                    secure=bool(editable.get("secure", False)),
                )
            )
        server_info = {}
        for k, v in server_info_node.items():
            server_info[k] = v
        return ActivationForm(title=title, description=description, fields=fields, server_info=server_info)

    async def activate(self, skip_apple_id_query: bool = False) -> None:
        """
        Activate the device end-to-end against Apple's activation servers.

        Does nothing if the device is already activated. Otherwise it collects activation info from
        the device (preferring the session-based flow, including a DRM handshake with Apple when
        available), posts it to the activation server, and applies the returned activation record.
        If the server responds with a BuddyML form requesting Apple ID credentials, the user is
        prompted interactively and the form is resubmitted. On success, the device's
        ``ActivationStateAcknowledged`` value is set.

        :param skip_apple_id_query: when True, do not prompt for Apple ID credentials; instead treat
            a credentials request as an iCloud lock and raise.
        :raises MobileActivationException: if the device is iCloud locked (with
            ``skip_apple_id_query`` set) or the activation server response is invalid.
        """
        if await self.state() != "Unactivated":
            self.logger.error("Device is already activated!")
            return

        blob = None
        try:
            blob = await self.create_activation_session_info()
            session_mode = True
        except Exception:
            session_mode = False

        # create drmHandshake request with blob from device
        headers = {"Content-Type": "application/x-apple-plist"}
        headers.update(DEFAULT_HEADERS)
        content = None
        if session_mode:
            assert blob is not None  # session_mode is True only when the session info was created
            content, headers = self.post(
                ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL, data=plistlib.dumps(blob), headers=headers
            )

        activation_request = {}
        if session_mode:
            activation_info = await self.create_activation_info_with_session(content)
        else:
            activation_info = await self.lockdown.get_value(key="ActivationInfo")
            activation_request.update({
                "InStoreActivation": False,
                "AppleSerialNumber": await self.lockdown.get_value(key="SerialNumber"),
            })
            if self.lockdown.all_values.get("TelephonyCapability"):
                req_pair = {
                    "IMEI": "InternationalMobileEquipmentIdentity",
                    "MEID": "MobileEquipmentIdentifier",
                    "IMSI": "InternationalMobileSubscriberIdentity",
                    "ICCID": "IntegratedCircuitCardIdentity",
                }

                has_meid = False
                for k, v in req_pair.items():
                    lv = self.lockdown.all_values.get(v)
                    if lv is not None:
                        activation_request.update({k: lv})
                        continue
                    else:
                        self.logger.warn(f"Unable to get {k} from lockdownd")
                        if k == "MEID" and has_meid:
                            # Something is wrong if both IMEI & MEID is missing
                            raise MobileActivationException("Unable to obtain both IMEI and MEID")

                    # Either IMEI or MEID, or both
                    if k == "IMEI":
                        has_meid = lv is None
        activation_request.update({"activation-info": plistlib.dumps(activation_info)})

        content, headers = self.post(ACTIVATION_DEFAULT_URL, data=activation_request)
        content_type = headers["Content-Type"]

        if content_type == "application/x-buddyml":
            if skip_apple_id_query:
                raise MobileActivationException("Device is iCloud locked")
            try:
                activation_form = self._get_activation_form_from_response(content.decode())
            except Exception as e:
                raise MobileActivationException("Activation server response is invalid") from e
            else:
                click.secho(activation_form.title, bold=True)
                click.secho(activation_form.description)
                fields = []
                for field in activation_form.fields:
                    if field.secure:
                        fields.append(inquirer3.Password(name=field.id, message=f"{field.label}"))
                    else:
                        fields.append(inquirer3.Text(name=field.id, message=f"{field.label}"))
                data = inquirer3.prompt(fields)
                data.update(activation_form.server_info)
                content, headers = self.post(ACTIVATION_DEFAULT_URL, data=data)
                content_type = headers["Content-Type"]

        assert content_type == "text/xml"
        if session_mode:
            await self.activate_with_session(content, headers)
        else:
            await self.activate_with_lockdown(content)

        # set ActivationStateAcknowledged if we succeeded
        await self.lockdown.set_value(True, key="ActivationStateAcknowledged")

    async def deactivate(self):
        """
        Deactivate the device.

        Sends a ``DeactivateRequest`` to the activation daemon, falling back to the lockdown
        ``Deactivate`` request if that fails.

        :returns: the response from whichever deactivation path succeeds.
        """
        try:
            return await self.send_command("DeactivateRequest")
        except Exception:
            assert isinstance(self.lockdown, LockdownClient)
            return await self.lockdown._request("Deactivate")

    async def create_activation_session_info(self):
        """
        Request the device's session-based activation handshake info.

        Sends a ``CreateTunnel1SessionInfoRequest`` to the activation daemon.

        :returns: the session info blob (the ``Value`` entry), including the handshake request message.
        :raises MobileActivationException: if the daemon returns an error.
        """
        response = await self.send_command("CreateTunnel1SessionInfoRequest")
        error = response.get("Error")
        if error is not None:
            raise MobileActivationException(f"Mobile activation can not be done due to: {response}")
        return response["Value"]

    async def create_activation_info_with_session(self, handshake_response):
        """
        Build the device's activation info from a completed DRM handshake.

        Sends a ``CreateTunnel1ActivationInfoRequest`` to the activation daemon, passing the DRM
        handshake response received from Apple.

        :param handshake_response: the DRM handshake response content returned by Apple's server.
        :returns: the activation info blob (the ``Value`` entry) to post to the activation server.
        :raises MobileActivationException: if the daemon returns an error.
        """
        response = await self.send_command("CreateTunnel1ActivationInfoRequest", handshake_response)
        error = response.get("Error")
        if error is not None:
            raise MobileActivationException(f"Mobile activation can not be done due to: {response}")
        return response["Value"]

    async def activate_with_lockdown(self, activation_record):
        """
        Apply an activation record to the device using the legacy lockdown flow.

        Parses the activation record, extracts the ``iphone-activation`` or ``device-activation``
        node, and submits its activation record via the lockdown ``Activate`` request.

        :param activation_record: the serialized activation record returned by the activation server.
        :raises MobileActivationException: if the activation record does not contain a recognized
            activation node.
        """
        record = plistlib.loads(activation_record)
        node = record.get("iphone-activation")
        if node is None:
            node = record.get("device-activation")
        if node is None:
            raise MobileActivationException("Activation record received is invalid")

        assert isinstance(self.lockdown, LockdownClient)
        await self.lockdown._request("Activate", {"ActivationRecord": node.get("activation-record")})

    async def activate_with_session(self, activation_record, headers):
        """
        Apply an activation record to the device using the session-based flow.

        Sends a ``HandleActivationInfoWithSessionRequest`` to the activation daemon, including the
        activation record and, if provided, the HTTP response headers from the activation server.

        :param activation_record: the activation record returned by the activation server.
        :param headers: HTTP response headers from the activation server, forwarded as
            ``ActivationResponseHeaders``; may be falsy to omit them.
        :returns: the daemon's response to the request.
        """
        data = {
            "Command": "HandleActivationInfoWithSessionRequest",
            "Value": activation_record,
        }
        if headers:
            data["ActivationResponseHeaders"] = dict(headers)
        async with _aclosing(await self.lockdown.start_lockdown_service(self.SERVICE_NAME)) as service:
            return await service.send_recv_plist(data)

    async def send_command(self, command: str, value: str = ""):
        """
        Send a single command to the activation daemon over a fresh service connection.

        Opens the ``com.apple.mobileactivationd`` service, sends the command (with an optional
        ``Value``), and returns the response. The connection is closed afterwards.

        :param command: the activation daemon command name.
        :param value: optional value sent alongside the command; omitted when empty.
        :returns: the daemon's response plist.
        """
        data = {"Command": command}
        if value:
            data["Value"] = value
        async with _aclosing(await self.lockdown.start_lockdown_service(self.SERVICE_NAME)) as service:
            return await service.send_recv_plist(data)

    def post(
        self, url: str, data: Union[dict, bytes], headers: Optional[dict[str, str]] = None
    ) -> tuple[bytes, CaseInsensitiveDict[str]]:
        """
        Perform an HTTP POST to an activation server endpoint.

        :param url: the activation endpoint to post to.
        :param data: the form data or request body to send.
        :param headers: optional request headers; the module's default activation headers are used
            when omitted.
        :returns: a tuple of the response body bytes and the response headers.
        """
        if headers is None:
            headers = DEFAULT_HEADERS

        resp = requests.post(url, data=data, headers=headers)
        return resp.content, resp.headers
