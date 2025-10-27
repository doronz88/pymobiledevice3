#!/usr/bin/env python3
import dataclasses
import logging
import plistlib
import xml.etree.ElementTree as ET
from contextlib import closing
from pathlib import Path
from typing import Optional

import click
import inquirer3
import requests
from requests.structures import CaseInsensitiveDict

from pymobiledevice3.exceptions import MobileActivationException
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


@dataclasses.dataclass
class Field:
    id: str
    label: str
    placeholder: str
    secure: bool


@dataclasses.dataclass
class ActivationForm:
    title: str
    description: str
    fields: list[Field]
    server_info: dict[str, str]


class MobileActivationService:
    """
    Perform device activation

    There is no point in inheriting from BaseService since we'll need a new lockdown connection
    for each request.
    """

    SERVICE_NAME = "com.apple.mobileactivationd"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self.lockdown = lockdown
        self.logger = logging.getLogger(__name__)

    @property
    def state(self):
        try:
            return self.send_command("GetActivationStateRequest")["Value"]
        except Exception:
            return self.lockdown.get_value(key="ActivationState")

    def wait_for_activation_session(self):
        try:
            blob = self.create_activation_session_info()
        except Exception:
            return
        handshake_request_message = blob["HandshakeRequestMessage"]
        while handshake_request_message == blob["HandshakeRequestMessage"]:
            blob = self.create_activation_session_info()

    @staticmethod
    def _get_activation_form_from_response(content: str) -> ActivationForm:
        root = ET.fromstring(content)
        title = root.find("page/navigationBar").get("title")
        description = root.find("page/tableView/section/footer").text
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
        for k, v in root.find("serverInfo").items():
            server_info[k] = v
        return ActivationForm(title=title, description=description, fields=fields, server_info=server_info)

    def activate(self, skip_apple_id_query: bool = False) -> None:
        if self.state != "Unactivated":
            self.logger.error("Device is already activated!")
            return

        try:
            blob = self.create_activation_session_info()
            session_mode = True
        except Exception:
            session_mode = False

        # create drmHandshake request with blob from device
        headers = {"Content-Type": "application/x-apple-plist"}
        headers.update(DEFAULT_HEADERS)
        if session_mode:
            content, headers = self.post(
                ACTIVATION_DRM_HANDSHAKE_DEFAULT_URL, data=plistlib.dumps(blob), headers=headers
            )

        activation_request = {}
        if session_mode:
            activation_info = self.create_activation_info_with_session(content)
        else:
            activation_info = self.lockdown.get_value(key="ActivationInfo")
            activation_request.update({
                "InStoreActivation": False,
                "AppleSerialNumber": self.lockdown.get_value(key="SerialNumber"),
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
            self.activate_with_session(content, headers)
        else:
            self.activate_with_lockdown(content)

        # set ActivationStateAcknowledged if we succeeded
        self.lockdown.set_value(True, key="ActivationStateAcknowledged")

    def deactivate(self):
        try:
            return self.send_command("DeactivateRequest")
        except Exception:
            return self.lockdown._request("Deactivate")

    def create_activation_session_info(self):
        response = self.send_command("CreateTunnel1SessionInfoRequest")
        error = response.get("Error")
        if error is not None:
            raise MobileActivationException(f"Mobile activation can not be done due to: {response}")
        return response["Value"]

    def create_activation_info_with_session(self, handshake_response):
        response = self.send_command("CreateTunnel1ActivationInfoRequest", handshake_response)
        error = response.get("Error")
        if error is not None:
            raise MobileActivationException(f"Mobile activation can not be done due to: {response}")
        return response["Value"]

    def activate_with_lockdown(self, activation_record):
        record = plistlib.loads(activation_record)
        node = record.get("iphone-activation")
        if node is None:
            node = record.get("device-activation")
        if node is None:
            raise MobileActivationException("Activation record received is invalid")

        self.lockdown._request("Activate", {"ActivationRecord": node.get("activation-record")})

    def activate_with_session(self, activation_record, headers):
        data = {
            "Command": "HandleActivationInfoWithSessionRequest",
            "Value": activation_record,
        }
        if headers:
            data["ActivationResponseHeaders"] = dict(headers)
        with closing(self.lockdown.start_lockdown_service(self.SERVICE_NAME)) as service:
            return service.send_recv_plist(data)

    def send_command(self, command: str, value: str = ""):
        data = {"Command": command}
        if value:
            data["Value"] = value
        with closing(self.lockdown.start_lockdown_service(self.SERVICE_NAME)) as service:
            return service.send_recv_plist(data)

    def post(
        self, url: str, data: dict, headers: Optional[CaseInsensitiveDict[str, str]] = None
    ) -> tuple[bytes, CaseInsensitiveDict[str]]:
        if headers is None:
            headers = DEFAULT_HEADERS

        resp = requests.post(url, data=data, headers=headers)
        return resp.content, resp.headers
