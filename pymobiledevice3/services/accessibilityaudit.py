import asyncio
import json
import typing
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from enum import Enum, IntEnum

from packaging.version import Version

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.remote_server import MessageAux, RemoteServer


class SerializedObject:
    def __init__(self, fields: dict):
        self._fields = fields


class AXAuditInspectorFocus_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)

    @property
    def caption(self) -> str:
        return self._fields.get("CaptionTextValue_v1")

    @property
    def spoken_description(self) -> str:
        return self._fields.get("SpokenDescriptionValue_v1")

    @property
    def element(self) -> bytes:
        return self._fields.get("ElementValue_v1")

    @property
    def platform_identifier(self) -> str:
        """Converts the element bytes to a hexadecimal string."""
        return self.element.identifier.hex().upper()

    @property
    def estimated_uid(self) -> str:
        """Generates a UID from the platform identifier."""
        hex_value = self.platform_identifier

        if len(hex_value) % 2 != 0:
            raise ValueError("Hex value length must be even.")

        hex_bytes = bytes.fromhex(hex_value)

        if len(hex_bytes) < 16:
            raise ValueError("Hex value must contain at least 16 bytes.")

        # Extract TimeLow bytes (indexes 12 to 15)
        time_low_bytes = hex_bytes[12:16]
        time_low = time_low_bytes.hex().upper()

        # Extract ClockSeq bytes (indexes 0 to 1)
        clock_seq_bytes = hex_bytes[0:2]
        clock_seq = clock_seq_bytes.hex().upper()

        # Construct UID with placeholder values for unused parts
        uid = f"{time_low}-0000-0000-{clock_seq}-000000000000"

        return uid

    def to_dict(self) -> dict:
        """Serializes the focus element into a dictionary."""
        return {
            "platform_identifier": self.platform_identifier,
            "estimated_uid": self.estimated_uid,
            "caption": self.caption,
            "spoken_description": self.spoken_description,
        }

    def __str__(self):
        return f"<Focused ElementCaption: {self.caption}>"


class AXAuditElement_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)

    @property
    def identifier(self) -> bytes:
        return self._fields["PlatformElementValue_v1"]

    def __repr__(self):
        return f"<Element: {self.identifier}>"


class AXAuditInspectorSection_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)


class AXAuditElementAttribute_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)


class AXAuditDeviceSetting_v1(SerializedObject):
    FIELDS = ("IdentiifierValue_v1", "CurrentValueNumber_v1")

    def __init__(self, fields):
        super().__init__(fields)
        for k in self.FIELDS:
            if k not in self._fields:
                self._fields[k] = None

    @property
    def key(self) -> str:
        return self._fields["IdentiifierValue_v1"]

    @property
    def value(self) -> typing.Any:
        return self._fields["CurrentValueNumber_v1"]

    def __str__(self) -> str:
        return f"<AXAuditDeviceSetting_v1 {self.key} = {self.value}>"


class AuditType(IntEnum):
    DYNAMIC_TEXT = 3001
    DYNAMIC_TEXT_ALT = 3002
    TEXT_CLIPPED = 3003
    ELEMENT_DETECTION = 1000
    SUFFICIENT_ELEMENT_DESCRIPTION = 5000
    HIT_REGION = 100
    CONTRAST = 12
    CONTRAST_ALT = 13


AUDIT_TYPE_DESCRIPTIONS = {
    AuditType.DYNAMIC_TEXT: "testTypeDynamicText",
    AuditType.DYNAMIC_TEXT_ALT: "testTypeDynamicText",
    AuditType.TEXT_CLIPPED: "testTypeTextClipped",
    AuditType.ELEMENT_DETECTION: "testTypeElementDetection",
    AuditType.SUFFICIENT_ELEMENT_DESCRIPTION: "testTypeSufficientElementDescription",
    AuditType.HIT_REGION: "testTypeHitRegion",
    AuditType.CONTRAST: "testTypeContrast",
    AuditType.CONTRAST_ALT: "testTypeContrast",
}


class AXAuditIssue_v1(SerializedObject):
    FIELDS = (
        "ElementRectValue_v1",
        "IssueClassificationValue_v1",
        "FontSizeValue_v1",
        "MLGeneratedDescriptionValue_v1",
        "ElementLongDescExtraInfo_v1",
        "BackgroundColorValue_v1",
        "ForegroundColorValue_v1",
    )

    def __init__(self, fields):
        super().__init__(fields)

        for k in self.FIELDS:
            if k not in self._fields:
                self._fields[k] = None

    @property
    def rect(self) -> str:
        return self._fields["ElementRectValue_v1"]

    @property
    def issue_type(self) -> typing.Any:
        issue_classification = self._fields["IssueClassificationValue_v1"]
        if issue_classification in AUDIT_TYPE_DESCRIPTIONS:
            return AUDIT_TYPE_DESCRIPTIONS[AuditType(issue_classification)]
        else:
            return issue_classification

    @property
    def ml_generated_description(self) -> typing.Any:
        return self._fields["MLGeneratedDescriptionValue_v1"]

    @property
    def long_description_extra_info(self) -> typing.Any:
        return self._fields["ElementLongDescExtraInfo_v1"]

    @property
    def font_size(self) -> typing.Any:
        return self._fields["FontSizeValue_v1"]

    @property
    def foreground_color(self) -> typing.Any:
        return self._fields["ForegroundColorValue_v1"]

    @property
    def background_color(self) -> typing.Any:
        return self._fields["BackgroundColorValue_v1"]

    def json(self) -> dict:
        resp = {
            "element_rect_value": self.rect,
            "issue_classification": self.issue_type,
            "font_size": self.font_size,
            "ml_generated_description": self.ml_generated_description,
            "long_description_extra_info": self.long_description_extra_info,
        }
        # Include foreground and background colors when issue type is 'testTypeContrast'
        if self._fields["IssueClassificationValue_v1"] in {AuditType.CONTRAST, AuditType.CONTRAST_ALT}:
            resp["foreground_color"] = self.foreground_color
            resp["background_color"] = self.background_color
        return resp

    def __str__(self) -> str:
        return json.dumps(self.json())


SERIALIZABLE_OBJECTS = {
    "AXAuditDeviceSetting_v1": AXAuditDeviceSetting_v1,
    "AXAuditInspectorFocus_v1": AXAuditInspectorFocus_v1,
    "AXAuditElement_v1": AXAuditElement_v1,
    "AXAuditInspectorSection_v1": AXAuditInspectorSection_v1,
    "AXAuditElementAttribute_v1": AXAuditElementAttribute_v1,
    "AXAuditIssue_v1": AXAuditIssue_v1,
}


@dataclass
class Event:
    name: str
    data: SerializedObject


class Direction(Enum):
    Previous = 3
    Next = 4
    First = 5
    Last = 6


def deserialize_object(d):
    if not isinstance(d, dict):
        if isinstance(d, list):
            return [deserialize_object(x) for x in d]
        return d

    if "ObjectType" not in d:
        # simple dictionary
        new_dict = {}
        for k, v in d.items():
            new_dict[k] = deserialize_object(v)
        return new_dict

    if d["ObjectType"] == "passthrough":
        return deserialize_object(d["Value"])
    else:
        return SERIALIZABLE_OBJECTS[d["ObjectType"]](deserialize_object(d["Value"]))


class AccessibilityAudit(RemoteServer):
    SERVICE_NAME = "com.apple.accessibility.axAuditDaemon.remoteserver"
    RSD_SERVICE_NAME = "com.apple.accessibility.axAuditDaemon.remoteserver.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        service_name = self.SERVICE_NAME if isinstance(lockdown, LockdownClient) else self.RSD_SERVICE_NAME

        super().__init__(
            lockdown,
            service_name,
            remove_ssl_context=True,
            is_developer_service=False,
        )

        self.product_version = Version(lockdown.product_version)
        self._connected = False
        self._initial_messages_to_flush = 2 if self.product_version >= Version("15.0") else 1
        self._initial_messages_flushed = False

    async def _ensure_ready(self) -> None:
        if self._connected:
            return
        await self.connect()
        if not self._initial_messages_flushed:
            for _ in range(self._initial_messages_to_flush):
                try:
                    await asyncio.wait_for(self.recv_plist(), timeout=0.3)
                except asyncio.TimeoutError:
                    break
            self._initial_messages_flushed = True
        self._connected = True

    async def capabilities(self) -> list[str]:
        await self._ensure_ready()
        await self.broadcast.deviceCapabilities()
        return (await self.recv_plist())[0]

    async def run_audit(self, value: list) -> list[AXAuditIssue_v1]:
        await self._ensure_ready()
        if self.product_version >= Version("15.0"):
            await self.broadcast.deviceBeginAuditTypes_(MessageAux().append_obj(value))
        else:
            await self.broadcast.deviceBeginAuditCaseIDs_(MessageAux().append_obj(value))

        while True:
            message = await self.recv_plist()
            if message[1] is None or message[0] != "hostDeviceDidCompleteAuditCategoriesWithAuditIssues:":
                continue
            return deserialize_object(message[1])[0]["value"]

    async def supported_audits_types(self) -> list:
        await self._ensure_ready()
        if self.product_version >= Version("15.0"):
            await self.broadcast.deviceAllSupportedAuditTypes()
        else:
            await self.broadcast.deviceAllAuditCaseIDs()
        return deserialize_object((await self.recv_plist())[0])

    async def settings(self) -> list[AXAuditDeviceSetting_v1]:
        await self._ensure_ready()
        await self.broadcast.deviceAccessibilitySettings()
        return deserialize_object((await self.recv_plist())[0])

    async def perform_handshake(self) -> None:
        # this service acts differently from others, requiring no handshake
        pass

    async def set_app_monitoring_enabled(self, value: bool) -> None:
        await self._ensure_ready()
        await self.broadcast.deviceSetAppMonitoringEnabled_(MessageAux().append_obj(value), expects_reply=False)

    async def set_monitored_event_type(self, event_type: typing.Optional[int] = None) -> None:
        await self._ensure_ready()
        if event_type is None:
            event_type = 0
        await self.broadcast.deviceInspectorSetMonitoredEventType_(
            MessageAux().append_obj(event_type), expects_reply=False
        )

    async def set_show_ignored_elements(self, value: bool) -> None:
        await self._ensure_ready()
        await self.broadcast.deviceInspectorShowIgnoredElements_(
            MessageAux().append_obj(int(value)), expects_reply=False
        )

    async def set_show_visuals(self, value: bool) -> None:
        await self._ensure_ready()
        await self.broadcast.deviceInspectorShowVisuals_(MessageAux().append_obj(int(value)), expects_reply=False)

    async def iter_events(
        self, app_monitoring_enabled=True, monitored_event_type: typing.Optional[int] = None
    ) -> AsyncGenerator[Event, None]:
        await self._ensure_ready()
        await self.set_app_monitoring_enabled(app_monitoring_enabled)
        await self.set_monitored_event_type(monitored_event_type)

        while True:
            message = await self.recv_plist()
            if message[1] is None:
                continue
            data = [x["value"] for x in message[1]]
            yield Event(name=message[0], data=deserialize_object(data))

    async def move_focus_next(self) -> None:
        await self.move_focus(Direction.Next)

    async def perform_press(self, element: bytes) -> None:
        """simulate click (can be used only for processes with task_for_pid-allow"""
        await self._ensure_ready()
        element = {
            "ObjectType": "AXAuditElement_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "PlatformElementValue_v1": {"ObjectType": "passthrough"},
                    "Value": element,
                },
            },
        }

        action = {
            "ObjectType": "AXAuditElementAttribute_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "AttributeNameValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": "AXAction-2010",
                    },
                    "DisplayAsTree_v1": {
                        "ObjectType": "passthrough",
                        "Value": 0,
                    },
                    "HumanReadableNameValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": "Activate",
                    },
                    "IsInternal_v1": {
                        "ObjectType": "passthrough",
                        "Value": 0,
                    },
                    "PerformsActionValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": 1,
                    },
                    "SettableValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": 0,
                    },
                    "ValueTypeValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": 1,
                    },
                },
            },
        }

        await self.broadcast.deviceElement_performAction_withValue_(
            MessageAux().append_obj(element).append_obj(action).append_obj(0), expects_reply=False
        )

    async def move_focus(self, direction: Direction) -> None:
        await self._ensure_ready()
        options = {
            "ObjectType": "passthrough",
            "Value": {
                "allowNonAX": {
                    "ObjectType": "passthrough",
                    "Value": 0,
                },
                "direction": {
                    "ObjectType": "passthrough",
                    "Value": direction.value,
                },
                "includeContainers": {
                    "ObjectType": "passthrough",
                    "Value": 1,
                },
            },
        }

        await self.broadcast.deviceInspectorMoveWithOptions_(MessageAux().append_obj(options), expects_reply=False)

    async def set_setting(self, name: str, value: typing.Any) -> None:
        await self._ensure_ready()
        setting = {
            "ObjectType": "AXAuditDeviceSetting_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "CurrentValueNumber_v1": {"ObjectType": "passthrough", "Value": True},
                    "EnabledValue_v1": {"ObjectType": "passthrough", "Value": True},
                    "IdentiifierValue_v1": {"ObjectType": "passthrough", "Value": name},
                    "SettingTypeValue_v1": {"ObjectType": "passthrough", "Value": 3},
                    "SliderTickMarksValue_v1": {"ObjectType": "passthrough", "Value": 0},
                },
            },
        }
        await self.broadcast.deviceUpdateAccessibilitySetting_withValue_(
            MessageAux().append_obj(setting).append_obj({"ObjectType": "passthrough", "Value": value}),
            expects_reply=False,
        )

    async def reset_settings(self) -> None:
        await self._ensure_ready()
        await self.broadcast.deviceResetToDefaultAccessibilitySettings()

    async def iter_elements(self) -> AsyncGenerator[AXAuditInspectorFocus_v1, None]:
        await self._ensure_ready()
        await self.set_app_monitoring_enabled(True)
        await self.set_monitored_event_type()

        # Every focus change is expected to publish "hostInspectorCurrentElementChanged:".
        await self.move_focus_next()
        visited_identifiers = set()
        consecutive_timeouts = 0

        while True:
            try:
                message = await asyncio.wait_for(self.recv_plist(), timeout=1.0)
                consecutive_timeouts = 0
            except asyncio.TimeoutError as err:
                consecutive_timeouts += 1
                if consecutive_timeouts >= 5:
                    raise TimeoutError("timed out waiting for accessibility focus events") from err
                await self.move_focus_next()
                continue
            if message[1] is None:
                continue
            data = [x["value"] for x in message[1]]
            event = Event(name=message[0], data=deserialize_object(data))
            if event.name != "hostInspectorCurrentElementChanged:":
                # ignore any other events
                continue

            # each such event should contain exactly one element that became in focus
            current_item = event.data[0]
            current_identifier = current_item.platform_identifier

            if current_identifier in visited_identifiers:
                break  # Exit if we've seen this element before (loop detected)

            yield current_item
            visited_identifiers.add(current_identifier)
            await self.move_focus_next()
