import typing
from dataclasses import dataclass
from enum import Enum

from packaging.version import Version

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.remote_server import MessageAux, RemoteServer


class SerializedObject:
    def __init__(self, fields: typing.Mapping):
        self._fields = fields


class AXAuditInspectorFocus_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)

    @property
    def caption(self) -> str:
        return self._fields.get('CaptionTextValue_v1')

    @property
    def element(self) -> bytes:
        return self._fields.get('ElementValue_v1')

    def __str__(self):
        return f'<Focused ElementCaption: {self.caption}>'


class AXAuditElement_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)

    @property
    def identifier(self) -> bytes:
        return self._fields['PlatformElementValue_v1'].NSdata

    def __repr__(self):
        return f'<Element: {self.identifier}>'


class AXAuditInspectorSection_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)


class AXAuditElementAttribute_v1(SerializedObject):
    def __init__(self, fields):
        super().__init__(fields)


class AXAuditDeviceSetting_v1(SerializedObject):
    FIELDS = ('IdentiifierValue_v1', 'CurrentValueNumber_v1')

    def __init__(self, fields):
        super().__init__(fields)
        for k in self.FIELDS:
            if k not in self._fields:
                self._fields[k] = None

    @property
    def key(self) -> str:
        return self._fields['IdentiifierValue_v1']

    @property
    def value(self) -> typing.Any:
        return self._fields['CurrentValueNumber_v1']

    def __str__(self) -> str:
        return f'<AXAuditDeviceSetting_v1 {self.key} = {self.value}>'


SERIALIZABLE_OBJECTS = {
    'AXAuditDeviceSetting_v1': AXAuditDeviceSetting_v1,
    'AXAuditInspectorFocus_v1': AXAuditInspectorFocus_v1,
    'AXAuditElement_v1': AXAuditElement_v1,
    'AXAuditInspectorSection_v1': AXAuditInspectorSection_v1,
    'AXAuditElementAttribute_v1': AXAuditElementAttribute_v1,
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

    if 'ObjectType' not in d:
        # simple dictionary
        new_dict = {}
        for k, v in d.items():
            new_dict[k] = deserialize_object(v)
        return new_dict

    if d['ObjectType'] == 'passthrough':
        return deserialize_object(d['Value'])
    else:
        return SERIALIZABLE_OBJECTS[d['ObjectType']](deserialize_object(d['Value']))


class AccessibilityAudit(RemoteServer):
    SERVICE_NAME = 'com.apple.accessibility.axAuditDaemon.remoteserver'
    RSD_SERVICE_NAME = 'com.apple.accessibility.axAuditDaemon.remoteserver.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME, remove_ssl_context=True, is_developer_service=False)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME, remove_ssl_context=True, is_developer_service=False)

        # flush previously received messages
        self.recv_plist()
        if Version(lockdown.product_version) >= Version('15.0'):
            self.recv_plist()

    @property
    def capabilities(self) -> typing.List[str]:
        self.broadcast.deviceCapabilities()
        return self.recv_plist()[0]

    @property
    def settings(self) -> typing.List[AXAuditDeviceSetting_v1]:
        self.broadcast.deviceAccessibilitySettings()
        return deserialize_object(self.recv_plist()[0])

    def perform_handshake(self) -> None:
        # this service acts differently from others, requiring no handshake
        pass

    def set_app_monitoring_enabled(self, value: bool) -> None:
        self.broadcast.deviceSetAppMonitoringEnabled_(MessageAux().append_obj(value), expects_reply=False)

    def set_monitored_event_type(self, event_type: int = None) -> None:
        if event_type is None:
            event_type = 0
        self.broadcast.deviceInspectorSetMonitoredEventType_(MessageAux().append_obj(event_type), expects_reply=False)

    def set_show_ignored_elements(self, value: bool) -> None:
        self.broadcast.deviceInspectorShowIgnoredElements_(MessageAux().append_obj(int(value)), expects_reply=False)

    def set_show_visuals(self, value: bool) -> None:
        self.broadcast.deviceInspectorShowVisuals_(MessageAux().append_obj(int(value)), expects_reply=False)

    def iter_events(self, app_monitoring_enabled=True, monitored_event_type: int = None) -> \
            typing.Generator[Event, None, None]:

        self.set_app_monitoring_enabled(app_monitoring_enabled)
        self.set_monitored_event_type(monitored_event_type)

        while True:
            message = self.recv_plist()
            if message[1] is None:
                continue
            data = [x['value'] for x in message[1]]
            yield Event(name=message[0], data=deserialize_object(data))

    def move_focus_next(self) -> None:
        self.move_focus(Direction.Next)

    def perform_press(self, element: bytes) -> None:
        """ simulate click (can be used only for processes with task_for_pid-allow """
        element = {
            'ObjectType': 'AXAuditElement_v1',
            'Value': {
                'ObjectType': 'passthrough',
                'Value': {
                    'PlatformElementValue_v1': {
                        'ObjectType': 'passthrough'
                    },
                    'Value': element,
                }
            }
        }

        action = {
            'ObjectType': 'AXAuditElementAttribute_v1',
            'Value': {
                'ObjectType': 'passthrough',
                'Value': {
                    'AttributeNameValue_v1': {
                        'ObjectType': 'passthrough',
                        'Value': 'AXAction-2010',
                    },
                    'DisplayAsTree_v1': {
                        'ObjectType': 'passthrough',
                        'Value': 0,
                    },
                    'HumanReadableNameValue_v1': {
                        'ObjectType': 'passthrough',
                        'Value': 'Activate',
                    },
                    'IsInternal_v1': {
                        'ObjectType': 'passthrough',
                        'Value': 0,
                    },
                    'PerformsActionValue_v1': {
                        'ObjectType': 'passthrough',
                        'Value': 1,
                    },
                    'SettableValue_v1': {
                        'ObjectType': 'passthrough',
                        'Value': 0,
                    },
                    'ValueTypeValue_v1': {
                        'ObjectType': 'passthrough',
                        'Value': 1,
                    },
                }
            }
        }

        self.broadcast.deviceElement_performAction_withValue_(
            MessageAux().append_obj(element).append_obj(action).append_obj(0), expects_reply=False)

    def move_focus(self, direction: Direction) -> None:
        options = {
            'ObjectType': 'passthrough',
            'Value': {
                'allowNonAX': {
                    'ObjectType': 'passthrough',
                    'Value': 0,
                },
                'direction': {
                    'ObjectType': 'passthrough',
                    'Value': direction.value,
                },
                'includeContainers': {
                    'ObjectType': 'passthrough',
                    'Value': 1,
                }
            }
        }

        self.broadcast.deviceInspectorMoveWithOptions_(MessageAux().append_obj(options), expects_reply=False)

    def set_setting(self, name: str, value: typing.Any) -> None:
        setting = {'ObjectType': 'AXAuditDeviceSetting_v1',
                   'Value': {'ObjectType': 'passthrough',
                             'Value': {'CurrentValueNumber_v1': {'ObjectType': 'passthrough',
                                                                 'Value': True},
                                       'EnabledValue_v1': {'ObjectType': 'passthrough', 'Value': True},
                                       'IdentiifierValue_v1': {'ObjectType': 'passthrough',
                                                               'Value': name},
                                       'SettingTypeValue_v1': {'ObjectType': 'passthrough', 'Value': 3},
                                       'SliderTickMarksValue_v1': {'ObjectType': 'passthrough', 'Value': 0}}}}
        self.broadcast.deviceUpdateAccessibilitySetting_withValue_(
            MessageAux().append_obj(setting).append_obj({'ObjectType': 'passthrough', 'Value': value}),
            expects_reply=False)
