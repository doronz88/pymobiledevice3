import typing

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.remote_server import RemoteServer, MessageAux


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

    def __str__(self):
        return f'<AXAuditDeviceSetting_v1 {self._fields["IdentiifierValue_v1"]} = ' \
               f'{self._fields["CurrentValueNumber_v1"]}>'


SERIALIZABLE_OBJECTS = {
    'AXAuditDeviceSetting_v1': AXAuditDeviceSetting_v1,
    'AXAuditInspectorFocus_v1': AXAuditInspectorFocus_v1,
    'AXAuditElement_v1': AXAuditElement_v1,
    'AXAuditInspectorSection_v1': AXAuditInspectorSection_v1,
    'AXAuditElementAttribute_v1': AXAuditElementAttribute_v1,
}

DIRECTION_PREV = 3
DIRECTION_NEXT = 4
DIRECTION_FIRST = 5
DIRECTION_LAST = 6


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

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, remove_ssl_context=True)

        self.broadcast.deviceSetAppMonitoringEnabled_(MessageAux().append_obj(True))
        self.recv_response()

        self.broadcast.deviceInspectorSetMonitoredEventType_(MessageAux().append_obj(0))
        self.recv_response()

        self.broadcast.deviceInspectorShowVisuals_(MessageAux().append_obj(1))
        self.recv_response()

        self.broadcast.deviceInspectorShowIgnoredElements_(MessageAux().append_obj(1))
        self.recv_response()

    def iter_notifications(self):
        while True:
            notification = self.recv_plist()
            if notification[1] is None:
                continue
            data = [x['value'] for x in notification[1]]
            yield notification[0], deserialize_object(data)

    def recv_response(self):
        plist = self.recv_plist()

        while plist[1] is not None:
            # skip notifications, but report them if exists
            yield plist[0], deserialize_object(plist[1])

            plist = self.recv_plist()

        return plist

    def device_capabilities(self):
        self.broadcast.deviceCapabilities()
        return self.recv_response()[0]

    def get_current_settings(self):
        self.broadcast.deviceAccessibilitySettings()
        return deserialize_object(self.recv_response()[0])

    def move_focus_next(self):
        self.move_focus(DIRECTION_NEXT)

    def perform_press(self, element: bytes):
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
            MessageAux().append_obj(element).append_obj(action).append_obj(0))
        self.recv_response()

    def move_focus(self, direction):
        options = {
            'ObjectType': 'passthrough',
            'Value': {
                'allowNonAX': {
                    'ObjectType': 'passthrough',
                    'Value': 0,
                },
                'direction': {
                    'ObjectType': 'passthrough',
                    'Value': direction,
                },
                'includeContainers': {
                    'ObjectType': 'passthrough',
                    'Value': 1,
                }
            }
        }

        self.broadcast.deviceInspectorMoveWithOptions_(MessageAux().append_obj(options))
        self.recv_response()

    def set_setting(self, name, value):
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
            MessageAux().append_obj(setting).append_obj({'ObjectType': 'passthrough', 'Value': value}))
        self.recv_response()
