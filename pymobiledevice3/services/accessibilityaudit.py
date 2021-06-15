from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.remote_server import RemoteServer, MessageAux


class AccessibilityAudit(RemoteServer):
    SERVICE_NAME = 'com.apple.accessibility.axAuditDaemon.remoteserver'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, remove_ssl_context=True)

    def recv_plist(self, **kwargs):
        plist = super().recv_plist()

        while plist[1] is not None:
            # skip notifications
            plist = super().recv_plist()
        return plist

    def device_capabilities(self):
        self.broadcast.deviceCapabilities()
        return self.recv_plist()[0]

    def get_current_settings(self):
        self.broadcast.deviceAccessibilitySettings()
        return self.recv_plist()[0]

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
        self.recv_plist()
