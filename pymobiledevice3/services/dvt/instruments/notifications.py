from pymobiledevice3.services.remote_server import MessageAux


class Notifications:
    IDENTIFIER = "com.apple.instruments.server.services.mobilenotifications"

    def __init__(self, dvt):
        self._dvt = dvt
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def __enter__(self):
        self._channel.setApplicationStateNotificationsEnabled_(MessageAux().append_obj(True))
        self._channel.setMemoryNotificationsEnabled_(MessageAux().append_obj(True))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._channel.setApplicationStateNotificationsEnabled_(MessageAux().append_obj(False))
        self._channel.setMemoryNotificationsEnabled_(MessageAux().append_obj(False))

    def __iter__(self):
        while True:
            yield self._dvt.recv_plist(self._channel)
