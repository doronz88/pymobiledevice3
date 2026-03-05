from pymobiledevice3.services.remote_server import MessageAux


class Notifications:
    IDENTIFIER = "com.apple.instruments.server.services.mobilenotifications"

    def __init__(self, dvt):
        self._dvt = dvt
        self._channel = None

    async def __aenter__(self):
        self._channel = await self._dvt.make_channel(self.IDENTIFIER)
        await self._channel.setApplicationStateNotificationsEnabled_(MessageAux().append_obj(True))
        await self._channel.setMemoryNotificationsEnabled_(MessageAux().append_obj(True))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._channel.setApplicationStateNotificationsEnabled_(MessageAux().append_obj(False))
        await self._channel.setMemoryNotificationsEnabled_(MessageAux().append_obj(False))

    async def __aiter__(self):
        while True:
            yield await self._dvt.recv_plist(self._channel)
