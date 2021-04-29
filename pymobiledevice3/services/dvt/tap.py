from pymobiledevice3.services.dvt.structs import MessageAux


class Tap:
    def __init__(self, dvt, channel_name: str, config: dict):
        self._dvt = dvt
        self._channel_name = channel_name
        self._channel = None
        self._config = config

    def __enter__(self):
        self._channel = self._dvt.make_channel(self._channel_name)
        self._channel.setConfig_(MessageAux().append_obj(self._config), expects_reply=False)
        self._channel.start(expects_reply=False)

        # first message is just kind of an ack
        self._channel.receive_plist()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._channel.stop(expects_reply=False)

    def __iter__(self):
        while True:
            for result in self._channel.receive_plist():
                yield result
