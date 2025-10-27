from pymobiledevice3.services.remote_server import MessageAux


class Graphics:
    IDENTIFIER = "com.apple.instruments.server.services.graphics.opengl"

    def __init__(self, dvt):
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def __enter__(self):
        self._channel.startSamplingAtTimeInterval_(MessageAux().append_obj(0.0))
        self._channel.receive_plist()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._channel.stopSampling()

    def __iter__(self):
        while True:
            yield self._channel.receive_plist()
