class Screenshot:
    IDENTIFIER = 'com.apple.instruments.server.services.screenshot'

    def __init__(self, dvt):
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def get_screenshot(self) -> bytes:
        """ get device screenshot """
        self._channel.takeScreenshot(expects_reply=True)
        return self._channel.receive_plist()
