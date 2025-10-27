from pymobiledevice3.services.remote_server import MessageAux


class ApplicationListing:
    IDENTIFIER = "com.apple.instruments.server.services.device.applictionListing"

    def __init__(self, dvt):
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def applist(self) -> list:
        """
        Get the applications list from the device.
        :return: List of applications and their attributes.
        """
        self._channel.installedApplicationsMatching_registerUpdateToken_(MessageAux().append_obj({}).append_obj(""))
        result = self._channel.receive_plist()
        assert isinstance(result, list)
        return result
