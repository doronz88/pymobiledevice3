from pymobiledevice3.services.dvt.structs import MessageAux


class EnergyMonitor:
    IDENTIFIER = 'com.apple.xcode.debug-gauge-data-providers.Energy'

    def __init__(self, dvt, pid_list: list):
        self._channel = dvt.make_channel(self.IDENTIFIER)
        self._pid_list = pid_list

    def __enter__(self):
        # stop monitoring if already monitored
        self._channel.stopSamplingForPIDs_(MessageAux().append_obj(self._pid_list))

        self._channel.startSamplingForPIDs_(MessageAux().append_obj(self._pid_list))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._channel.stopSamplingForPIDs_(MessageAux().append_obj(self._pid_list))

    def __iter__(self):
        while True:
            self._channel.sampleAttributes_forPIDs_(MessageAux().append_obj({}).append_obj(self._pid_list))
            yield self._channel.receive_plist()
