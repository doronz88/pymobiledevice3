from pymobiledevice3.services.dvt.tap import Tap


class ActivityTraceTap(Tap):
    IDENTIFIER = 'com.apple.instruments.server.services.activitytracetap'

    def __init__(self, dvt):
        # TODO: reverse [DTOSLogLoader _handleRecord:]

        config = {
            'bm': 0,  # buffer mode
            'combineDataScope': 0,
            'machTimebaseDenom': 3,
            'machTimebaseNumer': 125,
            'onlySignposts': 0,
            'pidToInjectCombineDYLIB': "-1",
            'predicate': "(messageType == info OR messageType == debug OR messageType == default OR "
                         "messageType == error OR messageType == fault)",
            'signpostsAndLogs': 1,
            'targetPID': "-3",
            'trackExpiredPIDs': 1,
            'ur': 500,
        }

        super().__init__(dvt, self.IDENTIFIER, config)
