import logging

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.services.remote_server import MessageAux


class ConditionInducer:
    IDENTIFIER = 'com.apple.instruments.server.services.ConditionInducer'

    def __init__(self, dvt):
        self.logger = logging.getLogger(__name__)
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def list(self) -> list:
        self._channel.availableConditionInducers()
        return self._channel.receive_plist()

    def set(self, profile_identifier):
        for group in self.list():
            for profile in group.get('profiles'):
                if profile_identifier == profile.get('identifier'):
                    self.logger.info(profile.get('description'))
                    self._channel.enableConditionWithIdentifier_profileIdentifier_(
                        MessageAux().append_obj(group.get('identifier')).append_obj(profile.get('identifier')))
                    return
        raise PyMobileDevice3Exception('Invalid profile identifier')

    def clear(self):
        self._channel.disableActiveCondition()
