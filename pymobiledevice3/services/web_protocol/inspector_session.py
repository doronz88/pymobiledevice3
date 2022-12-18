import asyncio
import json
import logging
from typing import Mapping

from pymobiledevice3.exceptions import InspectorEvaluateError
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol

logger = logging.getLogger(__name__)


class InspectorSession:

    def __init__(self, protocol: SessionProtocol, target_id: str):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        self.protocol = protocol
        self.target_id = target_id
        self.message_id = 1
        self._responses_cache = {}

    @classmethod
    async def create(cls, protocol: SessionProtocol):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        await protocol.inspector.setup_inspector_socket(protocol.id_, protocol.app.id_, protocol.page.id_)
        while not protocol.inspector.wir_events:
            await asyncio.sleep(0)
        created = protocol.inspector.wir_events.pop(0)
        while 'targetInfo' not in created['params']:
            created = protocol.inspector.wir_events.pop(0)
        target_id = created['params']['targetInfo']['targetId']
        logger.info(f'Created: {target_id}')
        target = cls(protocol, target_id)
        return target

    async def runtime_enable(self):
        await self.send_and_receive({'method': 'Runtime.enable', 'params': {}})

    async def runtime_evaluate(self, exp: str):
        response = await self.send_and_receive({'method': 'Runtime.evaluate',
                                                'params': {
                                                    'expression': exp,
                                                    'objectGroup': 'console',
                                                    'includeCommandLineAPI': True,
                                                    'silent': False,
                                                    'returnByValue': False,
                                                    'generatePreview': True,
                                                    'userGesture': True,
                                                    'awaitPromise': False,
                                                    'replMode': True,
                                                    'allowUnsafeEvalBlockedByCSP': False,
                                                    'uniqueContextId': '0.1'}
                                                })

        result = json.loads(response['params']['message'])['result']['result']
        if result.get('subtype', '') == 'error':
            details = result['description']
            logger.error(details)
            raise InspectorEvaluateError(details)
        elif result['type'] == 'undefined':
            pass
        else:
            try:
                return result['value']
            except KeyError as e:
                error_message = 'Message is not supported'
                logger.error(error_message)
                raise NotImplementedError(error_message) from e

    async def send_and_receive(self, message: Mapping) -> Mapping:
        message_id = await self.send_message_to_target(message)
        return await self.receive_message(message_id)

    async def send_message_to_target(self, message: Mapping) -> int:
        message['id'] = self.message_id
        self.message_id += 1
        await self.protocol.send_command('Target.sendMessageToTarget', targetId=self.target_id,
                                         message=json.dumps(message))
        return message['id']

    async def receive_message(self, message_id: int) -> Mapping:
        while True:
            if message_id in self._responses_cache:
                return self._responses_cache.pop(message_id)

            while not self.protocol.inspector.wir_events:
                await asyncio.sleep(0)

            response = self.protocol.inspector.wir_events.pop(0)
            message = json.loads(response['params'].get('message', '{}'))

            receive_message_id = message.get('id', None)
            if receive_message_id == message_id:
                return response

            self._responses_cache[receive_message_id] = response
