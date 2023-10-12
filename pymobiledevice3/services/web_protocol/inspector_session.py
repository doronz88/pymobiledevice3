import asyncio
import json
import logging
from typing import Mapping, Optional

from pymobiledevice3.exceptions import InspectorEvaluateError
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol

logger = logging.getLogger(__name__)
webinspector_logger = logging.getLogger('webinspector.console')

webinspector_logger_handlers = {
    'info': webinspector_logger.info,
    'error': webinspector_logger.error,
    'debug': webinspector_logger.debug,
    'warning': webinspector_logger.warning,
}


class InspectorSession:

    def __init__(self, protocol: SessionProtocol, target_id: Optional[str] = None):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        self.protocol = protocol
        self.target_id = target_id
        self.message_id = 1
        self._dispatch_message_responses = {}

        self.response_methods = {
            'Target.targetCreated': self._target_created,
            'Target.targetDestroyed': self._target_destroyed,
            'Target.dispatchMessageFromTarget': self._target_dispatch_message_from_target,
            'Target.didCommitProvisionalTarget': self._target_did_commit_provisional_target,
            'Console.messageAdded': self._console_message_added,
        }

        self._receive_task = asyncio.create_task(self._receive_loop())

    @classmethod
    async def create(cls, protocol: SessionProtocol, wait_target: bool = True):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        :param bool wait_target: Wait for target. If not, all operations won't have a window context to operate in
        """
        await protocol.inspector.setup_inspector_socket(protocol.id_, protocol.app.id_, protocol.page.id_)
        target_id = None
        if wait_target:
            while not protocol.inspector.wir_events:
                await asyncio.sleep(0)
            created = protocol.inspector.wir_events.pop(0)
            while 'targetInfo' not in created['params']:
                created = protocol.inspector.wir_events.pop(0)
            target_id = created['params']['targetInfo']['targetId']
            logger.info(f'Created: {target_id}')
        target = cls(protocol, target_id)
        return target

    def set_target_id(self, target_id):
        self.target_id = target_id
        logger.info(f'Changed to: {target_id}')

    async def console_enable(self):
        await self.send_command('Console.enable')

    async def runtime_enable(self):
        await self.send_command('Runtime.enable')

    async def send_command(self, method: str, **kwargs):
        if self.target_id is None:
            await self.protocol.send_command(method, **kwargs)
        else:
            await self.send_and_receive({'method': method, 'params': kwargs})

    async def runtime_evaluate(self, exp: str):
        # if the expression is dict, it's needed to be in ()
        exp = exp.strip()
        if exp:
            if exp[0] == '{' and exp[-1] == '}':
                exp = f'({exp})'

        response = await self.send_and_receive({'method': 'Runtime.evaluate',
                                                'params': {
                                                    'expression': f'\n'
                                                                  f'//# sourceURL=__WebInspectorConsoleEvaluation__\n'
                                                                  f'{exp}',
                                                    'objectGroup': 'console',
                                                    'includeCommandLineAPI': True,
                                                    'doNotPauseOnExceptionsAndMuteConsole': False,
                                                    'silent': False,
                                                    'returnByValue': False,
                                                    'generatePreview': False,
                                                    'userGesture': True,
                                                    'awaitPromise': False,
                                                    'replMode': True,
                                                    'allowUnsafeEvalBlockedByCSP': False,
                                                    'uniqueContextId': '0.1'}
                                                })

        return self._parse_runtime_evaluate(response)

    async def navigate_to_url(self, url: str):
        return await self.runtime_evaluate(exp=f'window.location = "{url}"')

    async def send_and_receive(self, message: Mapping) -> Mapping:
        if self.target_id is None:
            message_id = await self.protocol.send_command(message['method'], **message.get('params', {}))
            return await self.protocol.wait_for_message(message_id)
        else:
            message_id = await self.send_message_to_target(message)
            return await self.receive_response_by_id(message_id)

    async def send_message_to_target(self, message: Mapping) -> int:
        message['id'] = self.message_id
        self.message_id += 1
        await self.protocol.send_command('Target.sendMessageToTarget', targetId=self.target_id,
                                         message=json.dumps(message))
        return message['id']

    async def _receive_loop(self):
        while True:
            while not self.protocol.inspector.wir_events:
                await asyncio.sleep(0)

            response = self.protocol.inspector.wir_events.pop(0)
            response_method = response['method']
            if response_method in self.response_methods:
                self.response_methods[response_method](response)
            else:
                logger.error('Unknown response method')

    async def receive_response_by_id(self, message_id: int) -> Mapping:
        while True:
            if message_id in self._dispatch_message_responses:
                return self._dispatch_message_responses.pop(message_id)
            await asyncio.sleep(0)

    def _parse_runtime_evaluate(self, response: Mapping):
        if self.target_id is None:
            message = response
        else:
            message = json.loads(response['params']['message'])
        if 'error' in message:
            details = message['error']['message']
            logger.error(details)
            raise InspectorEvaluateError(details)

        result = message['result']['result']
        if result.get('subtype', '') == 'error':
            details = result['description']
            logger.error(details)
            raise InspectorEvaluateError(details)
        elif result['type'] == 'bigint':
            return result['description']
        elif result['type'] == 'undefined':
            pass
        elif result['type'] == 'object':
            return f'[object {result["className"]}]'
        else:
            return result['value']

    # response methods
    def _target_dispatch_message_from_target(self, response: Mapping):
        target_message = json.loads(response['params']['message'])
        receive_message_id = target_message.get('id')
        if receive_message_id is None:
            self._missing_id_in_message(target_message)
            return
        self._dispatch_message_responses[receive_message_id] = response

    def _missing_id_in_message(self, message: Mapping):
        handler = self.response_methods.get(message['method'])
        if handler is not None:
            handler(message)
        else:
            logger.critical(f'unhandled message: {message}')

    @staticmethod
    def _console_message_added(message: Mapping):
        log_level = message['params']['message']['level']
        text = message['params']['message']['text']
        webinspector_logger_handlers[log_level](text)

    def _target_created(self, response: Mapping):
        pass

    def _target_destroyed(self, response: Mapping):
        pass

    def _target_did_commit_provisional_target(self, response: Mapping):
        self.set_target_id(response['params']['newTargetId'])
