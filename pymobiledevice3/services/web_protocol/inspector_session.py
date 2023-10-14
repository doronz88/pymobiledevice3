import asyncio
import json
import logging
from collections import UserDict
from typing import List, Mapping, Optional

from pymobiledevice3.exceptions import InspectorEvaluateError
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol

logger = logging.getLogger(__name__)
console_logger = logging.getLogger('webinspector.console')
heap_logger = logging.getLogger('webinspector.heap')

webinspector_logger_handlers = {
    'log': console_logger.info,
    'info': console_logger.info,
    'error': console_logger.error,
    'debug': console_logger.debug,
    'warning': console_logger.warning,
}


class JSObjectPreview(UserDict):
    def __init__(self, properties: List[Mapping]):
        super().__init__()
        for p in properties:
            name = p['name']
            value = p['value']
            self.data[name] = value


class JSObjectProperties(UserDict):
    def __init__(self, properties: List[Mapping]):
        super().__init__()
        for p in properties:
            name = p['name']
            if name == '__proto__':
                self.class_name = p['value']['className']
                continue
            # test if a getter/setter first
            value = p.get('get', p.get('set', p.get('value')))
            if value is None:
                continue
            preview = value.get('preview')
            if preview is not None:
                value = JSObjectPreview(preview['properties'])
            elif value.get('className') == 'Function':
                value = value['description']
            else:
                value = value.get('value')
            self.data[name] = value


class InspectorSession:

    def __init__(self, protocol: SessionProtocol, target_id: Optional[str] = None):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        self.protocol = protocol
        self.target_id = target_id
        self.message_id = 1
        self._last_console_message = {}
        self._dispatch_message_responses = {}

        self.response_methods = {
            'Target.targetCreated': self._target_created,
            'Target.targetDestroyed': self._target_destroyed,
            'Target.dispatchMessageFromTarget': self._target_dispatch_message_from_target,
            'Target.didCommitProvisionalTarget': self._target_did_commit_provisional_target,
            'Console.messageAdded': self._console_message_added,
            'Console.messagesCleared': lambda _: _,
            'Console.messageRepeatCountUpdated': self._console_message_repeated_count_updated,
            'Heap.garbageCollected': self._heap_garbage_collected,
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

    async def heap_gc(self):
        return await self.send_command('Heap.gc')

    async def heap_snapshot(self):
        snapshot = await self.send_command('Heap.snapshot')
        if self.target_id is not None:
            snapshot = json.loads(snapshot['params']['message'])
        snapshot = json.loads(snapshot)['result']['snapshotData']
        return snapshot

    async def heap_enable(self):
        return await self.send_command('Heap.enable')

    async def console_enable(self):
        return await self.send_command('Console.enable')

    async def runtime_enable(self):
        return await self.send_command('Runtime.enable')

    async def send_command(self, method: str, **kwargs):
        if self.target_id is None:
            return await self.protocol.send_receive(method, **kwargs)
        else:
            return await self.send_and_receive({'method': method, 'params': kwargs})

    async def runtime_evaluate(self, exp: str, return_by_value: bool = False):
        # if the expression is dict, it's needed to be in ()
        exp = exp.strip()
        if exp:
            if exp[0] == '{' and exp[-1] == '}':
                exp = f'({exp})'

        response = await self.send_and_receive({'method': 'Runtime.evaluate',
                                                'params': {
                                                    'expression': exp,
                                                    'objectGroup': 'console',
                                                    'includeCommandLineAPI': True,
                                                    'doNotPauseOnExceptionsAndMuteConsole': False,
                                                    'silent': False,
                                                    'returnByValue': return_by_value,
                                                    'generatePreview': True,
                                                    'userGesture': True,
                                                    'awaitPromise': False,
                                                    'replMode': True,
                                                    'allowUnsafeEvalBlockedByCSP': False,
                                                    'uniqueContextId': '0.1'}
                                                })

        return await self._parse_runtime_evaluate(response)

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
                logger.error(f'Unknown response: {response}')

    async def receive_response_by_id(self, message_id: int) -> Mapping:
        while True:
            if message_id in self._dispatch_message_responses:
                return self._dispatch_message_responses.pop(message_id)
            await asyncio.sleep(0)

    async def get_properties(self, object_id: str) -> JSObjectProperties:
        message = await self.send_command(
            'Runtime.getProperties', objectId=object_id, ownProperties=True, generatePreview=True)
        if self.target_id is not None:
            message = json.loads(message['params']['message'])['result']
        return JSObjectProperties(message['properties'])

    async def _parse_runtime_evaluate(self, response: Mapping):
        if self.target_id is None:
            message = response
        else:
            message = json.loads(response['params']['message'])
        result = message['result']['result']
        if result.get('subtype', '') == 'error':
            properties = await self.get_properties(result['objectId'])
            raise InspectorEvaluateError(properties.class_name, properties['message'], properties.get('line'),
                                         properties.get('column'), properties.get('stack', '').split('\n'))
        elif result['type'] == 'bigint':
            return result['description']
        elif result['type'] == 'undefined':
            pass
        elif result['type'] == 'object':
            value = result.get('value')
            if value is not None:
                return value

            # TODO: JSObjectProperties()
            preview = result['preview']
            preview_buf = '{\n'
            for p in result['preview']['properties']:
                value = p.get('value', 'NOT_SUPPORTED_FOR_PREVIEW')
                preview_buf += f'\t{p["name"]}: {value}, // {p["type"]}\n'
            if preview.get('overflow'):
                preview_buf += '\t// ...\n'
            preview_buf += '}'
            return f'[object {result["className"]}]\n{preview_buf}'
        elif result['type'] == 'function':
            return result['description']
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

    def _console_message_added(self, message: Mapping):
        log_level = message['params']['message']['level']
        text = message['params']['message']['text']
        self._last_console_message = message
        webinspector_logger_handlers[log_level](text)

    def _console_message_repeated_count_updated(self, message: Mapping):
        self._console_message_added(self._last_console_message)

    def _heap_garbage_collected(self, message: Mapping):
        heap_logger.debug(message['params'])

    def _target_created(self, response: Mapping):
        pass

    def _target_destroyed(self, response: Mapping):
        pass

    def _target_did_commit_provisional_target(self, response: Mapping):
        self.set_target_id(response['params']['newTargetId'])
