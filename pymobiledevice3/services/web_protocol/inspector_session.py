import asyncio
import json
import logging
from ast import literal_eval
from typing import Mapping, List, Union

from pymobiledevice3.exceptions import InspectorEvaluateError
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol

logger = logging.getLogger(__name__)


class JsStr:

    def __init__(self, string: str):
        self.string = string

    def __repr__(self):
        return f'"{self.string}"'


class JsDictKey:

    def __init__(self, object):
        self.object = object

    def __repr__(self):
        return str(self.object)


class InspectorSession:
    __ERROR_SUPPORT_MESSAGE = 'Message is not supported'

    def __init__(self, protocol: SessionProtocol, target_id: str):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        self.protocol = protocol
        self.target_id = target_id
        self.message_id = 1
        self._dispatch_message_responses = {}

        self.remote_object_types = {
            'object': self._parse_object,
            'function': self._parse_undefined,
            'undefined': self._parse_undefined,
            'string': self._parse_string,
            'number': self._parse_int,
            'boolean': self._parse_boolean,
        }

        asyncio.create_task(self._receive_loop())

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
        # if the expression is dict, it's needed to be in ()
        try:
            json_exp = literal_eval(exp)
            if isinstance(json_exp, dict):
                exp = f'({exp})'
        except Exception:
            pass

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

        return self._parse_target_dispatch_message(response)

    async def send_and_receive(self, message: Mapping) -> Mapping:
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
            if response_method == 'Target.dispatchMessageFromTarget':
                self._target_dispatch_message_from_target(response)
            else:
                logger.error(self.__ERROR_SUPPORT_MESSAGE, response)
                raise RuntimeError(self.__ERROR_SUPPORT_MESSAGE)

    async def receive_response_by_id(self, message_id: int) -> Mapping:
        while True:
            if message_id in self._dispatch_message_responses:
                return self._dispatch_message_responses.pop(message_id)
            await asyncio.sleep(0)

    def _target_dispatch_message_from_target(self, response: Mapping):
        receive_message_id = json.loads(response['params']['message'])['id']
        self._dispatch_message_responses[receive_message_id] = response

    # -- PARSE OBJECTS
    def _parse_target_dispatch_message(self, response: Mapping):
        result = json.loads(response['params']['message'])['result']['result']

        if result.get('subtype', '') == 'error':
            details = result['description']
            logger.error(details)
            raise InspectorEvaluateError(details)
        elif result['type'] == 'undefined':
            pass
        else:
            return self.remote_object_types[result['type']](result)

    @staticmethod
    def _parse_string(result: Mapping) -> JsStr:
        return JsStr(result['value'])

    @staticmethod
    def _parse_int(result: Mapping) -> int:
        return int(result['value'])

    @staticmethod
    def _parse_boolean(result: Mapping) -> str:
        value = result['value']
        if value:
            return 'true'
        else:
            return 'false'

    @staticmethod
    def _parse_undefined(result: Mapping) -> None:
        pass

    def _parse_object(self, result: Mapping) -> Union[List, Mapping]:
        if result.get('subtype', '') == 'array':
            return self._parse_array(result)

        result_class_name = result.get('className', '')
        if result_class_name == 'Object' or not result_class_name:
            return self._parse_dict(result)
        else:
            logger.error(self.__ERROR_SUPPORT_MESSAGE)
            raise NotImplementedError(self.__ERROR_SUPPORT_MESSAGE)

    def _get_object_preview(self, result: Mapping) -> Mapping:
        if result.get('preview', False):
            return result.get('preview')
        elif result.get('valuePreview', False):
            return result.get('valuePreview')
        else:
            logger.error(self.__ERROR_SUPPORT_MESSAGE)
            raise NotImplementedError(self.__ERROR_SUPPORT_MESSAGE)

    def _parse_dict(self, result: Mapping) -> Mapping:
        preview = self._get_object_preview(result)
        result_dict = {}
        for entry in preview['properties']:
            result_dict[JsDictKey(entry['name'])] = self.remote_object_types[entry['type']](entry)
        return result_dict

    def _parse_array(self, result: Mapping) -> List:
        preview = self._get_object_preview(result)
        result_array = []
        for entry in preview['properties']:
            result_array.append(self.remote_object_types[entry['type']](entry))
        return result_array
