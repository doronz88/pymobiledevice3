import asyncio
import json
import logging
from collections import UserDict
from typing import Any, Callable, Optional, cast

from pymobiledevice3.exceptions import InspectorEvaluateError
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol

logger = logging.getLogger(__name__)
console_logger = logging.getLogger("webinspector.console")
# console history replayed by the page on attach, distinguishable (and silenceable) by logger name
console_replay_logger = logging.getLogger("webinspector.console.replay")
heap_logger = logging.getLogger("webinspector.heap")


def _console_logger_handlers(console: logging.Logger) -> "dict[str, Callable[[str], None]]":
    return {
        "log": console.info,
        "info": console.info,
        "error": console.error,
        "debug": console.debug,
        "warning": console.warning,
    }


webinspector_logger_handlers = _console_logger_handlers(console_logger)
webinspector_replay_logger_handlers = _console_logger_handlers(console_replay_logger)


_MAX_PROPERTY_VALUE_LENGTH = 80


def _shorten(text: str) -> str:
    first_line, *rest = text.split("\n", 1)
    shortened = first_line[:_MAX_PROPERTY_VALUE_LENGTH]
    if rest or len(first_line) > _MAX_PROPERTY_VALUE_LENGTH:
        shortened += "…"
    return shortened


def _shorten_remote_object(remote_object: dict[str, Any]) -> str:
    """One-line, JS-style rendering of a RemoteObject property value."""
    if remote_object.get("type") == "string":
        return _shorten(json.dumps(remote_object["value"]))
    if remote_object.get("type") == "function":
        return "ƒ"
    if remote_object.get("subtype") == "null":
        return "null"
    if remote_object.get("type") == "object":
        return remote_object.get("className") or remote_object.get("description") or "Object"
    if "description" in remote_object:
        return _shorten(remote_object["description"])
    if "value" in remote_object:
        # json.dumps renders JS-style primitives (true/false) rather than Python's
        return json.dumps(remote_object["value"])
    return remote_object.get("type", "")


class JSObjectPreview(UserDict[str, Any]):
    def __init__(self, properties: list[dict[str, Any]]):
        super().__init__()
        for p in properties:
            name = p["name"]
            value = p["value"]
            self.data[name] = value


class JSObjectProperties(UserDict[str, Any]):
    def __init__(self, properties: list[dict[str, Any]]):
        super().__init__()
        for p in properties:
            name = p["name"]
            if name == "__proto__":
                self.class_name = p["value"]["className"]
                continue
            # test if a getter/setter first
            value = p.get("get", p.get("set", p.get("value")))
            if value is None:
                continue
            preview = value.get("preview")
            if preview is not None:
                value = JSObjectPreview(preview["properties"])
            elif value.get("className") == "Function":
                value = value["description"]
            else:
                value = value.get("value")
            self.data[name] = value


class InspectorSession:
    def __init__(self, protocol: SessionProtocol, target_id: Optional[str] = None):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        self.protocol = protocol
        self.target_id = target_id
        self.message_id = 1
        self._last_console_message: dict[str, Any] = {}
        self._dispatch_message_responses: dict[int, dict[str, Any]] = {}
        # WebKit replays the page's buffered console history to a newly attached frontend
        # while Console.enable is being processed; mark those messages as replayed
        self._console_replay = True

        self.response_methods: dict[str, Callable[[dict[str, Any]], Any]] = {
            "Target.targetCreated": self._target_created,
            "Target.targetDestroyed": self._target_destroyed,
            "Target.dispatchMessageFromTarget": self._target_dispatch_message_from_target,
            "Target.didCommitProvisionalTarget": self._target_did_commit_provisional_target,
            "Console.messageAdded": self._console_message_added,
            "Console.messagesCleared": lambda _: _,
            "Console.messageRepeatCountUpdated": self._console_message_repeated_count_updated,
            "Heap.garbageCollected": self._heap_garbage_collected,
            "Runtime.executionContextCreated": self._runtime_execution_context_created,
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
            while "targetInfo" not in created["params"]:
                created = protocol.inspector.wir_events.pop(0)
            target_id = created["params"]["targetInfo"]["targetId"]
            logger.info(f"Created: {target_id}")
        target = cls(protocol, target_id)
        return target

    def set_target_id(self, target_id: str):
        self.target_id = target_id
        logger.info(f"Changed to: {target_id}")

    async def heap_gc(self):
        return await self.send_command("Heap.gc")

    async def heap_snapshot(self):
        snapshot = await self.send_command("Heap.snapshot")
        if self.target_id is not None:
            # when a target id is present, the response came from Target.dispatchMessageFromTarget (a dict)
            snapshot = json.loads(cast(dict[str, Any], snapshot)["params"]["message"])
        snapshot = json.loads(cast(str, snapshot))["result"]["snapshotData"]
        return snapshot

    async def heap_enable(self):
        return await self.send_command("Heap.enable")

    async def console_enable(self):
        result = await self.send_command("Console.enable")
        self._console_replay = False
        return result

    async def runtime_enable(self):
        return await self.send_command("Runtime.enable")

    async def send_command(self, method: str, **kwargs: Any):
        if self.target_id is None:
            return await self.protocol.send_receive(method, **kwargs)
        else:
            return await self.send_and_receive({"method": method, "params": kwargs})

    async def runtime_evaluate(self, exp: str, return_by_value: bool = False):
        # if the expression is dict, it's needed to be in ()
        exp = exp.strip()
        if exp and exp[0] == "{" and exp[-1] == "}":
            exp = f"({exp})"

        response = await self.send_and_receive({
            "method": "Runtime.evaluate",
            "params": {
                "expression": exp,
                "objectGroup": "console",
                "includeCommandLineAPI": True,
                "doNotPauseOnExceptionsAndMuteConsole": False,
                "silent": False,
                "returnByValue": return_by_value,
                "generatePreview": True,
                "userGesture": True,
                "awaitPromise": False,
                "replMode": True,
                "allowUnsafeEvalBlockedByCSP": False,
                "uniqueContextId": "0.1",
            },
        })

        return await self._parse_runtime_evaluate(response)

    async def navigate_to_url(self, url: str):
        return await self.runtime_evaluate(exp=f'window.location = "{url}"')

    async def send_and_receive(self, message: dict[str, Any]) -> dict[str, Any]:
        if self.target_id is None:
            message_id = await self.protocol.send_command(message["method"], **message.get("params", {}))
            return await self.protocol.wait_for_message(message_id)
        else:
            message_id = await self.send_message_to_target(message)
            return await self.receive_response_by_id(message_id)

    async def send_message_to_target(self, message: dict[str, Any]) -> int:
        message["id"] = self.message_id
        self.message_id += 1
        await self.protocol.send_command(
            "Target.sendMessageToTarget", targetId=self.target_id, message=json.dumps(message)
        )
        return message["id"]

    async def _receive_loop(self):
        while True:
            while not self.protocol.inspector.wir_events:
                await asyncio.sleep(0)

            response = self.protocol.inspector.wir_events.pop(0)
            response_method = response["method"]
            if response_method in self.response_methods:
                self.response_methods[response_method](response)
            else:
                logger.error(f"Unknown response: {response}")

    async def receive_response_by_id(self, message_id: int) -> dict[str, Any]:
        while True:
            if message_id in self._dispatch_message_responses:
                return self._dispatch_message_responses.pop(message_id)
            await asyncio.sleep(0)

    async def get_properties_raw(self, object_id: str) -> list[dict[str, Any]]:
        """Raw ``Runtime.getProperties`` descriptors, preserving RemoteObject dicts (objectIds)."""
        return await self._fetch_properties(
            "Runtime.getProperties", objectId=object_id, ownProperties=True, generatePreview=True
        )

    async def get_displayable_properties_raw(self, object_id: str) -> list[dict[str, Any]]:
        """Raw ``Runtime.getDisplayableProperties`` descriptors - the property set Safari's Web
        Inspector shows for an object: own properties plus the displayable native accessors
        (which is where most DOM element attributes live)."""
        return await self._fetch_properties(
            "Runtime.getDisplayableProperties", objectId=object_id, generatePreview=True
        )

    async def _fetch_properties(self, method: str, **kwargs: Any) -> list[dict[str, Any]]:
        message = cast(dict[str, Any], await self.send_command(method, **kwargs))
        if self.target_id is not None:
            message = json.loads(message["params"]["message"])["result"]
        return message["properties"]

    async def get_properties(self, object_id: str) -> JSObjectProperties:
        return JSObjectProperties(await self.get_properties_raw(object_id))

    async def _parse_runtime_evaluate(self, response: dict[str, Any]):
        message = response if self.target_id is None else json.loads(response["params"]["message"])
        result = message["result"]["result"]
        if result.get("subtype", "") == "error":
            properties = await self.get_properties(result["objectId"])
            raise InspectorEvaluateError(
                properties.class_name,
                properties["message"],
                properties.get("line"),
                properties.get("column"),
                properties.get("stack", "").split("\n"),
            )
        elif result["type"] == "bigint":
            return result["description"]
        elif result["type"] == "undefined":
            pass
        elif result["type"] == "object":
            value = result.get("value")
            if value is not None:
                return value
            return await self._describe_object(result)
        elif result["type"] == "function":
            return result["description"]
        else:
            return result["value"]

    async def _describe_object(self, result: dict[str, Any]) -> str:
        """Render an object result with all its top-level properties, one shortened line each,
        the way a browser console prints an evaluated object:

            Window {
              window: Window
              document: Document
              ...
            }

        Falls back to the bare class name when the object is not addressable or its
        properties cannot be fetched (released object, navigated page).
        """
        class_name = result.get("className") or result.get("description") or "Object"
        object_id = result.get("objectId")
        if object_id is None:
            return class_name
        try:
            # what Safari's Web Inspector shows: own properties + displayable native accessors
            descriptors = await self.get_displayable_properties_raw(object_id)
        except Exception:
            try:
                descriptors = await self.get_properties_raw(object_id)
            except Exception:
                return class_name
        lines: list[str] = []
        for descriptor in descriptors:
            if descriptor["name"] == "__proto__":
                continue
            remote_object = descriptor.get("value", descriptor.get("get", descriptor.get("set")))
            if remote_object is None:
                continue
            lines.append(f"  {descriptor['name']}: {_shorten_remote_object(remote_object)}")
        if not lines:
            return f"{class_name} {{}}"
        return "\n".join([f"{class_name} {{", *lines, "}"])

    # response methods
    def _target_dispatch_message_from_target(self, response: dict[str, Any]):
        target_message = json.loads(response["params"]["message"])
        receive_message_id = target_message.get("id")
        if receive_message_id is None:
            self._missing_id_in_message(target_message)
            return
        self._dispatch_message_responses[receive_message_id] = response

    def _missing_id_in_message(self, message: dict[str, Any]):
        handler = self.response_methods.get(message["method"])
        if handler is not None:
            handler(message)
        else:
            logger.critical(f"unhandled message: {message}")

    def _console_message_added(self, message: dict[str, Any]):
        message_body = message["params"]["message"]
        log_level = message_body["level"]
        # console-api messages carry only the first argument in 'text'; all arguments arrive
        # as RemoteObjects in 'parameters' (e.g. console.log(4,4) -> text '4', parameters [4, 4])
        parameters = message_body.get("parameters")
        if parameters:
            text = " ".join(self._stringify_console_parameter(parameter) for parameter in parameters)
        else:
            text = message_body["text"]
        self._last_console_message = message
        handlers = webinspector_replay_logger_handlers if self._console_replay else webinspector_logger_handlers
        handlers[log_level](text)

    @staticmethod
    def _stringify_console_parameter(parameter: dict[str, Any]) -> str:
        if parameter.get("type") == "string":
            return cast(str, parameter["value"])
        if "description" in parameter:
            return cast(str, parameter["description"])
        if "value" in parameter:
            # json.dumps renders JS-style primitives (true/false/null) rather than Python's
            return json.dumps(parameter["value"])
        return cast(str, parameter.get("type", ""))

    def _console_message_repeated_count_updated(self, message: dict[str, Any]):
        self._console_message_added(self._last_console_message)

    def _heap_garbage_collected(self, message: dict[str, Any]):
        heap_logger.debug(message["params"])

    def _runtime_execution_context_created(self, message: dict[str, Any]):
        # pushed by the page after Runtime.enable for every JS execution context; evaluation
        # pins uniqueContextId '0.1' (see runtime_evaluate), so the event is informational only
        logger.debug(f"executionContextCreated: {message['params']['context']}")

    def _target_created(self, response: dict[str, Any]):
        pass

    def _target_destroyed(self, response: dict[str, Any]):
        pass

    def _target_did_commit_provisional_target(self, response: dict[str, Any]):
        self.set_target_id(response["params"]["newTargetId"])
