import asyncio
from datetime import datetime
import hashlib
import json
from functools import partial
import logging

from pymobiledevice3.services.web_protocol.cdp_screencast import ScreenCast

logger = logging.getLogger(__name__)

NETWORK_RESOURCE_TYPES = ['Document', 'Stylesheet', 'Image', 'Media', 'Font', 'Script', 'TextTrack', 'XHR', 'Fetch',
                          'EventSource', 'WebSocket', 'Manifest', 'SignedExchange', 'Ping', 'CSPViolationReport',
                          'Preflight', 'Other']

LOG_MESSAGE_SOURCES = {
    'xml': 'xml',
    'javascript': 'javascript',
    'network': 'network',
    'console-api': 'javascript',
    'storage': 'storage',
    'appcache': 'appcache',
    'rendering': 'rendering',
    'css': 'rendering',
    'security': 'security',
    'deprecation': 'deprecation',
    'worker': 'worker',
    'violation': 'violation',
    'intervention': 'intervention',
    'recommendation': 'recommendation',
    'other': 'other',
    'content-blocker': 'other',
    'media': 'other',
    'mediasource': 'other',
    'webrtc': 'other',
    'itp-debug': 'other',
    'ad-click-attribution': 'other',
}

LOG_MESSAGE_LEVELS = {
    'log': 'info',
    'info': 'info',
    'warning': 'warning',
    'error': 'error',
    'debug': 'verbose',

}

DEBUGGER_PAUSED_REASON = {
    'XHR': 'XHR',
    'Fetch': 'other',
    'DOM': 'DOM',
    'AnimationFrame': 'other',
    'Interval': 'other',
    'Listener': 'EventListener',
    'Timeout': 'other',
    'exception': 'exception',
    'assert': 'assert',
    'CSPViolation': 'CSPViolation',
    'DebuggerStatement': 'debugCommand',
    'Breakpoint': 'instrumentation',
    'PauseOnNextStatement': 'instrumentation',
    'Microtask': 'other',
    'BlackboxedScript': 'other',
    'other': 'other',
}


class CdpTarget:
    def __init__(self, protocol, target_id: str):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        :param target_id: Target id.
        """
        self.protocol = protocol
        self.target_id = target_id
        self.frame = {}
        self.session_id = protocol.id_
        self.app_id = protocol.app.id_
        self.page_id = protocol.page.id_
        self.output_queue = asyncio.Queue()
        self.input_queue = asyncio.Queue()
        self.screencast = None
        self.from_cdp_special_messages_methods = {
            'Audits.enable': self._audits_enable,
            'DOM.getBoxModel': self._dom_get_box_model,
            'DOM.enable': partial(self._simple_response, value=None),
            'DOM.getNodeForLocation': self._dom_get_node_for_location,
            'DOM.getNodesForSubtreeByStyle': self._dom_get_nodes_for_subtree_by_style,
            'Log.clear': self._log_clear,
            'Log.disable': self._log_disable,
            'Log.enable': self._log_enable,
            'Log.startViolationsReport': partial(self._simple_response, value=None),
            'Page.getNavigationHistory': self._page_get_navigation_history,
            'Page.startScreencast': self._page_start_screencast,
            'Page.stopScreencast': self._page_stop_screencast,
            'Page.screencastFrameAck': self._page_screencast_frame_ack,
            'Page.getResourceTree': self._page_get_resource_tree,
            'Emulation.setEmulatedMedia': self._emulation_set_emulated_media,
            'Emulation.setTouchEmulationEnabled': partial(self._simple_response, value=None),
            'Emulation.setFocusEmulationEnabled': partial(self._simple_response, value=None),
            'Emulation.setEmulatedVisionDeficiency': partial(self._simple_response, value=None),
            'Emulation.setAutoDarkModeOverride': self._emulation_set_auto_dark_mode_override,
            'Emulation.setEmitTouchEventsForMouse': partial(self._simple_response, value=None),
            'Debugger.setAsyncCallStackDepth': partial(self._simple_response, value=True),
            'Debugger.setBlackboxPatterns': self._debugger_set_blackbox_patterns,
            'Debugger.setBreakpointByUrl': self._debugger_set_breakpoint_by_url,
            'DOMDebugger.setBreakOnCSPViolation': partial(self._simple_response, value=None),
            'DOMDebugger.getEventListeners': self._domdebugger_get_event_listeners,
            'Network.setCacheDisabled': self._network_set_cache_disabled,
            'Network.loadNetworkResource': self._network_load_network_resource,
            'Network.setAttachDebugStack': partial(self._simple_response, value=None),
            'Network.clearAcceptedEncodingsOverride': partial(self._simple_response, value=None),
            'ServiceWorker.enable': self._service_worker_enable,
            'HeapProfiler.enable': partial(self._simple_response, value=None),
            'Overlay.setShowGridOverlays': partial(self._simple_response, value=None),
            'Overlay.setShowFlexOverlays': partial(self._simple_response, value=None),
            'Overlay.setShowScrollSnapOverlays': partial(self._simple_response, value=None),
            'Overlay.setShowContainerQueryOverlays': partial(self._simple_response, value=None),
            'Overlay.setShowIsolatedElements': partial(self._simple_response, value=None),
            'Overlay.hideHighlight': partial(self._simple_response, value=None),
            'Overlay.highlightNode': self._overlay_highlight_node,
            'Overlay.enable': partial(self._simple_response, value=None),
            'Overlay.setShowViewportSizeOnResize': partial(self._simple_response, value=None),
            'Overlay.setPausedInDebuggerMessage': partial(self._simple_response, value=None),
            'Runtime.runIfWaitingForDebugger': partial(self._simple_response, value=None),
            'Runtime.compileScript': self._runtime_compile_script,
            'Runtime.getIsolateId': self._runtime_get_isolate_id,
            'Profiler.enable': partial(self._simple_response, value=None),
            'Target.setAutoAttach': self._target_set_auto_attach,
            'Target.setDiscoverTargets': partial(self._simple_response, value=None),
            'Target.setRemoteLocations': partial(self._simple_response, value=None),
            'CSS.trackComputedStyleUpdates': partial(self._simple_response, value=None),
            'CSS.takeComputedStyleUpdates': self._css_take_computed_style_updates,
            'CSS.addRule': self._css_add_rule,
            'Input.emulateTouchFromMouseEvent': self._input_emulate_touch_from_mouse_event,
            'Input.dispatchKeyEvent': self._input_dispatch_key_event,

        }
        self.to_cdp_special_messages_methods = {
            'Target.targetCreated': self._target_created,
            'Target.targetDestroyed': self._target_destroyed,
            'Target.dispatchMessageFromTarget': self._target_dispatch_message_from_target,
            'Target.didCommitProvisionalTarget': self._target_did_commit_provisional_target,
        }
        self.to_cdp_special_dispatched_messages_methods = {
            'Debugger.scriptParsed': self._debugger_script_parsed,
            'Debugger.scriptFailedToParse': self._debugger_script_failed_to_parse,
            'Debugger.paused': self._debugger_paused,
            'Debugger.globalObjectCleared': self._debugger_global_object_cleared,
            'Page.defaultAppearanceDidChange': self._page_default_appearance_did_change,
            'Runtime.executionContextCreated': self._runtime_execution_context_created,
            'Console.messageAdded': self._console_message_added,
            'Network.responseReceived': self._network_response_received,
            'Network.loadingFinished': self._network_loading_finished,
        }
        self._waiting_for_id = 0
        self._input_task = asyncio.create_task(self._input_loop())
        self._receiving_task = asyncio.create_task(self._receive_loop())
        self._script_source_to_context_id = {}
        self._default_execution_id = 0

    @classmethod
    async def create(cls, protocol):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        await protocol.inspector.start_cdp(protocol.id_, protocol.app.id_, protocol.page.id_)
        while not protocol.inspector.wir_events:
            await asyncio.sleep(0)
        created = protocol.inspector.wir_events.pop(0)
        while 'targetInfo' not in created['params']:
            created = protocol.inspector.wir_events.pop(0)
        target_id = created['params']['targetInfo']['targetId']
        logger.info(f'Created: {target_id}')
        target = cls(protocol, target_id)
        await target.output_queue.put(created)
        return target

    async def send(self, message):
        """
        Send message from devtools to the target.
        """
        await self.input_queue.put(message)

    async def receive(self):
        """
        Get message from the target to the devtools.
        """
        return await self.output_queue.get()

    async def wait_for_event_id(self, id_: int):
        """
        Wait for a message with a specific id from the target.
        :param id_: Message id to wait for.
        """
        while True:
            for i in range(len(self.protocol.inspector.wir_events)):
                message = self.protocol.inspector.wir_events[i]
                if message['method'] != 'Target.dispatchMessageFromTarget':
                    continue
                message = json.loads(message['params']['message'])
                if message.get('id', '') != id_:
                    continue
                del self.protocol.inspector.wir_events[i]
                return message
            await asyncio.sleep(0)

    async def send_message_with_result(self, id_, method, params):
        """
        Send a message to the target and wait for response.
        """
        self._waiting_for_id += 1
        await self._send_message_to_target({'id': id_, 'method': method, 'params': params})
        result = await self.wait_for_event_id(id_)
        self._waiting_for_id -= 1
        return result

    async def evaluate_and_result(self, id_, expression):
        """
        Evaluate Javascript expression.
        """
        logger.debug('Evaluating: ', expression)
        params = {'expression': expression}
        data = await self.send_message_with_result(id_, 'Runtime.evaluate', params)
        logger.debug('Evaluated: ', data)
        result = data['result']['result']
        if result['type'] == 'string':
            return result['value']
        elif result['type'] == 'undefined':
            return None
        elif result['type'] == 'object':
            return result
        else:
            logger.debug('Unknown type: ', result)
            return result

    async def _input_loop(self):
        while True:
            message = await self.input_queue.get()
            if message['method'] in self.from_cdp_special_messages_methods:
                await self.from_cdp_special_messages_methods[message['method']](message)
            else:
                await self._send_message_to_target(message)

    async def _receive_loop(self):
        while True:
            if self._waiting_for_id or not self.protocol.inspector.wir_events:
                await asyncio.sleep(0)
                continue
            message = self.protocol.inspector.wir_events.pop(0)
            await self._to_output_queue(message)

    async def _to_output_queue(self, message):
        if message['method'] in self.to_cdp_special_messages_methods:
            await self.to_cdp_special_messages_methods[message['method']](message)
        else:
            logger.error('Error!!!!!!!!!!!!', message)
            raise RuntimeError()

    async def _send_message_to_target(self, message):
        await self.protocol.send_command('Target.sendMessageToTarget', targetId=self.target_id,
                                         message=json.dumps(message))

    async def _simple_response(self, message, value):
        await self.output_queue.put({'id': message['id'], 'result': {'result': value}})

    async def _audits_enable(self, message):
        message['method'] = 'Audit.setup'
        await self._send_message_to_target(message)

    async def _dom_get_box_model(self, message):
        message['method'] = 'DOM.highlightNode'
        message['params']['highlightConfig'] = {
            'showInfo': True,
            'contentColor': {'r': 111, 'g': 168, 'b': 220, 'a': 0.66},
            'paddingColor': {'r': 147, 'g': 196, 'b': 125, 'a': 0.55},
            'borderColor': {'r': 255, 'g': 229, 'b': 153, 'a': 0.66},
            'marginColor': {'r': 246, 'g': 178, 'b': 107, 'a': 0.66},
        }
        await self._send_message_to_target(message)

    async def object_id_to_node_id(self, object_id, id_):
        node = await self.send_message_with_result(id_, 'DOM.requestNode', {'objectId': object_id})
        return node['result']['nodeId']

    async def _dom_get_node_for_location(self, message):
        x, y = message['params']['x'], message['params']['y']
        obj = await self.evaluate_and_result(message['id'], f'document.elementFromPoint({x},{y})')
        if 'objectId' not in obj:
            await self._simple_response(message, None)
            return
        result = {'nodeId': await self.object_id_to_node_id(obj['objectId'], message['id'])}
        await self.output_queue.put({'id': message['id'], 'result': result})

    async def _dom_get_nodes_for_subtree_by_style(self, message):
        object_id = (await self.send_message_with_result(
            message['id'], 'DOM.resolveNode', {'nodeId': message['params']['nodeId']}
        ))['result']['object']['objectId']
        result = await self.send_message_with_result(message['id'], 'Runtime.callFunctionOn', {
            'objectId': object_id,
            'functionDeclaration': (
                'function(styles) {'
                '   const result = new Set();'
                '   var all = this.getElementsByTagName("*");'
                '   for (var elem_i=0; elem_i < all.length; elem_i++) {'
                '       for (var style_i in styles) {'
                '           if (window.getComputedStyle(all[elem_i]).getPropertyValue(styles[style_i].name) ==='
                ' styles[style_i].value) {'
                '               result.add(all[elem_i]);'
                '               break;'
                '           }'
                '       }'
                '   }'
                '   return result;'
                '}'
            ),
            'arguments': [{'value': message['params']['computedStyles']}]
        })
        result = await self.send_message_with_result(message['id'], 'Runtime.getCollectionEntries',
                                                     {'objectId': result['result']['result']['objectId']})
        nodes = await asyncio.gather(
            *[self.object_id_to_node_id(obj['value']['objectId'], message['id'] - i) for i, obj in
              enumerate(result['result']['entries'])], return_exceptions=True)
        nodes = [n for n in nodes if isinstance(n, int)]
        await self.output_queue.put({'id': message['id'], 'result': {'nodeIds': nodes}})

    async def _log_clear(self, message):
        message['method'] = 'Console.clearMessages'
        await self._send_message_to_target(message)

    async def _log_disable(self, message):
        message['method'] = 'Console.disable'
        await self._send_message_to_target(message)

    async def _log_enable(self, message):
        message['method'] = 'Console.enable'
        await self._send_message_to_target(message)

    async def _page_get_navigation_history(self, message):
        href = await self.evaluate_and_result(message['id'], 'window.location.href')
        title = await self.evaluate_and_result(message['id'], 'document.title')
        await self.output_queue.put({
            'id': message['id'],
            'result': {
                'currentIndex': 0,
                'entries': [{'id': 0, 'url': href, 'title': title}]
            }
        })

    async def _page_start_screencast(self, message):
        params = message['params']
        self.screencast = ScreenCast(self, params['format'], params['quality'], params['maxWidth'], params['maxHeight'])
        await self.screencast.start(message['id'])
        await self._simple_response(message, None)

    async def _page_stop_screencast(self, message):
        if self.screencast is not None:
            await self.screencast.stop()
            self.screencast = None
        await self._simple_response(message, None)

    async def _page_screencast_frame_ack(self, message):
        if self.screencast is not None:
            self.screencast.ack(message['params']['sessionId'])
        await self._simple_response(message, None)

    async def _page_get_resource_tree(self, message):
        result = await self.send_message_with_result(message['id'], message['method'], message['params'])
        self.frame = result['result']['frameTree']['frame']
        await self.output_queue.put(result)

    async def _emulation_set_emulated_media(self, message):
        message['method'] = 'Page.setEmulatedMedia'
        await self._send_message_to_target(message)

    async def _emulation_set_auto_dark_mode_override(self, message):
        message['method'] = 'Page.setForcedAppearance'
        params = message['params']
        if not params:
            await self._simple_response(message, None)
            return
        message['params'] = {'appearance': 'Dark' if params['enabled'] else 'Light'}
        await self._send_message_to_target(message)

    async def _debugger_set_blackbox_patterns(self, message):
        for pattern in message['params']['patterns']:
            await self.send_message_with_result(message['id'], 'Debugger.setShouldBlackboxURL',
                                                {'url': pattern, 'shouldBlackbox': True})
        await self._simple_response(message, None)

    async def _debugger_set_breakpoint_by_url(self, message):
        condition = message['params'].pop('condition', '')
        if condition:
            message['params']['options']['condition'] = condition
        await self._send_message_to_target(message)

    async def _domdebugger_get_event_listeners(self, message):
        node = {'nodeId': await self.object_id_to_node_id(message['params']['objectId'], message['id'])}
        listeners = await self.send_message_with_result(message['id'], 'DOM.getEventListenersForNode', node)
        if 'error' in listeners:
            await self._simple_response(message, None)
            return
        listeners_out = []
        for listener in listeners['result']['listeners']:
            data = {
                'type': listener['type'],
                'useCapture': listener['useCapture'],
                'passive': listener.get('passive', False),
                'once': listener.get('once', False),
            }
            if 'location' in listener:
                data['scriptId'] = listener['location']['scriptId']
                data['lineNumber'] = listener['location']['lineNumber']
                data['columnNumber'] = listener['location']['columnNumber']
            listeners_out.append(data)
        await self.output_queue.put({'id': message['id'], 'result': {'listeners': listeners_out}})

    async def _network_set_cache_disabled(self, message):
        message['method'] = 'Network.setResourceCachingDisabled'
        message['params'] = {'disabled': message['params']['cacheDisabled']}
        await self._send_message_to_target(message)

    async def _network_load_network_resource(self, message):
        await self.output_queue.put({'id': message['id'], 'result': {'resource': {'success': True}}})

    async def _service_worker_enable(self, message):
        message['method'] = 'Worker.enable'
        await self._send_message_to_target(message)

    async def _overlay_highlight_node(self, message):
        message['method'] = 'DOM.highlightNode'
        await self._send_message_to_target(message)

    async def _runtime_compile_script(self, message):
        self._script_source_to_context_id[message['params']['expression']] = message['params']['executionContextId']
        response = await self.send_message_with_result(message['id'], 'Runtime.parse',
                                                       {'source': message['params']['expression']})
        if response['result']['result'] == 'none':
            await self._simple_response(message, None)
            return
        lines = message['params']['expression'][:response['result']['range']['endOffset']].splitlines()
        lines = lines if lines else ['']
        await self.output_queue.put({'id': message['id'], 'result': {
            'exceptionDetails': {
                'exceptionId': 1,
                'text': response['result']['message'],
                'lineNumber': len(lines) - 1,
                'columnNumber': len(lines[-1]) - 1
            }
        }})

    async def _runtime_get_isolate_id(self, message):
        await self.output_queue.put({'id': message['id'], 'result': {'id': self._default_execution_id}})

    async def _target_set_auto_attach(self, message):
        await self._simple_response(message, None)
        await self.output_queue.put({'method': 'Target.attachedToTarget', 'params': {
            'sessionId': self.protocol.id_, 'targetInfo': {'targetId': self.target_id}, 'waitingForDebugger': True
        }})

    async def _css_take_computed_style_updates(self, message):
        await self.output_queue.put({
            'id': message['id'],
            'result': {'nodeIds': []}
        })

    async def _css_add_rule(self, message):
        message['params']['selector'] = message['params']['ruleText'].split('{')[0]
        await self._send_message_to_target(message)

    async def _input_emulate_touch_from_mouse_event(self, message):
        params = message['params']
        if params['type'] == 'mouseWheel':
            delta_x, delta_y = params['deltaX'] // self.screencast.scale, params['deltaY'] // self.screencast.scale
            await self.evaluate_and_result(message['id'], f'window.scrollBy({-delta_x}, {-delta_y})')
        elif params['type'] == 'mouseReleased':
            pass
        else:
            modifiers = params['modifiers']
            x, y = params['x'] // self.screencast.scale, params['y'] // self.screencast.scale
            event_params = {
                'screenX': x, 'screenY': y, 'clientX': 0, 'clientY': 0, 'altKey': bool(modifiers & 1),
                'ctrlKey': bool(modifiers & 2), 'metaKey': bool(modifiers & 4), 'shiftKey': bool(modifiers & 8),
                'button': params['button'], 'bubbles': True, 'cancelable': False,
            }
            type_ = {'mousePressed': 'click', 'mouseReleased': 'click', 'mouseMoved': 'mousemove'}[params['type']]
            event_params = json.dumps(event_params)
            simulate_mouse_event = (
                'function simulateMouseEvent(type){'
                f'const element = document.elementFromPoint({x}, {y});'
                f'const e = new MouseEvent(type, JSON.parse(\'{event_params}\'));'
                'element.dispatchEvent(e);'
                'element.focus();'
                'return e;}'
            )
            await self.evaluate_and_result(message['id'], f'({simulate_mouse_event})("{type_}")')
            if type_ == 'click':
                await self.evaluate_and_result(message['id'], f'({simulate_mouse_event})("mouseup")')

        await self._simple_response(message, None)

    async def _input_dispatch_key_event(self, message):
        params = message['params']
        key = params['key']
        if params['type'] == 'keyUp' and key == 'Backspace':
            manipulation = 'document.activeElement.value = document.activeElement.value.slice(0, -1);'
        elif params['type'] == 'char' and key == 'Enter':
            manipulation = (
                'var tagName = document.activeElement.tagName.toLowerCase();'
                'if (tagName === "textarea" || document.activeElement.isContentEditable) {'
                '    document.activeElement.value = document.activeElement.value + "\\n";'
                '} else {'
                '    const result = document.evaluate("./ancestor-or-self::form", document.activeElement, '
                '                                     null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);'
                '    const e = result.singleNodeValue.ownerDocument.createEvent(\'Event\');'
                '    e.initEvent("submit", true, true);'
                '    if (result.singleNodeValue.dispatchEvent(e)) { result.singleNodeValue.submit() }'
                '}'
            )
        elif params['type'] == 'char':
            text = params['text']
            manipulation = f'document.activeElement.value = document.activeElement.value + "{text}";'
        else:
            await self._simple_response(message, None)
            return

        simulate_key_event = (
            'function isEditable(element) {'
            '    if (element.disabled || element.readOnly)'
            '        return false;'
            '    var tagName = element.tagName.toLowerCase();'
            '    if (tagName === "textarea" || element.isContentEditable)'
            '        return true;'
            '    if (tagName != "input")'
            '        return false;'
            '    switch (element.type) {'
            '    case "color": case "date": case "datetime-local": case "email": case "file": case "month": '
            '    case "number": case "password": case "range": case "search": case "tel": case "text": case "time": '
            '    case "url": case "week":'
            '        return true;'
            '    }'
            '    return false;'
            '}'
            'if (isEditable(document.activeElement)) {'
            f'{manipulation}'
            '}'
        )
        await self.evaluate_and_result(message['id'], simulate_key_event)
        await self._simple_response(message, None)

    async def _target_created(self, message):
        self.target_id = message['params']['targetInfo']['targetId']
        message['method'] = 'Target.targetInfoChanged'
        message['params']['targetInfo']['url'] = await self.evaluate_and_result(1, 'window.location.href')
        message['params']['targetInfo']['title'] = await self.evaluate_and_result(1, 'document.title')
        message['params']['targetInfo']['attached'] = message['params']['targetInfo'].pop('isProvisional')
        await self.output_queue.put(message)

    async def _target_destroyed(self, message):
        result = await self.send_message_with_result(1, 'Page.getResourceTree', {})
        self.frame = result['result']['frameTree']['frame']
        await self.output_queue.put({
            'method': 'Page.frameNavigated',
            'params': {
                'frame': self.frame,
            }
        })
        await self.output_queue.put({
            'method': 'Page.loadEventFired',
            'params': {
                'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'),
            }
        })
        await self.output_queue.put({'method': 'DOM.documentUpdated'})

    async def _target_dispatch_message_from_target(self, message):
        message = json.loads(message['params']['message'])
        if 'error' in message:
            logger.error(message)
        if message.get('method', '') in self.to_cdp_special_dispatched_messages_methods:
            await self.to_cdp_special_dispatched_messages_methods[message['method']](message)
        else:
            if 'method' in message:
                logger.debug('DISPACHING', message['method'])
            await self.output_queue.put(message)

    async def _target_did_commit_provisional_target(self, message):
        pass

    async def _debugger_script_parsed(self, message):
        if not self._waiting_for_id:
            await self.output_queue.put(message)

    async def _debugger_script_failed_to_parse(self, message):
        message['params'] = {
            'endColumn': 0,
            'endLine': message['params']['errorLine'],
            'executionContextId': self._script_source_to_context_id[message['params']['scriptSource']],
            'startColumn': 0,
            'startLine': message['params']['startLine'],
            'url': message['params']['url'],
            'scriptId': self._script_source_to_context_id[message['params']['scriptSource']],
            'hash': hashlib.sha1(message['params']['scriptSource']).hexdigest(),
        }
        await self.output_queue.put(message)

    async def _debugger_paused(self, message):
        message['params']['reason'] = DEBUGGER_PAUSED_REASON[message['params']['reason']]
        if 'breakpointId' in message['params'].get('data', {}):
            message['params']['hitBreakpoints'] = [message['params']['data']['breakpointId']]
        await self.output_queue.put(message)

    async def _debugger_global_object_cleared(self, message):
        await self.output_queue.put({'method': 'DOM.documentUpdated'})

    async def _page_default_appearance_did_change(self, message):
        pass

    async def _runtime_execution_context_created(self, message):
        if message['params']['context']['type'] == 'normal':
            self._default_execution_id = message['params']['context']['id']
        message['params'] = {
            'context': {
                'id': message['params']['context']['id'],
                'origin': 'default',
                'name': '',
                'uniqueId': message['params']['context']['frameId'],
            }
        }
        await self.output_queue.put(message)

    async def _console_message_added(self, message):
        log_record = {
            'source': LOG_MESSAGE_SOURCES[message['params']['message']['source']],
            'level': LOG_MESSAGE_LEVELS[message['params']['message']['level']],
            'text': message['params']['message']['text'],
            'timestamp': datetime.now().timestamp(),
        }
        if 'url' in message['params']['message']:
            log_record['url'] = message['params']['message']['url']
        if 'line' in message['params']['message']:
            log_record['lineNumber'] = message['params']['message']['line']
        if 'networkRequestId' in message['params']['message']:
            log_record['networkRequestId'] = message['params']['message']['networkRequestId']

        await self.output_queue.put({'method': 'Log.entryAdded', 'params': {'entry': log_record}})

    async def _network_response_received(self, message):
        params = message['params']
        message['params'] = {
            'loaderId': params['loaderId'],
            'requestId': params['requestId'],
            'timestamp': params['timestamp'],
            'type': params['type'] if params['type'] in NETWORK_RESOURCE_TYPES else 'Other',
            'response': {
                'url': params['response']['url'],
                'status': params['response']['status'],
                'statusText': params['response']['statusText'],
                'headers': params['response']['headers'],
                'mimeType': params['response']['mimeType'],
                'connectionReused': False,
                'encodedDataLength': 0,
                'securityState': 'unknown',
            },
        }
        if 'frameId' in params:
            message['params']['frameId'] = params['frameId']
        await self.output_queue.put(message)

    async def _network_loading_finished(self, message):
        params = message['params']
        header_size = params['metrics'].get('responseHeaderBytesReceived', 0)
        body_size = params['metrics'].get('responseBodyBytesReceived', 0)
        message['params'] = {
            'encodedDataLength': header_size + body_size,
            'requestId': params['requestId'],
            'timestamp': params['timestamp'],
        }
        await self.output_queue.put(message)
