import asyncio
import hashlib
import itertools
import json
import logging
from collections.abc import Awaitable
from datetime import datetime
from functools import partial
from typing import Any, Callable, Optional, cast

from pymobiledevice3.services.web_protocol.cdp_screencast import ScreenCast
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import WirTypes

logger = logging.getLogger(__name__)

# Seconds to wait for the device's response to a translated inspector request before giving up.
# The wait holds _waiting_for_id, which pauses the receive loop, so it must be bounded.
WIR_RESULT_TIMEOUT = 5

# Once a target has missed a reply it is flagged unresponsive and further internal requests
# fast-fail (see send_message_with_result). To notice a target that recovered but is otherwise
# silent, one request is let through every UNRESPONSIVE_REPROBE_INTERVAL seconds, with a short
# timeout so a still-dead target only briefly re-pauses the receive loop.
UNRESPONSIVE_REPROBE_INTERVAL = 2.0
UNRESPONSIVE_PROBE_TIMEOUT = 1.5

# sourceURL stamped onto the bridge's own internal evaluations (screencast offsets, synthesized
# input, navigation) so their Debugger.scriptParsed events can be recognized and dropped instead
# of polluting Chrome's script model. WebKit-inspector-internal scripts (its injected script
# source) carry their own marker.
INTERNAL_SCRIPT_URL = "__pymobiledevice3_internal__"
WEBKIT_INTERNAL_SCRIPT_MARKERS = ("__InjectedScript", INTERNAL_SCRIPT_URL)

# Minimum seconds between synthesized screencast hover (mouseMoved) events. DevTools streams
# dozens of moves per second as the pointer glides; synthesizing each one as a blocking device
# round-trip floods webinspectord and pauses the receive loop, which - on a chatty page - starves
# event delivery until the frontend wedges. Intermediate moves are acked and dropped.
MOUSEMOVE_MIN_INTERVAL = 0.08

# CDP domains WebKit does not implement at all. Any method in these that isn't specially
# translated is acknowledged with an empty response instead of being forwarded (and erroring).
NOOP_ABSENT_DOMAINS = frozenset({"Input", "Overlay"})

# Events WebKit's Web Inspector emits that have no counterpart in Chrome's protocol. Forwarding
# them is at best noise (Chrome ignores unknown events) and at worst fatal: an unrecognized event
# can throw in the frontend's message dispatcher and kill its pump, so a chatty page that emits
# them in bulk (e.g. CSS.nodeLayoutFlagsChanged on every layout) can wedge DevTools. Drop them.
WEBKIT_ONLY_EVENTS = frozenset({
    "CSS.nodeLayoutFlagsChanged",
    "DOM.willDestroyDOMNode",
    "Page.defaultUserPreferencesDidChange",
})

# Message ids for the un-multiplexed (JSContext) path. Those replies come back on the inspector's
# shared, id-keyed wir_message_results, where the frontend's own ids - small integers, restarting
# at 1 in every session - would consume each other's responses and SessionProtocol's. Allocating
# from a process-wide counter in a range neither of them reaches keeps them apart.
_FLAT_WIRE_IDS = itertools.count(0x40000000)

# The single execution context synthesized for a JSContext debuggable (see _runtime_enable).
JS_CONTEXT_EXECUTION_ID = 1
JS_CONTEXT_UNIQUE_ID = "jscontext.1"

# Error synthesized for requests routed to a target that got destroyed before answering
# (WebKit never answers those). Matches Chrome's own message for the same situation.
TARGET_CLOSED_ERROR: dict[str, Any] = {"code": -32000, "message": "Inspected target navigated or closed"}

# Per-target state (beyond *.enable) worth re-establishing on the fresh target after a process
# swap. These keep their latest params only.
REPLAYED_SETUP_METHODS = frozenset({
    "Network.setResourceCachingDisabled",
    "Page.setEmulatedMedia",
    "Page.setForcedAppearance",
    "Debugger.setBreakpointsActive",
    "Debugger.setPauseOnExceptions",
    "Debugger.setAsyncStackTraceDepth",
    # Synthesized by the bridge (Chrome never sends it); see _debugger_enable.
    "Debugger.setPauseOnDebuggerStatements",
})

# Replayed setup methods that accumulate state entry-by-entry (one replay per distinct params).
REPLAYED_MULTI_SETUP_METHODS = frozenset({
    "Debugger.setBreakpointByUrl",
    "Debugger.setShouldBlackboxURL",
})

NETWORK_RESOURCE_TYPES = [
    "Document",
    "Stylesheet",
    "Image",
    "Media",
    "Font",
    "Script",
    "TextTrack",
    "XHR",
    "Fetch",
    "EventSource",
    "WebSocket",
    "Manifest",
    "SignedExchange",
    "Ping",
    "CSPViolationReport",
    "Preflight",
    "Other",
]

LOG_MESSAGE_SOURCES = {
    "xml": "xml",
    "javascript": "javascript",
    "network": "network",
    "console-api": "javascript",
    "storage": "storage",
    "appcache": "appcache",
    "rendering": "rendering",
    "css": "rendering",
    "security": "security",
    "deprecation": "deprecation",
    "worker": "worker",
    "violation": "violation",
    "intervention": "intervention",
    "recommendation": "recommendation",
    "other": "other",
    "content-blocker": "other",
    "media": "other",
    "mediasource": "other",
    "webrtc": "other",
    "itp-debug": "other",
    "ad-click-attribution": "other",
}

LOG_MESSAGE_LEVELS = {
    "log": "info",
    "info": "info",
    "warning": "warning",
    "error": "error",
    "debug": "verbose",
}

# objectGroups DevTools uses for autocomplete's throwOnSideEffect evaluations (completion list and
# argument hint). These are side-effect-free sub-expression lookups the dropdown needs, so unlike
# the eager-evaluation preview they must be forwarded rather than refused (see _runtime_evaluate).
_COMPLETION_OBJECT_GROUPS = frozenset({"completion", "argumentsHint"})

# WebKit's Debugger.Scope.type enum -> Chrome's Scope.type enum. WebKit has scope kinds Chrome
# lacks ("functionName", "globalLexicalEnvironment", "nestedLexical", ...); an unrecognized value
# makes Chrome's ScopeChainSidebar throw, so every WebKit type is mapped to a valid Chrome one.
WEBKIT_SCOPE_TYPE_MAP = {
    "closure": "closure",
    "functionName": "closure",
    "global": "global",
    "globalLexicalEnvironment": "global",
    "with": "with",
    "catch": "catch",
    "nestedLexical": "block",
    "functionInParameter": "local",
}

DEBUGGER_PAUSED_REASON = {
    "XHR": "XHR",
    "Fetch": "other",
    "DOM": "DOM",
    "AnimationFrame": "other",
    "Interval": "other",
    "Listener": "EventListener",
    "Timeout": "other",
    "exception": "exception",
    "assert": "assert",
    "CSPViolation": "CSPViolation",
    "DebuggerStatement": "debugCommand",
    "Breakpoint": "instrumentation",
    "PauseOnNextStatement": "instrumentation",
    "Microtask": "other",
    "BlackboxedScript": "other",
    "other": "other",
}


class CdpTarget:
    def __init__(self, protocol: SessionProtocol, target_id: str):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        :param target_id: Target id.
        """
        self.protocol = protocol
        self.target_id = target_id
        self.frame: dict[str, Any] = {}
        self.session_id = protocol.id_
        self.app_id = protocol.app.id_
        self.page_id = protocol.page.id_
        self.output_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.input_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.screencast: Optional[ScreenCast] = None
        self.from_cdp_special_messages_methods: dict[str, Callable[..., Awaitable[Any]]] = {
            "Audits.enable": self._audits_enable,
            "DOM.getBoxModel": self._dom_get_box_model,
            "DOM.enable": partial(self._simple_response, value=None),
            "DOM.getNodeForLocation": self._dom_get_node_for_location,
            "DOM.getNodesForSubtreeByStyle": self._dom_get_nodes_for_subtree_by_style,
            "Log.clear": self._log_clear,
            "Log.disable": self._log_disable,
            "Log.enable": self._log_enable,
            "Log.startViolationsReport": partial(self._simple_response, value=None),
            "Page.getNavigationHistory": self._page_get_navigation_history,
            "Page.startScreencast": self._page_start_screencast,
            "Page.stopScreencast": self._page_stop_screencast,
            "Page.screencastFrameAck": self._page_screencast_frame_ack,
            "Page.getResourceTree": self._page_get_resource_tree,
            "Emulation.setEmulatedMedia": self._emulation_set_emulated_media,
            "Emulation.setTouchEmulationEnabled": partial(self._simple_response, value=None),
            "Emulation.setFocusEmulationEnabled": partial(self._simple_response, value=None),
            "Emulation.setEmulatedVisionDeficiency": partial(self._simple_response, value=None),
            "Emulation.setAutoDarkModeOverride": self._emulation_set_auto_dark_mode_override,
            "Emulation.setEmitTouchEventsForMouse": partial(self._simple_response, value=None),
            "Debugger.setAsyncCallStackDepth": partial(self._simple_response, value=True),
            "Debugger.enable": self._debugger_enable,
            "Debugger.setBreakpointsActive": self._debugger_set_breakpoints_active,
            "Debugger.setBlackboxPatterns": self._debugger_set_blackbox_patterns,
            "Debugger.setBreakpointByUrl": self._debugger_set_breakpoint_by_url,
            "DOMDebugger.setBreakOnCSPViolation": partial(self._simple_response, value=None),
            "DOMDebugger.getEventListeners": self._domdebugger_get_event_listeners,
            "Network.setCacheDisabled": self._network_set_cache_disabled,
            "Network.loadNetworkResource": self._network_load_network_resource,
            "Network.setAttachDebugStack": partial(self._simple_response, value=None),
            "Network.clearAcceptedEncodingsOverride": partial(self._simple_response, value=None),
            "ServiceWorker.enable": self._service_worker_enable,
            "HeapProfiler.enable": partial(self._simple_response, value=None),
            # Overlay is absent in WebKit; only highlightNode is worth translating, the rest are
            # acknowledged by the NOOP_ABSENT_DOMAINS fallback in _input_loop.
            "Overlay.highlightNode": self._overlay_highlight_node,
            "Runtime.runIfWaitingForDebugger": partial(self._simple_response, value=None),
            "Runtime.enable": self._runtime_enable,
            "Runtime.evaluate": self._runtime_evaluate,
            "Runtime.compileScript": self._runtime_compile_script,
            "Runtime.runScript": self._runtime_run_script,
            "Runtime.getIsolateId": self._runtime_get_isolate_id,
            "Profiler.enable": partial(self._simple_response, value=None),
            "Target.setAutoAttach": self._target_set_auto_attach,
            "Target.setDiscoverTargets": partial(self._simple_response, value=None),
            "Target.setRemoteLocations": partial(self._simple_response, value=None),
            "CSS.trackComputedStyleUpdates": partial(self._simple_response, value=None),
            "CSS.takeComputedStyleUpdates": self._css_take_computed_style_updates,
            "CSS.addRule": self._css_add_rule,
            "Input.emulateTouchFromMouseEvent": self._input_emulate_touch_from_mouse_event,
            "Input.dispatchKeyEvent": self._input_dispatch_key_event,
            "Input.dispatchMouseEvent": self._input_dispatch_mouse_event,
            "Page.navigate": self._page_navigate,
            "Page.setAdBlockingEnabled": partial(self._simple_response, value=None),
            "Page.addScriptToEvaluateOnNewDocument": self._page_add_script_to_evaluate_on_new_document,
            "Accessibility.enable": partial(self._simple_response, value=None),
            "Autofill.enable": partial(self._simple_response, value=None),
            "Autofill.setAddresses": partial(self._simple_response, value=None),
            "Runtime.addBinding": partial(self._simple_response, value=None),
            "Runtime.globalLexicalScopeNames": self._runtime_global_lexical_scope_names,
            "Runtime.getProperties": self._runtime_get_properties,
            "Network.setBlockedURLs": partial(self._simple_response, value=None),
            # The SDK reads ruleIds.length from this response inside the target-initialization
            # Promise.all; a field-less response rejects it and silently kills the rest of the
            # init chain (the console stops rendering results).
            "Network.emulateNetworkConditionsByRule": partial(self._result_response, result={"ruleIds": []}),
            "Network.overrideNetworkState": partial(self._simple_response, value=None),
            # The frontend queries this per frame and reads response.status.coep/.coop; WebKit has
            # no such method, so report a schema-valid "no isolation policies" status.
            "Network.getSecurityIsolationStatus": partial(
                self._result_response,
                result={
                    "status": {
                        "coep": {"value": "None", "reportOnlyValue": "None"},
                        "coop": {"value": "UnsafeNone", "reportOnlyValue": "UnsafeNone"},
                    }
                },
            ),
            "Storage.getStorageKey": partial(self._result_response, result={"storageKey": ""}),
            "CSS.getAnimatedStylesForNode": partial(self._simple_response, value=None),
            "CSS.getEnvironmentVariables": partial(self._result_response, result={"environmentVariables": {}}),
            "CSS.trackComputedStyleUpdatesForNode": partial(self._simple_response, value=None),
            "CSS.getPlatformFontsForNode": self._css_get_platform_fonts,
            "DOM.pushNodesByBackendIdsToFrontend": self._dom_push_nodes_by_backend_ids,
        }
        self.to_cdp_special_messages_methods = {
            "Target.targetCreated": self._target_created,
            "Target.targetDestroyed": self._target_destroyed,
            "Target.dispatchMessageFromTarget": self._target_dispatch_message_from_target,
            "Target.didCommitProvisionalTarget": self._target_did_commit_provisional_target,
        }
        self.to_cdp_special_dispatched_messages_methods = {
            "Console.messageRepeatCountUpdated": self._console_message_repeat_count_updated,
            "Debugger.scriptParsed": self._debugger_script_parsed,
            "Debugger.scriptFailedToParse": self._debugger_script_failed_to_parse,
            "Debugger.paused": self._debugger_paused,
            "Debugger.globalObjectCleared": self._debugger_global_object_cleared,
            "Page.defaultAppearanceDidChange": self._page_default_appearance_did_change,
            "Runtime.executionContextCreated": self._runtime_execution_context_created,
            "Console.messageAdded": self._console_message_added,
            "Network.responseReceived": self._network_response_received,
            "Network.loadingFinished": self._network_loading_finished,
        }
        # JavaScriptCore's JSContext inspector implements no Target domain at all: nothing is
        # announced on attach, messages are exchanged as-is instead of through
        # Target.sendMessageToTarget/Target.dispatchMessageFromTarget, and its replies - carrying a
        # top-level id - are filed by the inspector into wir_message_results rather than
        # wir_events. Talk to it directly and translate everything else the same way.
        self._flat = protocol.page.type_ == WirTypes.JAVASCRIPT
        # wire id -> the id the message was sent with, for the un-multiplexed path
        self._flat_pending: dict[int, int] = {}
        self._waiting_for_id = 0
        self._input_task = asyncio.create_task(self._input_loop())
        self._receiving_task = asyncio.create_task(self._receive_loop())
        self._script_source_to_context_id: dict[str, Any] = {}
        # scriptId -> url, from Debugger.scriptParsed; used to fill the `url` WebKit omits from the
        # callFrames of Debugger.paused (Chrome's CallFrame requires it).
        self._script_id_to_url: dict[str, str] = {}
        self._eval_side_effect_id = 0
        self._default_execution_id = 0
        self._last_console_api_call: Optional[dict[str, Any]] = None
        self._internal_id = 0
        # loop time of the last synthesized hover, to throttle high-frequency mouseMoved events.
        self._last_mousemove_time = 0.0
        # execution-context uniqueIds already announced to the frontend, to drop duplicate
        # Runtime.executionContextCreated events (WebKit re-announces contexts) that would
        # otherwise corrupt Chrome's RuntimeModel.
        self._emitted_context_unique_ids: set[str] = set()
        # Runtime.compileScript synthesizes a scriptId (WebKit has no compileScript); persisted
        # scripts are kept here so a later Runtime.runScript can execute their source.
        self._compiled_script_counter = 0
        self._persisted_scripts: dict[str, str] = {}
        # id -> target the request was routed to, for synthesizing errors when that target dies
        self._pending_requests: dict[int, str] = {}
        self._destroyed_targets: set[str] = set()
        # Targets that stopped answering our internal requests (e.g. a page wedged on a native
        # app-open interstitial that WebKit refuses to navigate). Further internal requests to
        # them fast-fail instead of each blocking the receive loop for WIR_RESULT_TIMEOUT, which
        # would otherwise freeze the whole session. Cleared as soon as the target answers again
        # (an inbound event, or a periodic re-probe) so a merely-slow page is not stuck flagged.
        self._unresponsive_targets: set[str] = set()
        # loop time of the last re-probe attempt per unresponsive target, to rate-limit re-probes.
        self._unresponsive_last_probe: dict[str, float] = {}
        # setup (domain enables & co.) the frontend established, replayed onto new targets
        self._setup_messages: dict[Any, dict[str, Any]] = {}
        self._setup_sent_targets: set[str] = {target_id}

    def next_internal_id(self) -> int:
        """
        Allocate a unique id for a request we originate ourselves (screencast, sub-queries).

        Negative so it can never collide with a frontend message id; unique so concurrent
        internal requests don't consume each other's responses in wait_for_event_id (a fixed,
        reused id let a slow evaluate response be mis-matched to a snapshotRect wait, which
        silently killed the screencast).
        """
        self._internal_id -= 1
        return self._internal_id

    @classmethod
    async def create(cls, protocol: SessionProtocol) -> "CdpTarget":
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        await protocol.inspector.setup_inspector_socket(protocol.id_, protocol.app.id_, protocol.page.id_)
        if protocol.page.type_ == WirTypes.JAVASCRIPT:
            # A JSContext debuggable has no Target domain, so it announces nothing on attach and
            # there is only ever the one target - synthesize its id instead of waiting forever.
            return cls(protocol, f"jscontext:{protocol.app.id_}:{protocol.page.id_}")
        events = protocol.inspector.session_events(protocol.id_)
        while True:
            if not events:
                await asyncio.sleep(0)
                continue
            created = events.pop(0)
            if "targetInfo" in created.get("params", {}):
                break
        target_id = created["params"]["targetInfo"]["targetId"]
        logger.info(f"Created: {target_id}")
        # The raw WIR Target.targetCreated is NOT forwarded: its targetInfo lacks the fields
        # Chrome's schema requires (type/title/url/attached) and crashes the frontend's SDK.
        return cls(protocol, target_id)

    async def close(self) -> None:
        """
        Stop the queue-consumer tasks and any running screencast, and tear down the WIR socket.
        """
        if self.screencast is not None:
            await self.screencast.stop()
            self.screencast = None
        for task in (self._input_task, self._receiving_task):
            task.cancel()
        await asyncio.gather(self._input_task, self._receiving_task, return_exceptions=True)
        # Without the teardown, webinspectord ignores the next socket setup for this page and
        # the following debugger connection never receives its Target.targetCreated event.
        await self.protocol.inspector.teardown_inspector_socket(self.session_id, self.app_id, self.page_id)

    async def send(self, message: dict[str, Any]):
        """
        Send message from devtools to the target.
        """
        await self.input_queue.put(message)

    async def receive(self) -> dict[str, Any]:
        """
        Get message from the target to the devtools.
        """
        return await self.output_queue.get()

    async def wait_for_event_id(
        self, id_: int, target_id: Optional[str] = None, timeout: float = WIR_RESULT_TIMEOUT
    ) -> Optional[dict[str, Any]]:
        """
        Wait for a message with a specific id from the target.
        :param id_: Message id to wait for.
        :param target_id: Target the request was routed to; the wait is abandoned as soon as that
            target is destroyed (WebKit never answers requests of a destroyed target, so waiting
            out the full timeout would only stall the paused receive loop).
        :param timeout: Seconds to wait before giving up (shorter for re-probes of a target already
            believed unresponsive, so a still-dead one barely re-pauses the receive loop).
        :returns: The matching target message, or None if it does not arrive within the timeout.
        """
        if self._flat:
            return await self._wait_for_flat_result(id_, timeout)
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if target_id is not None and target_id in self._destroyed_targets:
                return None
            events = self.protocol.inspector.session_events(self.session_id)
            for i in range(len(events)):
                message = events[i]
                if message["method"] == "Target.targetDestroyed":
                    # Only give up the wait; the event stays queued for the receive loop.
                    if message["params"]["targetId"] == target_id:
                        return None
                    continue
                if message["method"] != "Target.dispatchMessageFromTarget":
                    continue
                message = json.loads(message["params"]["message"])
                if message.get("id", "") != id_:
                    continue
                del events[i]
                self._pending_requests.pop(id_, None)
                return message
            await asyncio.sleep(0)
        return None

    async def send_message_with_result(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """
        Send a self-originated request to the target and wait for its response.

        A unique internal id is allocated per call so concurrent sub-requests (screen input
        synthesis, object inspection, script parsing, ...) never consume each other's responses;
        reusing the frontend's message id let a slow response be matched to the wrong wait, which
        stalled the receive loop and hung the console. Returns an empty dict if the device never
        answers. The wait is bounded and _waiting_for_id is always released: while it is held the
        receive loop is paused, so a lost response would otherwise starve every later event.
        """
        target_id = self.target_id
        timeout = WIR_RESULT_TIMEOUT
        if target_id in self._unresponsive_targets:
            # Believed dead: fast-fail without holding the receive loop, except let one request
            # through every UNRESPONSIVE_REPROBE_INTERVAL to notice a target that came back but is
            # otherwise silent (a slow page finished loading, an interstitial finally redirected).
            now = asyncio.get_event_loop().time()
            if now - self._unresponsive_last_probe.get(target_id, 0.0) < UNRESPONSIVE_REPROBE_INTERVAL:
                logger.debug(f"skipping {method}: target {target_id} is unresponsive")
                return {}
            self._unresponsive_last_probe[target_id] = now
            timeout = UNRESPONSIVE_PROBE_TIMEOUT
        id_ = self.next_internal_id()
        self._waiting_for_id += 1
        try:
            await self._send_message_to_target({"id": id_, "method": method, "params": params})
            result = await self.wait_for_event_id(id_, target_id, timeout)
            if result is None:
                self._pending_requests.pop(id_, None)
                if target_id not in self._destroyed_targets:
                    # Mark (or keep) it unresponsive so the next request fast-fails instead of
                    # blocking another timeout; a destroyed target is handled elsewhere.
                    if target_id not in self._unresponsive_targets:
                        logger.warning(f"target {target_id} stopped responding ({method}); backing off")
                    self._unresponsive_targets.add(target_id)
                    # Rate-limit the next re-probe from the end of this attempt.
                    self._unresponsive_last_probe[target_id] = asyncio.get_event_loop().time()
                return {}
            # A reply proves the target is alive again; resume normal sending.
            self._mark_target_responsive(target_id)
            return result
        finally:
            self._waiting_for_id -= 1

    def _mark_target_responsive(self, target_id: str) -> None:
        """Clear the unresponsive flag once a target answers again."""
        self._unresponsive_targets.discard(target_id)
        self._unresponsive_last_probe.pop(target_id, None)

    @staticmethod
    def _tag_internal(expression: str) -> str:
        """Stamp a sourceURL on a bridge-originated evaluation so its scriptParsed can be dropped."""
        return f"{expression}\n//# sourceURL={INTERNAL_SCRIPT_URL}"

    async def evaluate_and_result(self, expression: str) -> Any:
        """
        Evaluate Javascript expression.
        """
        logger.debug(f"Evaluating: {expression}")
        params = {"expression": self._tag_internal(expression)}
        data = await self.send_message_with_result("Runtime.evaluate", params)
        logger.debug(f"Evaluated: {data}")
        if "result" not in data:
            return None
        result = data["result"]["result"]
        if result["type"] == "string":
            return result["value"]
        elif result["type"] == "undefined":
            return None
        elif result["type"] == "object":
            return result
        else:
            logger.debug(f"Unknown type: {result}")
            return result

    async def _input_loop(self):
        while True:
            message = await self.input_queue.get()
            try:
                if message["method"] in self.from_cdp_special_messages_methods:
                    await self.from_cdp_special_messages_methods[message["method"]](message)
                elif message["method"].split(".", 1)[0] in NOOP_ABSENT_DOMAINS:
                    # WebKit has no Input/Overlay domains at all; the few methods worth
                    # translating are in the special table above, so acknowledge the rest
                    # (mouse moves over the screencast, inspect-mode toggles, ...) instead of
                    # forwarding them and erroring.
                    await self._simple_response(message, None)
                else:
                    await self._send_message_to_target(message)
            except asyncio.CancelledError:
                raise
            except Exception:
                # One failing translation must not kill the session's input processing.
                logger.exception(f"Failed handling DevTools message: {message.get('method')}")
                if "id" in message:
                    await self.output_queue.put({
                        "id": message["id"],
                        "error": {"code": -32000, "message": f"pymobiledevice3 failed to handle {message['method']}"},
                    })

    async def _receive_loop(self):
        while True:
            if self._waiting_for_id:
                await asyncio.sleep(0)
                continue
            message = self._next_message()
            if message is None:
                await asyncio.sleep(0)
                continue
            try:
                if self._flat:
                    # No Target wrapper to unwrap: these already are the debuggable's own
                    # protocol messages.
                    await self._dispatch_target_message(message)
                else:
                    await self._to_output_queue(message)
            except asyncio.CancelledError:
                raise
            except Exception:
                # One failing event translation must not kill the whole receive loop - that
                # silently starves every later response and the session appears dead.
                logger.exception(f"Failed handling target event: {message.get('method')}")

    def _next_message(self) -> Optional[dict[str, Any]]:
        """Next message to translate, or None while there is nothing pending."""
        if self._flat:
            result = self._next_flat_result()
            if result is not None:
                return result
        events = self.protocol.inspector.session_events(self.session_id)
        if not events:
            return None
        return cast(dict[str, Any], events.pop(0))

    async def _to_output_queue(self, message: dict[str, Any]):
        if message["method"] != "Target.dispatchMessageFromTarget":
            logger.debug(f"WIR EVENT: {message}")
        if message["method"] in self.to_cdp_special_messages_methods:
            await self.to_cdp_special_messages_methods[message["method"]](message)
        else:
            logger.error(f"Unknown target event: {message}")

    async def _send_message_to_target(
        self, message: dict[str, Any], target_id: Optional[str] = None, record: bool = True
    ):
        resolved_target_id = target_id if target_id is not None else self.target_id
        if "id" in message:
            self._pending_requests[message["id"]] = resolved_target_id
        if record:
            self._record_setup_message(message)
        if self._flat:
            await self._send_message_flat(message)
            return
        await self.protocol.send_command(
            "Target.sendMessageToTarget", targetId=resolved_target_id, message=json.dumps(message)
        )

    async def _send_message_flat(self, message: dict[str, Any]) -> None:
        """Send straight to an un-multiplexed debuggable, under a wire id of our own (see
        _FLAT_WIRE_IDS) that the reply is mapped back from."""
        wire = dict(message)
        if "id" in message:
            wire_id = next(_FLAT_WIRE_IDS)
            self._flat_pending[wire_id] = message["id"]
            wire["id"] = wire_id
        await self.protocol.inspector.send_socket_data(self.session_id, self.app_id, self.page_id, wire)

    def _next_flat_result(self, id_: Optional[int] = None) -> Optional[dict[str, Any]]:
        """Take one reply this target is still waiting for off the inspector's result table, with
        its wire id mapped back to the id it was sent with. `id_` restricts the search to the reply
        of that request; without it, the first available one is taken.

        :returns: The reply, or None if none of the awaited ones arrived yet.
        """
        results = self.protocol.inspector.wir_message_results
        for wire_id, original_id in list(self._flat_pending.items()):
            if (id_ is not None and original_id != id_) or wire_id not in results:
                continue
            del self._flat_pending[wire_id]
            message = cast(dict[str, Any], results.pop(wire_id))
            message["id"] = original_id
            return message
        return None

    async def _wait_for_flat_result(self, id_: int, timeout: float) -> Optional[dict[str, Any]]:
        """wait_for_event_id for the un-multiplexed path: replies arrive on the inspector's result
        table rather than as Target.dispatchMessageFromTarget events."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            message = self._next_flat_result(id_)
            if message is not None:
                self._pending_requests.pop(id_, None)
                return message
            await asyncio.sleep(0)
        return None

    def _record_setup_message(self, message: dict[str, Any]):
        """
        Remember per-target setup so it can be re-established on the fresh target after a process
        swap. WebKit expects the inspector frontend to re-initialize every new target, but Chrome
        knows nothing of WebKit's target multiplexing, so the bridge must replay it.
        """
        method = message.get("method", "")
        params = message.get("params", {})
        if method.endswith(".enable") or method in REPLAYED_SETUP_METHODS:
            self._setup_messages[method] = params
        elif method in REPLAYED_MULTI_SETUP_METHODS:
            self._setup_messages[(method, json.dumps(params, sort_keys=True))] = params

    async def _send_setup_to_target(self, target_id: str):
        """Replay the frontend's recorded setup onto a new target (once per target)."""
        if target_id in self._setup_sent_targets:
            return
        self._setup_sent_targets.add(target_id)
        for key, params in list(self._setup_messages.items()):
            method = key if isinstance(key, str) else key[0]
            await self._send_message_to_target(
                {"id": self.next_internal_id(), "method": method, "params": params},
                target_id=target_id,
                record=False,
            )

    async def _simple_response(self, message: dict[str, Any], value: Any):
        await self.output_queue.put({"id": message["id"], "result": {"result": value}})

    async def _result_response(self, message: dict[str, Any], result: dict[str, Any]):
        """Respond with an exact result body, for methods whose response fields the frontend reads."""
        await self.output_queue.put({"id": message["id"], "result": result})

    async def _audits_enable(self, message: dict[str, Any]):
        # A previous inspector session may have left an audit configured; WebKit then rejects
        # setup with "Must call teardown before calling setup again", so always reset first.
        await self.send_message_with_result("Audit.teardown", {})
        message["method"] = "Audit.setup"
        message["params"] = {}
        await self._send_message_to_target(message)

    async def _page_navigate(self, message: dict[str, Any]):
        """WebKit has no Page.navigate; navigate in-page instead (URL bar / reload in DevTools)."""
        url = json.dumps(message["params"]["url"])
        await self.evaluate_and_result(f"location.href = {url}")
        await self.output_queue.put({"id": message["id"], "result": {"frameId": self.frame.get("id", "")}})

    async def _dom_push_nodes_by_backend_ids(self, message: dict[str, Any]):
        await self.output_queue.put({"id": message["id"], "result": {"nodeIds": []}})

    async def _runtime_get_properties(self, message: dict[str, Any]):
        """
        WebKit answers Runtime.getProperties with a 'properties' array; Chrome's frontend reads
        'result' and renders "No properties" otherwise. WebKit also lacks the
        accessorPropertiesOnly/nonIndexedPropertiesOnly filters, so apply them here.
        """
        params = message["params"]
        response = await self.send_message_with_result(
            "Runtime.getProperties",
            {
                "objectId": params["objectId"],
                "ownProperties": params.get("ownProperties", False),
                "generatePreview": params.get("generatePreview", False),
            },
        )
        if "result" not in response:
            await self.output_queue.put({"id": message["id"], "result": {"result": []}})
            return
        properties: list[dict[str, Any]] = response["result"].get("properties", [])
        if params.get("accessorPropertiesOnly", False):
            properties = [p for p in properties if "get" in p or "set" in p]
        if params.get("nonIndexedPropertiesOnly", False):
            properties = [p for p in properties if not p.get("name", "").isdigit()]
        for prop in properties:
            prop.setdefault("configurable", False)
            prop.setdefault("enumerable", False)
        # Expanded objects list function properties whose native descriptions the console
        # autocomplete inspects; normalize them (see _normalize_native_functions).
        self._normalize_native_functions(properties)
        result: dict[str, Any] = {"result": properties}
        if "internalProperties" in response["result"]:
            result["internalProperties"] = response["result"]["internalProperties"]
        await self.output_queue.put({"id": message["id"], "result": result})

    async def _runtime_global_lexical_scope_names(self, message: dict[str, Any]):
        """
        WebKit lacks Runtime.globalLexicalScopeNames (console autocomplete asks for global
        let/const/class names). Those are not enumerable from page JavaScript, and window
        properties are already covered by the frontend's regular completion path.
        """
        await self.output_queue.put({"id": message["id"], "result": {"names": []}})

    async def _css_get_platform_fonts(self, message: dict[str, Any]):
        await self.output_queue.put({"id": message["id"], "result": {"fonts": []}})

    async def _page_add_script_to_evaluate_on_new_document(self, message: dict[str, Any]):
        await self.output_queue.put({"id": message["id"], "result": {"identifier": "1"}})

    async def _dom_get_box_model(self, message: dict[str, Any]):
        message["method"] = "DOM.highlightNode"
        message["params"]["highlightConfig"] = {
            "showInfo": True,
            "contentColor": {"r": 111, "g": 168, "b": 220, "a": 0.66},
            "paddingColor": {"r": 147, "g": 196, "b": 125, "a": 0.55},
            "borderColor": {"r": 255, "g": 229, "b": 153, "a": 0.66},
            "marginColor": {"r": 246, "g": 178, "b": 107, "a": 0.66},
        }
        await self._send_message_to_target(message)

    async def object_id_to_node_id(self, object_id: str):
        node = await self.send_message_with_result("DOM.requestNode", {"objectId": object_id})
        return node["result"]["nodeId"]

    async def _dom_get_node_for_location(self, message: dict[str, Any]):
        x, y = message["params"]["x"], message["params"]["y"]
        obj = await self.evaluate_and_result(f"document.elementFromPoint({x},{y})")
        if obj is None or "objectId" not in obj:
            await self._simple_response(message, None)
            return
        result = {"nodeId": await self.object_id_to_node_id(obj["objectId"])}
        await self.output_queue.put({"id": message["id"], "result": result})

    async def _dom_get_nodes_for_subtree_by_style(self, message: dict[str, Any]):
        object_id = (await self.send_message_with_result("DOM.resolveNode", {"nodeId": message["params"]["nodeId"]}))[
            "result"
        ]["object"]["objectId"]
        result = await self.send_message_with_result(
            "Runtime.callFunctionOn",
            {
                "objectId": object_id,
                "functionDeclaration": (
                    "function(styles) {"
                    "   const result = new Set();"
                    '   var all = this.getElementsByTagName("*");'
                    "   for (var elem_i=0; elem_i < all.length; elem_i++) {"
                    "       for (var style_i in styles) {"
                    "           if (window.getComputedStyle(all[elem_i]).getPropertyValue(styles[style_i].name) ==="
                    " styles[style_i].value) {"
                    "               result.add(all[elem_i]);"
                    "               break;"
                    "           }"
                    "       }"
                    "   }"
                    "   return result;"
                    "}"
                ),
                "arguments": [{"value": message["params"]["computedStyles"]}],
            },
        )
        result = await self.send_message_with_result(
            "Runtime.getCollectionEntries", {"objectId": result["result"]["result"]["objectId"]}
        )
        nodes = await asyncio.gather(
            *[self.object_id_to_node_id(obj["value"]["objectId"]) for obj in result["result"]["entries"]],
            return_exceptions=True,
        )
        nodes = [n for n in nodes if isinstance(n, int)]
        await self.output_queue.put({"id": message["id"], "result": {"nodeIds": nodes}})

    async def _log_clear(self, message: dict[str, Any]):
        message["method"] = "Console.clearMessages"
        await self._send_message_to_target(message)

    async def _log_disable(self, message: dict[str, Any]):
        message["method"] = "Console.disable"
        await self._send_message_to_target(message)

    async def _log_enable(self, message: dict[str, Any]):
        message["method"] = "Console.enable"
        await self._send_message_to_target(message)

    async def _page_get_navigation_history(self, message: dict[str, Any]):
        href = await self.evaluate_and_result("window.location.href")
        title = await self.evaluate_and_result("document.title")
        # evaluate_and_result returns None when the device does not answer in time (common during
        # the initial setup handshake, when the page is still busy). A null url crashes the whole
        # screencast panel - ScreencastView.requestNavigationHistory does url.match(HTTP_REGEX) on
        # each entry - which manifests as a blank "no screen" inspector. Never emit null: fall back
        # to the page's advertised URL, and coerce a missing title to an empty string.
        if not isinstance(href, str) or not href:
            href = self.protocol.page.web_url or "about:blank"
        if not isinstance(title, str):
            title = ""
        await self.output_queue.put({
            "id": message["id"],
            "result": {"currentIndex": 0, "entries": [{"id": 0, "url": href, "title": title}]},
        })

    async def _page_start_screencast(self, message: dict[str, Any]):
        params = message["params"]
        self.screencast = ScreenCast(self, params["format"], params["quality"], params["maxWidth"], params["maxHeight"])
        await self.screencast.start()
        await self._simple_response(message, None)

    async def _page_stop_screencast(self, message: dict[str, Any]):
        if self.screencast is not None:
            await self.screencast.stop()
            self.screencast = None
        await self._simple_response(message, None)

    async def _page_screencast_frame_ack(self, message: dict[str, Any]):
        if self.screencast is not None:
            self.screencast.ack(message["params"]["sessionId"])
        await self._simple_response(message, None)

    async def _page_get_resource_tree(self, message: dict[str, Any]):
        result = await self.send_message_with_result(message["method"], message["params"])
        self.frame = result["result"]["frameTree"]["frame"]
        # result carries our internal request id; answer the frontend with its own id.
        await self.output_queue.put({"id": message["id"], "result": result["result"]})

    async def _emulation_set_emulated_media(self, message: dict[str, Any]):
        message["method"] = "Page.setEmulatedMedia"
        await self._send_message_to_target(message)

    async def _emulation_set_auto_dark_mode_override(self, message: dict[str, Any]):
        message["method"] = "Page.setForcedAppearance"
        params = message["params"]
        if not params:
            await self._simple_response(message, None)
            return
        message["params"] = {"appearance": "Dark" if params["enabled"] else "Light"}
        await self._send_message_to_target(message)

    async def _debugger_enable(self, message: dict[str, Any]):
        await self._send_message_to_target(message)
        # Two WebKit quirks conspire to make the debugger never stop, and Chrome's frontend papers
        # over neither because its own backend behaves differently:
        #   1. Chrome assumes breakpoints default to ACTIVE and only sends setBreakpointsActive when
        #      the user *deactivates* them; WebKit deactivates breakpoints on enable, so nothing -
        #      breakpoints or `debugger;` - ever pauses until setBreakpointsActive(true) is sent.
        #   2. Pausing on `debugger;` is separately gated behind setPauseOnDebuggerStatements, which
        #      defaults OFF and has no Chrome equivalent (Chrome pauses on `debugger;` whenever the
        #      debugger is attached and breakpoints are active).
        # Establish both on enable; they are kept in sync with the frontend's toggle below and
        # replayed onto fresh targets after a process swap.
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Debugger.setBreakpointsActive",
            "params": {"active": True},
        })
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Debugger.setPauseOnDebuggerStatements",
            "params": {"enabled": True},
        })

    async def _debugger_set_breakpoints_active(self, message: dict[str, Any]):
        # Chrome's "Deactivate breakpoints" toggle also suppresses `debugger;` statements; mirror
        # that by keeping WebKit's separate pause-on-debugger-statements setting in lockstep.
        active = message["params"].get("active", True)
        await self._send_message_to_target(message)
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Debugger.setPauseOnDebuggerStatements",
            "params": {"enabled": active},
        })

    async def _debugger_set_blackbox_patterns(self, message: dict[str, Any]):
        for pattern in message["params"]["patterns"]:
            await self.send_message_with_result(
                "Debugger.setShouldBlackboxURL", {"url": pattern, "shouldBlackbox": True}
            )
        await self._simple_response(message, None)

    async def _debugger_set_breakpoint_by_url(self, message: dict[str, Any]):
        condition = message["params"].pop("condition", "")
        if condition:
            message["params"]["options"]["condition"] = condition
        await self._send_message_to_target(message)

    async def _domdebugger_get_event_listeners(self, message: dict[str, Any]):
        node = {"nodeId": await self.object_id_to_node_id(message["params"]["objectId"])}
        listeners = await self.send_message_with_result("DOM.getEventListenersForNode", node)
        if "error" in listeners:
            await self._simple_response(message, None)
            return
        listeners_out: list[dict[str, Any]] = []
        for listener in listeners["result"]["listeners"]:
            data = {
                "type": listener["type"],
                "useCapture": listener["useCapture"],
                "passive": listener.get("passive", False),
                "once": listener.get("once", False),
            }
            if "location" in listener:
                data["scriptId"] = listener["location"]["scriptId"]
                data["lineNumber"] = listener["location"]["lineNumber"]
                data["columnNumber"] = listener["location"]["columnNumber"]
            listeners_out.append(data)
        await self.output_queue.put({"id": message["id"], "result": {"listeners": listeners_out}})

    async def _network_set_cache_disabled(self, message: dict[str, Any]):
        message["method"] = "Network.setResourceCachingDisabled"
        message["params"] = {"disabled": message["params"]["cacheDisabled"]}
        await self._send_message_to_target(message)

    async def _network_load_network_resource(self, message: dict[str, Any]):
        await self.output_queue.put({"id": message["id"], "result": {"resource": {"success": True}}})

    async def _service_worker_enable(self, message: dict[str, Any]):
        message["method"] = "Worker.enable"
        await self._send_message_to_target(message)

    async def _overlay_highlight_node(self, message: dict[str, Any]):
        message["method"] = "DOM.highlightNode"
        await self._send_message_to_target(message)

    async def _runtime_enable(self, message: dict[str, Any]):
        await self._send_message_to_target(message)
        if not self._flat:
            return
        # Chrome's frontend expects console output to follow from Runtime.enable alone (V8 emits
        # Runtime.consoleAPICalled once the Runtime domain is on) and never enables a console
        # domain on a JavaScript-only target - it sends Log.enable only for frame targets. WebKit
        # gates Console.messageAdded behind Console.enable, so without this every console.log on
        # the debuggable is silently dropped.
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Console.enable",
            "params": {},
        })
        if JS_CONTEXT_UNIQUE_ID in self._emitted_context_unique_ids:
            return
        # A JSContext debuggable announces no execution context - JavaScriptCore's inspector has no
        # Page/frame model to hang one on - and Chrome's frontend will not evaluate anything before
        # it knows one: the console prompt silently swallows every line while its context picker
        # reads "Not selected". Announce the single context such a debuggable has, the way V8 does
        # for a Node.js target.
        self._emitted_context_unique_ids.add(JS_CONTEXT_UNIQUE_ID)
        self._default_execution_id = JS_CONTEXT_EXECUTION_ID
        await self.output_queue.put({
            "method": "Runtime.executionContextCreated",
            "params": {
                "context": {
                    "id": JS_CONTEXT_EXECUTION_ID,
                    "origin": "",
                    "name": "",
                    "uniqueId": JS_CONTEXT_UNIQUE_ID,
                    "auxData": {"isDefault": True},
                }
            },
        })

    async def _runtime_evaluate(self, message: dict[str, Any]):
        # Chrome's console "eager evaluation" previews the current line as you type by evaluating it
        # with throwOnSideEffect=true, relying on V8 to ABORT the moment the expression would cause a
        # side effect (so `console.log(4234)` shows no preview and does NOT log until Enter). WebKit's
        # Runtime.evaluate has no such guard, so forwarding it runs the line for real - the console
        # logs/mutates while typing. Refuse the preview the way V8 does for a side-effecting
        # expression: report a side-effect error so DevTools shows no preview and nothing executes.
        # The real evaluation triggered by Enter carries no throwOnSideEffect and is forwarded.
        #
        # Autocomplete shares the same throwOnSideEffect evaluate, but on *sub-expressions* (the base
        # object for the completion list, the callee for the argument hint) under a dedicated
        # objectGroup. Those are side-effect-free identifier lookups the dropdown needs, so let them
        # through - refusing them would kill autocomplete. Only the eager preview (no completion
        # objectGroup) is refused.
        params = message["params"]
        if self._flat:
            # The context the frontend targets is the one synthesized in _runtime_enable, which the
            # debuggable knows nothing about; addressing it explicitly would fail the lookup. It has
            # exactly one context anyway - let it use its default.
            params.pop("contextId", None)
            params.pop("uniqueContextId", None)
        if params.get("throwOnSideEffect") and params.get("objectGroup") not in _COMPLETION_OBJECT_GROUPS:
            self._eval_side_effect_id += 1
            error_object = {
                "type": "object",
                "subtype": "error",
                "className": "EvalError",
                "description": "EvalError: Possible side-effect in debug-evaluate",
            }
            await self.output_queue.put({
                "id": message["id"],
                "result": {
                    "result": error_object,
                    "exceptionDetails": {
                        "exceptionId": self._eval_side_effect_id,
                        "text": "Uncaught",
                        "lineNumber": 0,
                        "columnNumber": 0,
                        "exception": error_object,
                    },
                },
            })
            return
        await self._send_message_to_target(message)

    async def _runtime_compile_script(self, message: dict[str, Any]):
        self._script_source_to_context_id[message["params"]["expression"]] = message["params"]["executionContextId"]
        response = await self.send_message_with_result("Runtime.parse", {"source": message["params"]["expression"]})
        result = response.get("result")
        # send_message_with_result returns {} when the device is busy/unresponsive (e.g. mid-flood
        # on a chatty page). This handler runs on every console keystroke; a missing result must
        # not raise (it would break compilation and wedge the console's eager evaluation). Treat an
        # absent or "no error" parse as a clean compile and answer with Chrome's schema (an empty
        # result object for a non-persisted script), not a bogus {"result": null}.
        if not result or result.get("result") == "none":
            # Compiled cleanly. Runtime.compileScript's response REQUIRES a scriptId (per the CDP
            # spec); omitting it makes Chrome's console treat the compile as unfinished and re-send
            # compileScript in a tight loop until the frontend wedges. Mint one, and remember the
            # source so a later Runtime.runScript (persistScript=true) can still execute it.
            self._compiled_script_counter += 1
            script_id = f"pmd-compiled-{self._compiled_script_counter}"
            if message["params"].get("persistScript"):
                self._persisted_scripts[script_id] = message["params"]["expression"]
            await self.output_queue.put({"id": message["id"], "result": {"scriptId": script_id}})
            return
        lines = message["params"]["expression"][: result["range"]["endOffset"]].splitlines()
        lines = lines if lines else [""]
        await self.output_queue.put({
            "id": message["id"],
            "result": {
                "exceptionDetails": {
                    "exceptionId": 1,
                    "text": result["message"],
                    "lineNumber": len(lines) - 1,
                    "columnNumber": len(lines[-1]) - 1,
                }
            },
        })

    async def _runtime_run_script(self, message: dict[str, Any]):
        # WebKit has no compileScript/runScript; execute the source we stashed at compile time.
        source = self._persisted_scripts.get(message["params"].get("scriptId", ""))
        if source is None:
            await self.output_queue.put({"id": message["id"], "result": {"result": {"type": "undefined"}}})
            return
        response = await self.send_message_with_result("Runtime.evaluate", {"expression": source})
        await self.output_queue.put({
            "id": message["id"],
            "result": response.get("result", {"result": {"type": "undefined"}}),
        })

    async def _runtime_get_isolate_id(self, message: dict[str, Any]):
        await self.output_queue.put({"id": message["id"], "result": {"id": self._default_execution_id}})

    async def _target_set_auto_attach(self, message: dict[str, Any]):
        # Only acknowledge. Emitting a fabricated Target.attachedToTarget (with a sessionId and
        # a partial targetInfo) crashes the frontend's SDK and progressively breaks the console.
        await self._simple_response(message, None)

    async def _css_take_computed_style_updates(self, message: dict[str, Any]):
        await self.output_queue.put({"id": message["id"], "result": {"nodeIds": []}})

    async def _css_add_rule(self, message: dict[str, Any]):
        message["params"]["selector"] = message["params"]["ruleText"].split("{")[0]
        await self._send_message_to_target(message)

    def _screencast_scale(self) -> float:
        return self.screencast.get_scale() if self.screencast is not None else 1.0

    def _mouse_event_js(self, type_: str, x: int, y: int, modifiers: int, button: int) -> str:
        """Build the in-page expression that dispatches a synthesized mouse event at (x, y)."""
        event_params = json.dumps({
            "screenX": x,
            "screenY": y,
            "clientX": x,
            "clientY": y,
            "altKey": bool(modifiers & 1),
            "ctrlKey": bool(modifiers & 2),
            "metaKey": bool(modifiers & 4),
            "shiftKey": bool(modifiers & 8),
            "button": button,
            "bubbles": True,
            "cancelable": True,
        })
        simulate_mouse_event = (
            "function simulateMouseEvent(type){"
            f"const element = document.elementFromPoint({x}, {y});"
            "if (element === null) { return null; }"
            f"const e = new MouseEvent(type, JSON.parse('{event_params}'));"
            "element.dispatchEvent(e);"
            "element.focus();"
            "return e;}"
        )
        return f'({simulate_mouse_event})("{type_}")'

    async def _synthesize_mouse_event(self, type_: str, x: int, y: int, modifiers: int, button: int):
        await self.evaluate_and_result(self._mouse_event_js(type_, x, y, modifiers, button))
        if type_ == "click":
            await self.evaluate_and_result(self._mouse_event_js("mouseup", x, y, modifiers, button))

    async def _send_evaluate_noreply(self, expression: str) -> None:
        """
        Fire-and-forget page evaluate for high-frequency screencast input (hover, scroll).

        Waiting for the device (send_message_with_result) holds _waiting_for_id and pauses the
        receive loop; doing that per pointer move floods webinspectord and, on a chatty page,
        starves every incoming event. We don't need the result, so just send and move on; the
        (negative-id) reply is dropped by _target_dispatch_message_from_target.
        """
        if self.target_id in self._unresponsive_targets:
            return
        await self._send_message_to_target(
            {
                "id": self.next_internal_id(),
                "method": "Runtime.evaluate",
                "params": {"expression": self._tag_internal(expression)},
            },
            record=False,
        )

    async def _input_emulate_touch_from_mouse_event(self, message: dict[str, Any]):
        params = message["params"]
        scale = self._screencast_scale()
        if params["type"] == "mouseWheel":
            delta_x, delta_y = params["deltaX"] // scale, params["deltaY"] // scale
            await self.evaluate_and_result(f"window.scrollBy({-delta_x}, {-delta_y})")
        elif params["type"] == "mouseReleased":
            pass
        else:
            x, y = int(params["x"] // scale), int(params["y"] // scale)
            type_ = {"mousePressed": "click", "mouseMoved": "mousemove"}[params["type"]]
            await self._synthesize_mouse_event(type_, x, y, params["modifiers"], params["button"])

        await self._simple_response(message, None)

    async def _input_dispatch_mouse_event(self, message: dict[str, Any]):
        """
        Modern DevTools drives the screencast with Input.dispatchMouseEvent (the legacy
        Input.emulateTouchFromMouseEvent is no longer sent); WebKit has no Input domain,
        so synthesize the events in-page like the legacy handler does.
        """
        params = message["params"]
        scale = self._screencast_scale()
        type_ = params["type"]
        if type_ == "mouseWheel":
            # Scrolling is frequent; don't block the receive loop waiting for the device.
            delta_x, delta_y = params.get("deltaX", 0) // scale, params.get("deltaY", 0) // scale
            await self._send_evaluate_noreply(f"window.scrollBy({-delta_x}, {-delta_y})")
        elif type_ == "mouseMoved":
            # Hover: throttle (DevTools streams dozens/sec) and never block on the device.
            now = asyncio.get_event_loop().time()
            if now - self._last_mousemove_time >= MOUSEMOVE_MIN_INTERVAL:
                self._last_mousemove_time = now
                x, y = int(params["x"] // scale), int(params["y"] // scale)
                await self._send_evaluate_noreply(
                    self._mouse_event_js("mousemove", x, y, params.get("modifiers", 0), 0)
                )
        elif type_ == "mousePressed":
            # Clicks are low-frequency and must land in order (focus, submit), so keep them synchronous.
            x, y = int(params["x"] // scale), int(params["y"] // scale)
            button = {"none": 0, "left": 0, "middle": 1, "right": 2, "back": 3, "forward": 4}.get(
                params.get("button", "none"), 0
            )
            await self._synthesize_mouse_event("click", x, y, params.get("modifiers", 0), button)

        await self._simple_response(message, None)

    async def _input_dispatch_key_event(self, message: dict[str, Any]):
        params = message["params"]
        key = params["key"]
        if params["type"] == "keyUp" and key == "Backspace":
            manipulation = (
                "document.activeElement.value = document.activeElement.value.slice(0, -1);"
                "document.activeElement.dispatchEvent("
                "    new InputEvent('input', {bubbles: true, inputType: 'deleteContentBackward'}));"
            )
        elif params["type"] == "char" and key == "Enter":
            # The page's own Enter handling must run first (e.g. google fires its search from a
            # keydown listener on a <textarea> and prevents the default); only when the page
            # leaves the events unhandled fall back to what a browser would do by default.
            manipulation = (
                "const enterInit = {key: 'Enter', code: 'Enter', bubbles: true, cancelable: true};"
                "const keydown = new KeyboardEvent('keydown', enterInit);"
                "const keypress = new KeyboardEvent('keypress', enterInit);"
                "for (const event of [keydown, keypress]) {"
                "    Object.defineProperty(event, 'keyCode', {get: () => 13});"
                "    Object.defineProperty(event, 'which', {get: () => 13});"
                "}"
                "const prevented = !document.activeElement.dispatchEvent(keydown)"
                "    || !document.activeElement.dispatchEvent(keypress);"
                "document.activeElement.dispatchEvent("
                "    new KeyboardEvent('keyup', {key: 'Enter', code: 'Enter', bubbles: true}));"
                "if (!prevented) {"
                "    var tagName = document.activeElement.tagName.toLowerCase();"
                '    if (tagName === "textarea" || document.activeElement.isContentEditable) {'
                '        document.activeElement.value = document.activeElement.value + "\\n";'
                "    } else if (document.activeElement.form) {"
                "        const form = document.activeElement.form;"
                "        if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }"
                "    }"
                "}"
            )
        elif params["type"] == "char":
            text = params["text"]
            manipulation = (
                f'document.activeElement.value = document.activeElement.value + "{text}";'
                "document.activeElement.dispatchEvent("
                "    new InputEvent('input', {bubbles: true, inputType: 'insertText'}));"
            )
        else:
            await self._simple_response(message, None)
            return

        simulate_key_event = (
            "function isEditable(element) {"
            "    if (element.disabled || element.readOnly)"
            "        return false;"
            "    var tagName = element.tagName.toLowerCase();"
            '    if (tagName === "textarea" || element.isContentEditable)'
            "        return true;"
            '    if (tagName != "input")'
            "        return false;"
            "    switch (element.type) {"
            '    case "color": case "date": case "datetime-local": case "email": case "file": case "month": '
            '    case "number": case "password": case "range": case "search": case "tel": case "text": case "time": '
            '    case "url": case "week":'
            "        return true;"
            "    }"
            "    return false;"
            "}"
            "if (isEditable(document.activeElement)) {"
            f"{manipulation}"
            "}"
        )
        await self.evaluate_and_result(simulate_key_event)
        await self._simple_response(message, None)

    async def _target_created(self, message: dict[str, Any]):
        # These handlers run inside the receive loop; a device round-trip here (the old code
        # evaluated document.title/location.href) blocks delivery of every other event for the
        # whole session, and while a freshly navigated page is still loading it blocks until the
        # timeout. Rapid link navigation stacks those blocks until the session never catches up.
        # So emit a non-blocking, schema-complete targetInfo (a partial one crashes the frontend
        # SDK); the real url arrives via the device's own Page.frameNavigated.
        target_info = message["params"]["targetInfo"]
        new_target_id = target_info["targetId"]
        if not target_info.get("isProvisional", False):
            # A provisional target becomes current only on didCommitProvisionalTarget; routing
            # commands to it earlier loses them if the load never commits.
            self.target_id = new_target_id
        # New targets start with all agents disabled; without replaying the frontend's setup no
        # Network/Page/Console/Debugger event ever arrives again after a process swap and the
        # session appears dead after a couple of link clicks.
        await self._send_setup_to_target(new_target_id)
        await self.output_queue.put({
            "method": "Target.targetInfoChanged",
            "params": {
                "targetInfo": {
                    "targetId": new_target_id,
                    "type": "page",
                    "title": "",
                    "url": self.frame.get("url", ""),
                    "attached": True,
                    "canAccessOpener": False,
                }
            },
        })

    async def _target_destroyed(self, message: dict[str, Any]):
        destroyed_target_id = message["params"]["targetId"]
        self._destroyed_targets.add(destroyed_target_id)
        self._setup_sent_targets.discard(destroyed_target_id)
        self._mark_target_responsive(destroyed_target_id)
        # WebKit never answers requests routed to a destroyed target; resolve them with an error
        # (like Chrome's backend does on navigation) so the frontend's pending promises settle
        # instead of wedging whole panels. Internal (negative-id) waits abandon themselves via
        # _destroyed_targets.
        for id_, target_id in list(self._pending_requests.items()):
            if target_id != destroyed_target_id:
                continue
            del self._pending_requests[id_]
            if id_ >= 0:
                await self.output_queue.put({"id": id_, "error": dict(TARGET_CLOSED_ERROR)})
        # The device emits its own Page.frameNavigated for the new page, so no getResourceTree
        # round-trip is needed (and must not be done here - see _target_created). Just nudge the
        # frontend that the load finished and the document changed.
        await self.output_queue.put({
            "method": "Page.loadEventFired",
            # MonotonicTime, in seconds - not a formatted string
            "params": {"timestamp": datetime.now().timestamp()},
        })
        await self.output_queue.put({"method": "DOM.documentUpdated"})

    @staticmethod
    def _normalize_native_functions(obj: Any) -> None:
        """
        Collapse WebKit's multi-line native-function descriptions to Chrome's exact single-line
        form, in place and recursively. WebKit reports native functions as
        `function name() {\\n    [native code]\\n}`; the console's argument-hint autocomplete only
        treats a function as native when its description ends with the literal `{ [native code] }`
        (devtools-frontend front_end/ui/components/text_editor/javascript.ts,
        getArgumentsForFunctionValue). Otherwise it feeds the description to a JS parser to extract
        the parameter list, which throws "Failed to parse for arguments list" on `[native code]`;
        fired on every keystroke while typing a call, that uncaught rejection wedges the console.
        """
        if isinstance(obj, dict):
            node = cast(dict[str, Any], obj)
            if node.get("type") == "function":
                desc = node.get("description")
                if isinstance(desc, str) and "[native code]" in desc and not desc.endswith("{ [native code] }"):
                    brace = desc.find("{")
                    if brace != -1:
                        node["description"] = desc[:brace] + "{ [native code] }"
            for value in node.values():
                CdpTarget._normalize_native_functions(value)
        elif isinstance(obj, list):
            for value in cast(list[Any], obj):
                CdpTarget._normalize_native_functions(value)

    async def _target_dispatch_message_from_target(self, message: dict[str, Any]):
        await self._dispatch_target_message(json.loads(message["params"]["message"]))

    async def _dispatch_target_message(self, message: dict[str, Any]):
        """Translate one protocol message coming from the target and hand it to the frontend."""
        # Any message from the current target proves it is alive again (a wedged page that finally
        # navigated, a slow response that eventually arrived); resume sending it internal requests.
        self._mark_target_responsive(self.target_id)
        if "result" in message:
            # Function objects in evaluate/callFunctionOn results carry native descriptions the
            # console autocomplete inspects; normalize them (see _normalize_native_functions).
            self._normalize_native_functions(message["result"])
        if "error" in message:
            # Expected protocol-level errors (e.g. element-only DOM queries on text nodes) are
            # already delivered to the frontend, which copes; don't shout about them here.
            logger.debug(f"Target error response: {message}")
        if "id" in message:
            self._pending_requests.pop(message["id"], None)
            if message["id"] < 0:
                # Response to a bridge-internal request (setup replay or an abandoned wait);
                # forwarding it would hand the frontend an id it never issued.
                return
        method = message.get("method", "")
        if method in WEBKIT_ONLY_EVENTS:
            # Not part of Chrome's protocol; forwarding it only risks wedging the frontend.
            return
        if method in self.to_cdp_special_dispatched_messages_methods:
            await self.to_cdp_special_dispatched_messages_methods[method](message)
        else:
            if method:
                logger.debug(f"Dispatching: {method}")
            await self.output_queue.put(message)

    async def _target_did_commit_provisional_target(self, message: dict[str, Any]):
        # The provisional target replaces the committed one only now; from here on route the
        # frontend's commands to it.
        self.target_id = message["params"]["newTargetId"]
        # Normally already done at targetCreated; covers a commit whose creation we never saw.
        await self._send_setup_to_target(self.target_id)

    async def _debugger_script_parsed(self, message: dict[str, Any]):
        # Drop scripts that are not the page's own: the bridge's internal evaluations (screencast
        # offsets, synthesized input - fired several times a second) and WebKit's inspector
        # injected scripts. Forwarding them floods Chrome's Debugger model with phantom scripts,
        # which - independent of the page - eventually wedges the console/autocomplete.
        params = message.get("params", {})
        source = params.get("sourceURL", "") or params.get("url", "")
        if any(marker in source for marker in WEBKIT_INTERNAL_SCRIPT_MARKERS):
            return
        script_id = params.get("scriptId")
        if script_id is not None:
            self._script_id_to_url[script_id] = source
        await self.output_queue.put(message)

    async def _debugger_script_failed_to_parse(self, message: dict[str, Any]):
        # The failing source is only known from Runtime.compileScript; parse failures of other
        # evaluations (e.g. the console's eager previews) fall back to the default context.
        context_id = self._script_source_to_context_id.get(
            message["params"].get("scriptSource", ""), self._default_execution_id
        )
        message["params"] = {
            "endColumn": 0,
            "endLine": message["params"].get("errorLine", 0),
            "executionContextId": context_id,
            "startColumn": 0,
            "startLine": message["params"].get("startLine", 0),
            "url": message["params"].get("url", ""),
            "scriptId": context_id,
            "hash": hashlib.sha1(message["params"].get("scriptSource", "").encode()).hexdigest(),
        }
        await self.output_queue.put(message)

    async def _debugger_paused(self, message: dict[str, Any]):
        params = message["params"]
        params["reason"] = DEBUGGER_PAUSED_REASON.get(params["reason"], "other")
        if "breakpointId" in params.get("data", {}):
            params["hitBreakpoints"] = [params["data"]["breakpointId"]]
        # WebKit's CallFrame differs from Chrome's: it omits the required `url` and uses scope-type
        # enum values Chrome rejects. Untranslated, Chrome's SDK throws while building the paused
        # state and the Sources panel never shows the pause. Reshape each frame in place.
        for frame in params.get("callFrames", []):
            if "url" not in frame:
                script_id = frame.get("location", {}).get("scriptId")
                frame["url"] = self._script_id_to_url.get(script_id, "")
            for scope in frame.get("scopeChain", []):
                scope["type"] = WEBKIT_SCOPE_TYPE_MAP.get(scope["type"], "closure")
                # WebKit names the defining position `location`; Chrome calls it `startLocation`.
                if "location" in scope:
                    scope["startLocation"] = scope.pop("location")
        await self.output_queue.put(message)

    async def _debugger_global_object_cleared(self, message: dict[str, Any]):
        # Contexts are gone; allow their uniqueIds to be re-announced after the reload.
        self._emitted_context_unique_ids.clear()
        await self.output_queue.put({"method": "Runtime.executionContextsCleared"})
        await self.output_queue.put({"method": "DOM.documentUpdated"})

    async def _page_default_appearance_did_change(self, message: dict[str, Any]):
        pass

    async def _runtime_execution_context_created(self, message: dict[str, Any]):
        context = message["params"]["context"]
        # WebKit announces a context per isolated world (and per inspector evaluation batch);
        # forwarding them all with a shared uniqueId makes Chrome's RuntimeModel treat each as
        # a replacement of the selected console context, and pending evaluations lose their
        # results depending on timing. Only the main-world context is forwarded.
        if context["type"] != "normal":
            return
        unique_id = f"{context['frameId']}.{context['id']}"
        if unique_id in self._emitted_context_unique_ids:
            # WebKit re-announces the same context; a duplicate executionContextCreated corrupts
            # Chrome's RuntimeModel (it keys contexts by uniqueId), so emit each at most once.
            return
        self._emitted_context_unique_ids.add(unique_id)
        self._default_execution_id = context["id"]
        message["params"] = {
            "context": {
                "id": context["id"],
                "origin": "default",
                "name": "",
                # must be unique per context - Chrome keys contexts by it
                "uniqueId": unique_id,
            }
        }
        await self.output_queue.put(message)

    async def _console_message_repeat_count_updated(self, message: dict[str, Any]):
        """
        WebKit coalesces repeated identical console messages into a repeat-count update; Chrome
        has no such event, so replay the last console-API message and let the frontend coalesce.
        """
        if self._last_console_api_call is not None:
            params = dict(self._last_console_api_call)
            params["timestamp"] = datetime.now().timestamp() * 1000
            await self.output_queue.put({"method": "Runtime.consoleAPICalled", "params": params})

    async def _console_message_added(self, message: dict[str, Any]):
        console_message = message["params"]["message"]
        # Chrome renders console-API output (console.log & friends) from Runtime.consoleAPICalled,
        # complete with the argument objects; Log.entryAdded is only for browser-generated logs.
        if console_message["source"] == "console-api":
            args: list[dict[str, Any]] = console_message.get("parameters")
            if not args:
                args = [{"type": "string", "value": console_message.get("text", "")}]
            type_ = console_message.get("type", "log")
            if type_ == "log":
                # WebKit reports console.error/info/warn as type "log" with a level; Chrome
                # renders by the consoleAPICalled type.
                type_ = {"warning": "warning", "error": "error", "info": "info", "debug": "debug"}.get(
                    console_message.get("level", "log"), "log"
                )
            params: dict[str, Any] = {
                "type": type_,
                "args": args,
                "executionContextId": self._default_execution_id,
                # Runtime.Timestamp is in milliseconds
                "timestamp": datetime.now().timestamp() * 1000,
            }
            self._last_console_api_call = params
            await self.output_queue.put({"method": "Runtime.consoleAPICalled", "params": params})
            return
        log_record: dict[str, Any] = {
            "source": LOG_MESSAGE_SOURCES[console_message["source"]],
            "level": LOG_MESSAGE_LEVELS[console_message["level"]],
            "text": console_message["text"],
            # Log.LogEntry.timestamp is in milliseconds; seconds sort the entry into 1970
            "timestamp": datetime.now().timestamp() * 1000,
        }
        if "url" in console_message:
            log_record["url"] = console_message["url"]
        if "line" in console_message:
            log_record["lineNumber"] = console_message["line"]
        if "networkRequestId" in console_message:
            log_record["networkRequestId"] = console_message["networkRequestId"]

        await self.output_queue.put({"method": "Log.entryAdded", "params": {"entry": log_record}})

    async def _network_response_received(self, message: dict[str, Any]):
        params = message["params"]
        message["params"] = {
            "loaderId": params["loaderId"],
            "requestId": params["requestId"],
            "timestamp": params["timestamp"],
            "type": params["type"] if params["type"] in NETWORK_RESOURCE_TYPES else "Other",
            "response": {
                "url": params["response"]["url"],
                "status": params["response"]["status"],
                "statusText": params["response"]["statusText"],
                "headers": params["response"]["headers"],
                "mimeType": params["response"]["mimeType"],
                "connectionReused": False,
                "encodedDataLength": 0,
                "securityState": "unknown",
            },
        }
        if "frameId" in params:
            message["params"]["frameId"] = params["frameId"]
        await self.output_queue.put(message)

    async def _network_loading_finished(self, message: dict[str, Any]):
        params = message["params"]
        header_size = params["metrics"].get("responseHeaderBytesReceived", 0)
        body_size = params["metrics"].get("responseBodyBytesReceived", 0)
        message["params"] = {
            "encodedDataLength": header_size + body_size,
            "requestId": params["requestId"],
            "timestamp": params["timestamp"],
        }
        await self.output_queue.put(message)
