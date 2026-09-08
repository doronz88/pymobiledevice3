import asyncio
import base64
import hashlib
import itertools
import json
import logging
import re
from collections.abc import Awaitable
from datetime import datetime
from functools import partial
from typing import Any, Callable, Optional, cast

from pymobiledevice3.exceptions import ScreencastUnavailableError
from pymobiledevice3.services.web_protocol.cdp_screencast import ScreenCast
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import WirTypes, make_target_id

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
# How long an in-page key handler's reply may take before the bridge nudges the page (see
# CdpTarget._evaluate_key_handler). Typical replies arrive within ~10 ms.
KEY_HANDLER_WAKE_DELAY = 0.05

# Any forwarded client request hits the same iOS 26 WebKit quirk as the key handlers: its reply -
# and the events it triggers, such as the Debugger.paused after a step - is occasionally held until
# the next message reaches the page (see CdpTarget._wake_late_replies). Measured on a large script,
# half of all step-overs stalled this way, and an evaluate, a stepOver reply and its paused event
# were each freed by one throwaway message within ~10 ms. While any client reply is outstanding the
# bridge checks every REPLY_WAKE_TICK and nudges once any reply has waited REPLY_WAKE_INTERVAL - one
# nudge flushes everything held, so traffic is bounded whatever is pending - and stops tracking a
# request after REPLY_WAKE_MAX_AGE (a script that never terminates). The interval is well above a
# normal round-trip (~10 ms), so a prompt reply is never nudged; the finer tick keeps a withheld
# step-over's stall to ~0.3 s rather than up to two intervals.
REPLY_WAKE_TICK = 0.1
REPLY_WAKE_INTERVAL = 0.25
REPLY_WAKE_MAX_AGE = 20.0

# The receive loop and the internal-reply waits poll their queues. Polling with sleep(0) spun a
# core flat out whenever nothing was pending - 23% of a CPU measured while a debugger sat idle at
# a breakpoint. A 1 ms sleep drops that to nothing; a message that is already queued is still
# handled without sleeping, so throughput under load is unchanged.
IDLE_POLL_INTERVAL = 0.001

# A navigation that commits in a new process destroys the target the bridge is talking to, and
# WebKit never answers what was in flight to it. That is exactly when Chrome's frontend asks for
# the resource tree and when a screencast starts, so those requests wait here for the replacement
# target to become current and ask it instead of failing. The events that commit the swap are
# applied by the receive loop, which is paused for the whole of every request wait - the yield
# below is what lets them through.
SWAP_COMMIT_TIMEOUT = 5.0
SWAP_COMMIT_POLL_INTERVAL = 0.05

# Seconds Page.navigate waits for the navigation it started to commit before answering without a
# loaderId (which is how an in-page navigation is reported - see _page_navigate).
NAVIGATE_COMMIT_TIMEOUT = 10.0

# How far synthesized input follows a point or the focus down into nested frames before giving up.
MAX_FRAME_DESCENT = 5

# backendNodeIds minted for the <iframe> elements that own a frame (see _dom_get_frame_owner).
# WebKit has no node identity space of its own that survives without DOM.getDocument, so these are
# allocated here, well clear of anything the device would produce.
_FRAME_OWNER_NODE_IDS = itertools.count(0x60000000)

# backendNodeIds minted for nodes a client asked about with DOM.describeNode, so it can name the
# same node again later (DOM.resolveNode) - which is how it moves an element between worlds.
_DESCRIBED_NODE_IDS = itertools.count(0x70000000)

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

# execution-context ids minted for the synthesized isolated worlds (see _page_create_isolated_world).
# Based well above WebKit's own small per-session context ids so the two never collide.
_ISOLATED_WORLD_IDS = itertools.count(0x50000000)

# The single execution context synthesized for a JSContext debuggable (see _runtime_enable).
JS_CONTEXT_EXECUTION_ID = 1
JS_CONTEXT_UNIQUE_ID = "jscontext.1"

# WebKit reports the engine's own errors - uncaught exceptions, unhandled rejections, parse errors
# - as console messages of this source; Chrome reports them as Runtime.exceptionThrown, which is
# the only form VS Code's debugger renders (it has no handler for Log.entryAdded at all).
JAVASCRIPT_ERROR_SOURCE = "javascript"
UNHANDLED_REJECTION_PREFIX = "Unhandled Promise Rejection: "

# A binding installed by Runtime.addBinding reports its calls through console.debug with this
# marker as the first argument; the bridge turns those into Runtime.bindingCalled and never
# forwards them as console output. WebKit has no binding mechanism of its own.
BINDING_MARKER = "__pymobiledevice3_binding__"

# The domains a Node.js inspector target adds on top of Chrome's. Editors attaching "as Node"
# (VS Code's node attach, WebStorm) send these to a JSContext; WebKit has none of them, so they
# are acknowledged here the way an idle Node process would (no workers, nothing traced).
NODE_ACKNOWLEDGED_METHODS = (
    "NodeRuntime.enable",
    "NodeRuntime.disable",
    "NodeRuntime.notifyWhenWaitingForDisconnect",
    "NodeWorker.enable",
    "NodeWorker.disable",
    "NodeWorker.detach",
    "NodeWorker.sendMessageToWorker",
    "NodeTracing.start",
    "NodeTracing.stop",
)

# Target.TargetInfo.type of the targets this bridge debugs. WebKit announces "frame", "worker"
# and "service-worker" ones too - see _target_created.
PAGE_TARGET_TYPE = "page"

# Error synthesized for requests routed to a target that got destroyed before answering
# (WebKit never answers those). Matches Chrome's own message for the same situation.
TARGET_CLOSED_ERROR: dict[str, Any] = {"code": -32000, "message": "Inspected target navigated or closed"}

# Per-target state (beyond *.enable) worth re-establishing on the fresh target after a process
# swap. These keep their latest params only.
REPLAYED_SETUP_METHODS = frozenset({
    "Network.setResourceCachingDisabled",
    "Page.setEmulatedMedia",
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

# Replayed setup methods whose latest params are kept per value of one parameter: the user
# preference overrides are independent per preference name, and a later clear must replace (not
# join) the override it clears.
REPLAYED_KEYED_SETUP_METHODS: dict[str, str] = {"Page.overrideUserPreference": "name"}

# Chrome's Emulation.setEmulatedMedia features -> WebKit's Page.overrideUserPreference
# (Page.UserPreferenceName, Page.UserPreferenceValue). A feature value with no WebKit counterpart
# ("" is Chrome's reset; "less"/"custom" contrast has no WebKit value) clears that override.
USER_PREFERENCE_FEATURES: dict[str, tuple[str, dict[str, str]]] = {
    "prefers-color-scheme": ("PrefersColorScheme", {"dark": "Dark", "light": "Light"}),
    "prefers-reduced-motion": ("PrefersReducedMotion", {"reduce": "Reduce", "no-preference": "NoPreference"}),
    "prefers-contrast": ("PrefersContrast", {"more": "More", "no-preference": "NoPreference"}),
}

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

# Chrome sets RemoteObject.subtype for the built-in object kinds a client dispatches on; WebKit
# reports only className for most of them. A missing "promise" in particular strands a client that
# uses it to decide the value still has to be awaited, so it reads a result that is not there yet.
# Only unambiguous JavaScript built-ins are mapped - a page's own class named "Map" would be a
# plain object, but so would Chrome report it, since it keys off the internal type, not the name.
REMOTE_OBJECT_SUBTYPES = {
    "Promise": "promise",
    "Array": "array",
    "Date": "date",
    "RegExp": "regexp",
    "Map": "map",
    "Set": "set",
    "WeakMap": "weakmap",
    "WeakSet": "weakset",
    "Proxy": "proxy",
    "ArrayBuffer": "arraybuffer",
    "DataView": "dataview",
    "Error": "error",
    "EvalError": "error",
    "RangeError": "error",
    "ReferenceError": "error",
    "SyntaxError": "error",
    "TypeError": "error",
    "URIError": "error",
    "AggregateError": "error",
    "Int8Array": "typedarray",
    "Uint8Array": "typedarray",
    "Uint8ClampedArray": "typedarray",
    "Int16Array": "typedarray",
    "Uint16Array": "typedarray",
    "Int32Array": "typedarray",
    "Uint32Array": "typedarray",
    "Float32Array": "typedarray",
    "Float64Array": "typedarray",
    "BigInt64Array": "typedarray",
    "BigUint64Array": "typedarray",
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
    # A `debugger;` statement. V8/Chrome report this as "other", and that is what editors treat
    # as a genuine suspend to hold. "debugCommand" is Chrome's reason for a pause the client
    # itself requested via Debugger.pause; WebStorm, seeing it without having asked, took the
    # pause for spurious and resumed on its own - so `debugger` never stopped it on a JSContext.
    "DebuggerStatement": "other",
    # A hit on a source breakpoint. V8/Chrome report this as "other" with hitBreakpoints set;
    # "instrumentation" is Chrome's reason for its instrumentation breakpoints (DOM/event/...),
    # which carry data an editor looks for and, not finding, discards the pause - so a breakpoint
    # a user set on a JSContext line was reached but never surfaced.
    "Breakpoint": "other",
    # Chrome's reason for its own pause button. "instrumentation" is reserved for the frontend's
    # instrumentation breakpoints, which carry breakpoint data; without it the frontend drops
    # the pause silently and stays at "Not paused".
    "PauseOnNextStatement": "other",
    "Microtask": "other",
    "BlackboxedScript": "other",
    "other": "other",
}


# In-page handler for a keyDown the bridge received (see CdpTarget._editing_key_event). Dispatches
# the keydown to the focused element and, unless the page prevented its default, performs the key's
# editing action on a field: select-all (Cmd/Ctrl-A), caret movement by character, word (Alt) or
# line (Cmd, Home/End) with Shift extending the selection, Backspace and Delete - replacing the
# selection when there is one, and honouring beforeinput. Up/Down move to the ends of a single-line
# input only; in a textarea they are left alone. Returns "prevented", "handled" or "none".
KEY_DOWN_JS = """(function (k) {
  const el = document.activeElement || document.body;
  const event = new KeyboardEvent('keydown', {key: k.key, code: k.code, altKey: k.alt, ctrlKey: k.ctrl,
      metaKey: k.meta, shiftKey: k.shift, repeat: k.repeat, bubbles: true, cancelable: true});
  if (k.keyCode) {
    for (const name of ['keyCode', 'which']) { Object.defineProperty(event, name, {get: () => k.keyCode}); }
  }
  if (!el.dispatchEvent(event)) { return 'prevented'; }
  const tag = el.tagName ? el.tagName.toLowerCase() : '';
  const isField = (tag === 'input' || tag === 'textarea') && !el.disabled && !el.readOnly;
  if ((k.meta || k.ctrl) && k.key.toLowerCase() === 'a') {
    if (isField) { el.select(); }
    else if (el.isContentEditable) { document.execCommand('selectAll'); }
    else { document.getSelection().selectAllChildren(document.body); }
    return 'handled';
  }
  const fire = (type, inputType) => el.dispatchEvent(
      new InputEvent(type, {bubbles: true, cancelable: type === 'beforeinput', inputType: inputType}));
  if (el.isContentEditable) {
    const selection = document.getSelection();
    const alter = k.shift ? 'extend' : 'move';
    switch (k.key) {
      case 'ArrowLeft': case 'ArrowRight':
        selection.modify(alter, k.key === 'ArrowLeft' ? 'backward' : 'forward',
            k.meta ? 'lineboundary' : k.alt ? 'word' : 'character');
        return 'handled';
      case 'Home': case 'End':
        selection.modify(alter, k.key === 'Home' ? 'backward' : 'forward', 'lineboundary');
        return 'handled';
      case 'Backspace':
        if (fire('beforeinput', 'deleteContentBackward')) { document.execCommand('delete'); }
        return 'handled';
      case 'Delete':
        if (fire('beforeinput', 'deleteContentForward')) { document.execCommand('forwardDelete'); }
        return 'handled';
    }
    return 'none';
  }
  if (!isField) { return 'none'; }
  const value = el.value || '';
  let start = el.selectionStart, end = el.selectionEnd;
  if (start === null || start === undefined) { start = end = value.length; }
  const backward = el.selectionDirection === 'backward';
  const anchor = backward ? end : start, focus = backward ? start : end;
  const space = (c) => /\\s/.test(c);
  const wordLeft = (pos) => { while (pos > 0 && space(value[pos - 1])) { pos--; }
                             while (pos > 0 && !space(value[pos - 1])) { pos--; } return pos; };
  const wordRight = (pos) => { while (pos < value.length && space(value[pos])) { pos++; }
                              while (pos < value.length && !space(value[pos])) { pos++; } return pos; };
  const lineStart = (pos) => value.lastIndexOf('\\n', pos - 1) + 1;
  const lineEnd = (pos) => { const i = value.indexOf('\\n', pos); return i === -1 ? value.length : i; };
  const setRange = (a, b, direction) => { try { el.setSelectionRange(a, b, direction); } catch (e) {} };
  let target = null;
  switch (k.key) {
    case 'ArrowLeft':
      target = k.meta ? lineStart(focus) : k.alt ? wordLeft(focus)
          : (!k.shift && start !== end) ? start : Math.max(0, focus - 1);
      break;
    case 'ArrowRight':
      target = k.meta ? lineEnd(focus) : k.alt ? wordRight(focus)
          : (!k.shift && start !== end) ? end : Math.min(value.length, focus + 1);
      break;
    case 'Home': target = lineStart(focus); break;
    case 'End': target = lineEnd(focus); break;
    case 'ArrowUp': if (tag === 'input') { target = 0; } break;
    case 'ArrowDown': if (tag === 'input') { target = value.length; } break;
  }
  if (target !== null) {
    if (k.shift) { setRange(Math.min(anchor, target), Math.max(anchor, target), target < anchor ? 'backward' : 'forward'); }
    else { setRange(target, target, 'none'); }
    return 'handled';
  }
  if (k.key !== 'Backspace' && k.key !== 'Delete') { return 'none'; }
  let from = start, to = end;
  if (start === end) {
    if (k.key === 'Backspace') { from = k.meta ? lineStart(start) : k.alt ? wordLeft(start) : Math.max(0, start - 1); }
    else { to = k.meta ? lineEnd(end) : k.alt ? wordRight(end) : Math.min(value.length, end + 1); }
  }
  if (from === to) { return 'handled'; }
  const inputType = k.key === 'Backspace' ? 'deleteContentBackward' : 'deleteContentForward';
  if (!fire('beforeinput', inputType)) { return 'handled'; }
  const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
  const next = value.slice(0, from) + value.slice(to);
  if (descriptor && descriptor.set) { descriptor.set.call(el, next); } else { el.value = next; }
  setRange(from, from, 'none');
  fire('input', inputType);
  return 'handled';
})"""

# In-page handler for a keyUp: the matching keyup event for the page's listeners.
KEY_UP_JS = """(function (k) {
  const el = document.activeElement || document.body;
  const event = new KeyboardEvent('keyup', {key: k.key, code: k.code, altKey: k.alt, ctrlKey: k.ctrl,
      metaKey: k.meta, shiftKey: k.shift, bubbles: true, cancelable: true});
  if (k.keyCode) {
    for (const name of ['keyCode', 'which']) { Object.defineProperty(event, name, {get: () => k.keyCode}); }
  }
  el.dispatchEvent(event);
  return 'handled';
})"""


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
        # Chrome guarantees the top frame's id equals the page's targetId; a Chrome-protocol client
        # (Playwright's crPage keys its per-page session by targetId, then looks the session up by
        # the frame's id) relies on it and throws "Frame has been detached" otherwise. WebKit names
        # the top frame independently ("0.1"), so the bridge maps that id to the id the client
        # attached with, in both directions, everywhere a frameId crosses the wire.
        self.frame_id = make_target_id(self.app_id, str(self.page_id))
        # WebKit's own id for the top frame, learned from the first frame tree / main-world context.
        self._webkit_frame_id: Optional[str] = None
        # WebKit's Web Inspector cannot create isolated worlds (Page.createIsolatedWorld). Chrome
        # clients (Playwright) run their own helpers in one and block until its context is
        # announced. The bridge synthesizes that context and routes evaluations addressed to it
        # into the page's real (main) world - the ids handed out for those synthetic contexts are
        # collected here so their contextId can be rewritten back on the way to the device.
        self._isolated_world_context_ids: set[int] = set()
        # Synthetic isolated world -> the frame it was created for, so its evaluations reach that
        # frame's real context rather than whichever one happened to be announced last.
        self._isolated_world_frames: dict[int, str] = {}
        self._isolated_world_names: dict[int, str] = {}
        # Frame -> the id of the main-world execution context WebKit announced for it. A page with
        # subframes announces one per frame, and they are not interchangeable.
        self._frame_execution_ids: dict[str, int] = {}
        # Child frames the client has been told about, so each is announced once (see
        # _page_frame_navigated).
        self._announced_frames: set[str] = set()
        # Minted backendNodeId -> the (frame, index) of the <iframe> element it stands for.
        self._frame_owner_nodes: dict[int, tuple[str, int]] = {}
        # Minted backendNodeId -> the remote object a client was told about. WebKit has no node
        # identity that outlives a description, so one is kept here (see _dom_describe_node).
        self._described_nodes: dict[int, str] = {}
        # World names the client registered through Page.addScriptToEvaluateOnNewDocument. Chrome
        # creates a world of that name in every document that loads; the bridge does the same, so
        # a frame that appears later still gets the world its client expects to evaluate in.
        self._auto_world_names: list[str] = []
        # (frame, world name) pairs already announced, so each world is minted once per document.
        self._announced_worlds: set[tuple[str, str]] = set()
        # Whether the client asked for Page.lifecycleEvent (Chrome only reports those once
        # Page.setLifecycleEventsEnabled turned them on, and DevTools never asks).
        self._lifecycle_events_enabled = False
        # loaderId of the document currently committed in the top frame, tracked from the frame
        # tree and Page.frameNavigated so the synthesized lifecycle events can carry it.
        self._loader_id = ""
        # Number of documents committed in the top frame, so Page.navigate can tell whether the
        # navigation it started committed a new document.
        self._top_frame_commits = 0
        # Detached tasks (a navigation waiting for its commit); cancelled when the session closes.
        self._background_tasks: set[asyncio.Task[None]] = set()
        # Forwarded client request id -> loop time it was sent, while its reply is outstanding, and the
        # single watchdog nudging the page for them (see _wake_late_replies).
        self._reply_wake_pending: dict[int, float] = {}
        # Client request id -> how to finish that request when its device reply arrives, for
        # requests forwarded without blocking (see _forward_and_translate).
        self._reply_translators: dict[int, Callable[[dict[str, Any]], Awaitable[None]]] = {}
        self._reply_wake_task: Optional[asyncio.Task[None]] = None
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
            # WebKit implements no Page.getFrameTree (Playwright's connectOverCDP calls it to
            # learn the frame tree); answer it from the resource tree, whose frameTree carries the
            # same frame. Nor Page.setLifecycleEventsEnabled - raw-forwarding it errors and rejects
            # Playwright's page initialization, so translate it (see the handler).
            "Page.getFrameTree": self._page_get_resource_tree,
            "Page.setLifecycleEventsEnabled": self._page_set_lifecycle_events_enabled,
            "Emulation.setEmulatedMedia": self._emulation_set_emulated_media,
            "Emulation.setTouchEmulationEnabled": partial(self._simple_response, value=None),
            "Emulation.setFocusEmulationEnabled": partial(self._simple_response, value=None),
            "Emulation.setEmulatedVisionDeficiency": partial(self._simple_response, value=None),
            "Emulation.setAutoDarkModeOverride": self._emulation_set_auto_dark_mode_override,
            "Emulation.setEmitTouchEventsForMouse": partial(self._simple_response, value=None),
            "Debugger.setAsyncCallStackDepth": partial(self._simple_response, value=None),
            "Debugger.removeBreakpoint": self._debugger_remove_breakpoint,
            "Debugger.enable": self._debugger_enable,
            "Debugger.setSkipAllPauses": self._debugger_set_skip_all_pauses,
            "Debugger.setBreakpointsActive": self._debugger_set_breakpoints_active,
            "Debugger.setBlackboxPatterns": self._debugger_set_blackbox_patterns,
            "Debugger.setBreakpointByUrl": self._debugger_set_breakpoint_by_url,
            "DOMDebugger.setBreakOnCSPViolation": partial(self._simple_response, value=None),
            "DOMDebugger.getEventListeners": self._domdebugger_get_event_listeners,
            "Network.setCacheDisabled": self._network_set_cache_disabled,
            "Network.loadNetworkResource": self._network_load_network_resource,
            "Network.setAttachDebugStack": partial(self._simple_response, value=None),
            "Network.clearAcceptedEncodingsOverride": partial(self._simple_response, value=None),
            "Fetch.enable": self._fetch_enable,
            "Fetch.disable": self._fetch_disable,
            "Fetch.continueRequest": self._fetch_continue_request,
            "Fetch.continueResponse": self._fetch_continue_response,
            "Fetch.continueWithAuth": self._fetch_continue_with_auth,
            "Fetch.fulfillRequest": self._fetch_fulfill_request,
            "Fetch.failRequest": self._fetch_fail_request,
            "ServiceWorker.enable": self._service_worker_enable,
            "HeapProfiler.enable": partial(self._simple_response, value=None),
            # Overlay is absent in WebKit; only highlightNode is worth translating, the rest are
            # acknowledged by the NOOP_ABSENT_DOMAINS fallback in _input_loop.
            "Overlay.highlightNode": self._overlay_highlight_node,
            "Runtime.runIfWaitingForDebugger": self._runtime_run_if_waiting_for_debugger,
            "Runtime.enable": self._runtime_enable,
            "Runtime.evaluate": self._runtime_evaluate,
            "Runtime.callFunctionOn": self._runtime_call_function_on,
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
            "Input.insertText": self._input_insert_text,
            "Input.emulateTouchFromMouseEvent": self._input_emulate_touch_from_mouse_event,
            "Input.dispatchKeyEvent": self._input_dispatch_key_event,
            "Input.dispatchMouseEvent": self._input_dispatch_mouse_event,
            "Page.navigate": self._page_navigate,
            "Page.setAdBlockingEnabled": partial(self._simple_response, value=None),
            "Page.addScriptToEvaluateOnNewDocument": self._page_add_script_to_evaluate_on_new_document,
            "Page.createIsolatedWorld": self._page_create_isolated_world,
            # WebKit implements neither, and Chrome's screenshot path is built on both.
            "Page.getLayoutMetrics": self._page_get_layout_metrics,
            "Page.captureScreenshot": self._page_capture_screenshot,
            # WebKit implements neither, and a Chrome client's click/fill path is built on both.
            "DOM.scrollIntoViewIfNeeded": self._dom_scroll_into_view_if_needed,
            "DOM.getContentQuads": self._dom_get_content_quads,
            # WebKit has no DOM.describeNode; a client resolves an <iframe> element to the frame
            # it hosts through it, which is how frameLocator() reaches into a child frame.
            "DOM.describeNode": self._dom_describe_node,
            # The other half of reaching into a frame: a client asks which element owns a frame
            # and then resolves that answer back to an object it can measure.
            "DOM.getFrameOwner": self._dom_get_frame_owner,
            "DOM.resolveNode": self._dom_resolve_node,
            "Accessibility.enable": partial(self._simple_response, value=None),
            "Autofill.enable": partial(self._simple_response, value=None),
            "Autofill.setAddresses": partial(self._simple_response, value=None),
            "Runtime.addBinding": self._runtime_add_binding,
            "Runtime.removeBinding": self._runtime_remove_binding,
            "NodeTracing.getCategories": partial(self._result_response, result={"categories": []}),
            **{method: partial(self._simple_response, value=None) for method in NODE_ACKNOWLEDGED_METHODS},
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
            "Runtime.executionContextCreated": self._runtime_execution_context_created,
            "Console.messageAdded": self._console_message_added,
            "Inspector.inspect": self._inspector_inspect,
            "Network.responseReceived": self._network_response_received,
            "Network.loadingFinished": self._network_loading_finished,
            "Network.requestWillBeSent": self._network_request_will_be_sent,
            "Network.requestIntercepted": self._network_request_intercepted,
            "Network.responseIntercepted": self._network_response_intercepted,
            # WebKit reports a load's progress with the pre-lifecycle events Chrome has long since
            # replaced; each is also turned into the Page.lifecycleEvent modern clients wait on.
            "Page.frameNavigated": self._page_frame_navigated,
            "Page.frameDetached": self._page_frame_detached,
            "Page.domContentEventFired": self._page_dom_content_event_fired,
            "Page.loadEventFired": self._page_load_event_fired,
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
        # For a flat JSContext: the synthetic URL handed to the frontend for a URL-less script ->
        # the script's id. Lets a URL breakpoint (how editors set breakpoints) be turned into a
        # scriptId-location breakpoint, the only kind that binds on a URL-less script.
        self._flat_script_url_to_id: dict[str, str] = {}
        # URL breakpoints a JSContext client set before their script existed: the bridge's own
        # breakpoint id -> the request, plus the device breakpoint ids it produced once bound.
        self._flat_pending_url_breakpoints: dict[str, dict[str, Any]] = {}
        self._flat_bound_url_breakpoints: dict[str, list[str]] = {}
        # Runtime.addBinding: name -> the executionContextName it is scoped to (None = every main
        # world). Re-installed into every context created later, as Chrome does.
        self._bindings: dict[str, Optional[str]] = {}
        self._exception_ids = itertools.count(1)
        self._eval_side_effect_id = 0
        self._default_execution_id = 0
        self._last_console_api_call: Optional[dict[str, Any]] = None
        self._internal_id = 0
        # loop time of the last synthesized hover, to throttle high-frequency mouseMoved events.
        self._last_mousemove_time = 0.0
        # Text a keyDown said it would produce, held until it is known whether the client also
        # sends the "char" event that classically carried it (see _input_dispatch_key_event).
        self._pending_key_text: Optional[str] = None
        # Whether the page's own keydown listener prevented the default of the key currently held,
        # and the execution context its keydown was dispatched in (see _input_dispatch_key_event).
        self._key_default_prevented = False
        self._key_context: Optional[int] = None
        # Chrome's Fetch domain, translated onto WebKit's Network request-interception. When
        # armed, WebKit pauses each matching request as Network.requestIntercepted, which the
        # bridge presents to the client as Fetch.requestPaused and answers through
        # Network.intercept* on the client's continue/fulfill/fail. Injecting an Authorization
        # header on continueRequest answers HTTP Basic auth without the on-device dialog.
        self._fetch_enabled = False
        self._fetch_handle_auth = False
        # requestId -> {frameId (client), type}, from Network.requestWillBeSent: the fields
        # Network.requestIntercepted omits but Fetch.requestPaused must carry.
        self._request_meta: dict[str, dict[str, Any]] = {}
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
        # WebKit user preferences currently overridden through Emulation.setEmulatedMedia features.
        self._emulated_preferences: set[str] = set()
        self._setup_sent_targets: set[str] = {target_id}
        # Targets announced as pages - the only kind this session talks to (see _target_created).
        self._page_targets: set[str] = {target_id}
        # The debuggable was attached before it ran (an automatic-inspection candidate) and the
        # application is blocked until the frontend reports itself initialized. Released by the
        # client's Runtime.runIfWaitingForDebugger, or on close.
        self.waiting_for_debugger = False
        # Stop the debuggable on its first statement once attached (Safari's "Automatically
        # Pause Connecting to JSContexts"). A held JSContext is paused by WebKit itself on
        # release (the socket was set up with WIRAutomaticallyPause); anything else - a page,
        # the target a process swap creates - is paused by the bridge as soon as its debugger is
        # enabled (see _debugger_enable and _target_created).
        self.pause_on_start = False
        # Hold the page target a cross-site navigation creates until its debugger setup has been
        # replayed (WebKit's Target.setPauseOnStart); see hold_new_targets.
        self.hold_navigations = False
        # Targets the bridge already asked to pause, so each is stopped once.
        self._paused_targets: set[str] = set()
        # What the target emitted while the bridge held it with no frontend attached (see
        # start_holding): handed to the frontend that adopts it once its debugger is on.
        self.held_events: list[dict[str, Any]] = []
        self._holding_task: Optional[asyncio.Task[None]] = None
        # id of the adopting frontend's Debugger.enable; the held events follow its response.
        self._replay_after_id: Optional[int] = None

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

    def _to_client_frame_id(self, frame_id: Any) -> Any:
        """WebKit's top-frame id -> the id the client attached with (see self.frame_id)."""
        return self.frame_id if frame_id == self._webkit_frame_id else frame_id

    def _to_device_frame_id(self, frame_id: Any) -> Any:
        """The client's frame id -> WebKit's, the reverse of _to_client_frame_id."""
        if frame_id == self.frame_id and self._webkit_frame_id is not None:
            return self._webkit_frame_id
        return frame_id

    def _learn_webkit_frame_id(self, frame_id: Any) -> None:
        """Record WebKit's own id for the top frame the first time it is seen (the frame tree's
        top frame, or the main-world execution context's frame)."""
        if self._webkit_frame_id is None and isinstance(frame_id, str):
            self._webkit_frame_id = frame_id

    def _map_frame_ids_outbound(self, message: dict[str, Any]) -> None:
        """Rewrite WebKit's top-frame id to the client's in the frameId-bearing fields of an event
        (Page.frame*, Network.*), so every frame reference the client sees matches its targetId."""
        params = message.get("params")
        if not isinstance(params, dict):
            return
        params_d = cast(dict[str, Any], params)
        for key in ("frameId", "parentFrameId"):
            if key in params_d:
                params_d[key] = self._to_client_frame_id(params_d[key])
        frame = params_d.get("frame")
        if isinstance(frame, dict):
            frame_d = cast(dict[str, Any], frame)
            for key in ("id", "parentId"):
                if key in frame_d:
                    frame_d[key] = self._to_client_frame_id(frame_d[key])

    @classmethod
    async def create(cls, protocol: SessionProtocol, automatically_pause: bool = False) -> "CdpTarget":
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        :param automatically_pause: Have WebKit pause the debuggable on its next statement once the
            frontend is initialized (see WebinspectorService.setup_inspector_socket).
        """
        await protocol.inspector.setup_inspector_socket(
            protocol.id_, protocol.app.id_, protocol.page.id_, automatically_pause=automatically_pause
        )
        if protocol.page.type_ == WirTypes.JAVASCRIPT:
            # A JSContext debuggable has no Target domain, so it announces nothing on attach and
            # there is only ever the one target - synthesize its id instead of waiting forever.
            return cls(protocol, f"jscontext:{protocol.app.id_}:{protocol.page.id_}")
        events = protocol.inspector.session_events(protocol.id_)
        while True:
            if not events:
                await asyncio.sleep(IDLE_POLL_INTERVAL)
                continue
            created = events.popleft()
            target_info = created.get("params", {}).get("targetInfo")
            # Only a page target can serve this session (see _target_created).
            if target_info is not None and target_info.get("type", PAGE_TARGET_TYPE) == PAGE_TARGET_TYPE:
                break
        target_id = created["params"]["targetInfo"]["targetId"]
        logger.info(f"Created: {target_id}")
        # The raw WIR Target.targetCreated is NOT forwarded: its targetInfo lacks the fields
        # Chrome's schema requires (type/title/url/attached) and crashes the frontend's SDK.
        return cls(protocol, target_id)

    async def hold_new_targets(self) -> None:
        """Ask WebKit to hold the page target a cross-site navigation creates until it is resumed.

        The one creation-time hold WebKit offers for pages: a WKWebView's page runs from the
        moment it exists, but a navigation that swaps processes announces its provisional target
        first, and with Target.setPauseOnStart that target waits for Target.resume before its
        load commits. The bridge resumes it right after replaying the frontend's setup (see
        _target_created), so breakpoints reach the new process ahead of its first script.
        """
        if self.hold_navigations:
            return
        self.hold_navigations = True
        if not self._flat:
            await self.protocol.send_command("Target.setPauseOnStart", pauseOnStart=True)

    async def release_debugger(self) -> None:
        """Let a debuggable attached before it ran start running.

        WebKit blocks the thread creating an automatic-inspection candidate until the frontend
        sends Inspector.initialized (or ten seconds pass); Chrome clients express the same step
        as Runtime.runIfWaitingForDebugger. Nothing to do for a target that was not held.
        """
        if not self.waiting_for_debugger:
            return
        self.waiting_for_debugger = False
        await self._send_message_to_target(
            {"id": self.next_internal_id(), "method": "Inspector.initialized", "params": {}}, record=False
        )

    async def enable_debugger(self) -> None:
        """Turn the debugger on on the bridge's own behalf (with the same extras a frontend's
        Debugger.enable gets), before any frontend is attached."""
        await self._debugger_enable({"id": self.next_internal_id(), "method": "Debugger.enable", "params": {}})

    def start_holding(self) -> None:
        """Keep the target alive with no frontend attached: whatever it emits meanwhile - the
        scripts it parsed, the pause it stopped at - is kept for the frontend that adopts it."""

        async def collect() -> None:
            while True:
                self.held_events.append(await self.output_queue.get())

        self._holding_task = asyncio.create_task(collect())

    def adopt(self) -> None:
        """Hand a held target to a frontend. What it missed is replayed once it enables the
        debugger (see _debugger_enable): a pause only means something to a debugger that is on,
        and that is the order a fresh backend would have produced."""
        if self._holding_task is not None:
            self._holding_task.cancel()
            self._holding_task = None

    async def _pause_target(self, target_id: str) -> None:
        """Stop a target on its next statement, once, if the client's debugger is on."""
        if target_id in self._paused_targets or "Debugger.enable" not in self._setup_messages:
            return
        self._paused_targets.add(target_id)
        await self._send_message_to_target(
            {"id": self.next_internal_id(), "method": "Debugger.pause", "params": {}}, target_id=target_id, record=False
        )

    async def close(self) -> None:
        """
        Stop the queue-consumer tasks and any running screencast, and tear down the WIR socket.
        """
        if self.screencast is not None:
            await self.screencast.stop()
            self.screencast = None
        # A held debuggable must not outlive its debugger: release it before the socket goes.
        await self.release_debugger()
        if self._holding_task is not None:
            self._holding_task.cancel()
            await asyncio.gather(self._holding_task, return_exceptions=True)
            self._holding_task = None
        for task in (self._input_task, self._receiving_task, *self._background_tasks):
            task.cancel()
        await asyncio.gather(self._input_task, self._receiving_task, *self._background_tasks, return_exceptions=True)
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
                    if target_id is not None and message["params"]["targetId"] == target_id:
                        # Record it here too: the receive loop is paused until this wait returns,
                        # so its own bookkeeping runs too late for the caller to tell a destroyed
                        # target from one that went quiet (it used to report "stopped responding"
                        # and back off on a target that had simply been swapped out).
                        self._destroyed_targets.add(target_id)
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
            await asyncio.sleep(IDLE_POLL_INTERVAL)
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

    async def _await_target_swap(self, target_id: str, deadline: float) -> bool:
        """Wait for the target that replaced a destroyed one to become current.

        :param target_id: The target whose answer was lost.
        :param deadline: Event-loop time to give up at.
        :returns: True once a different target is current, False if `target_id` was not destroyed
            in the first place or nothing took over in time.
        """
        if target_id not in self._destroyed_targets:
            return False
        while self.target_id == target_id:
            if asyncio.get_event_loop().time() >= deadline:
                return False
            # Yields to the receive loop, which applies the targetCreated /
            # didCommitProvisionalTarget pair that makes the replacement current.
            await asyncio.sleep(SWAP_COMMIT_POLL_INTERVAL)
        return True

    async def send_message_with_result_across_swaps(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """send_message_with_result, re-asked of the target that replaces one destroyed mid-request.

        Returns the last (empty) result if no replacement became current in time.
        """
        deadline = asyncio.get_event_loop().time() + SWAP_COMMIT_TIMEOUT
        while True:
            target_id = self.target_id
            result = await self.send_message_with_result(method, params)
            if result or not await self._await_target_swap(target_id, deadline):
                return result

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
                # The client refers to the top frame by the id it attached with; translate it back
                # to WebKit's before the request reaches the device.
                params = message.get("params")
                if isinstance(params, dict) and "frameId" in params:
                    params_d = cast(dict[str, Any], params)
                    params_d["frameId"] = self._to_device_frame_id(params_d["frameId"])
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
                await asyncio.sleep(IDLE_POLL_INTERVAL)
                continue
            message = self._next_message()
            if message is None:
                await asyncio.sleep(IDLE_POLL_INTERVAL)
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
        return cast(dict[str, Any], events.popleft())

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
        message_id = message.get("id")
        if record and isinstance(message_id, int) and message_id > 0:
            # A client request whose reply WebKit may withhold until the next message; the watchdog
            # keeps the page nudged until it answers (see _wake_late_replies).
            self._reply_wake_pending[message_id] = asyncio.get_event_loop().time()
            if self._reply_wake_task is None or self._reply_wake_task.done():
                self._reply_wake_task = asyncio.ensure_future(self._wake_late_replies())
                self._background_tasks.add(self._reply_wake_task)
                self._reply_wake_task.add_done_callback(self._background_tasks.discard)
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
            await asyncio.sleep(IDLE_POLL_INTERVAL)
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
        elif method in REPLAYED_KEYED_SETUP_METHODS:
            self._setup_messages[(method, str(params.get(REPLAYED_KEYED_SETUP_METHODS[method])))] = params

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
        """Acknowledge a request the bridge answers itself: an empty result, as Chrome's protocol
        defines for commands that return nothing, or {"result": value} for the few that do."""
        result: dict[str, Any] = {} if value is None else {"result": value}
        await self.output_queue.put({"id": message["id"], "result": result})

    async def _result_response(self, message: dict[str, Any], result: dict[str, Any]):
        """Respond with an exact result body, for methods whose response fields the frontend reads."""
        await self.output_queue.put({"id": message["id"], "result": result})

    async def _error_response(self, message: dict[str, Any], error: dict[str, Any]) -> None:
        """Refuse a frontend request. Chrome's frontends absorb a protocol error - what they cannot
        absorb is no answer at all, which is what raising out of a translation leaves them with."""
        await self.output_queue.put({"id": message["id"], "error": error})

    async def _audits_enable(self, message: dict[str, Any]):
        # A previous inspector session may have left an audit configured; WebKit then rejects
        # setup with "Must call teardown before calling setup again", so always reset first.
        await self.send_message_with_result("Audit.teardown", {})
        message["method"] = "Audit.setup"
        message["params"] = {}
        await self._send_message_to_target(message)

    async def _page_navigate(self, message: dict[str, Any]):
        """
        WebKit has no Page.navigate; navigate in-page instead (URL bar / reload in DevTools).

        The response must say which document the navigation started, because that is how a client
        tells a new-document navigation from an in-page one: Chrome's Page.navigate answers with
        the new loaderId, and Playwright waits for a *same-document* navigation when it is absent -
        an event a real page load never sends, so page.goto() hung until its timeout. WebKit only
        reveals the loaderId once the document commits, so start the navigation and report the
        commit that follows. Nothing commits for an in-page navigation (a fragment change), and
        answering without a loaderId is then exactly right.
        """
        url = json.dumps(message["params"]["url"])
        commits_before = self._top_frame_commits
        # Fire-and-forget: a committed navigation destroys the target and WebKit never answers the
        # evaluation, and waiting for that would pause the receive loop past the commit below.
        await self._send_message_to_target(
            {
                "id": self.next_internal_id(),
                "method": "Runtime.evaluate",
                "params": {"expression": self._tag_internal(f"location.href = {url}")},
            },
            record=False,
        )
        # The wait runs off the input loop: everything else the client sends - screencast acks
        # above all - has to keep being served while a navigation is in flight, and a load that
        # never commits must not freeze the session for the whole timeout.
        self._spawn(self._answer_navigate_on_commit(message["id"], commits_before))

    async def _answer_navigate_on_commit(self, id_: int, commits_before: int) -> None:
        """Answer a Page.navigate once the navigation it started commits (see _page_navigate)."""
        deadline = asyncio.get_event_loop().time() + NAVIGATE_COMMIT_TIMEOUT
        while self._top_frame_commits == commits_before and asyncio.get_event_loop().time() < deadline:
            # The receive loop is what applies the commit (see _page_frame_navigated). The client
            # collects the commit it forwards meanwhile and matches it against the loaderId below.
            await asyncio.sleep(SWAP_COMMIT_POLL_INTERVAL)
        result: dict[str, Any] = {"frameId": self.frame_id}
        if self._top_frame_commits != commits_before:
            result["loaderId"] = self._loader_id
        await self.output_queue.put({"id": id_, "result": result})

    def _spawn(self, coroutine: "Awaitable[None]") -> None:
        """Run a coroutine detached from the loop that started it, keeping a reference so it is
        neither garbage collected mid-flight nor left running after the session closes."""
        task = asyncio.ensure_future(coroutine)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _dom_push_nodes_by_backend_ids(self, message: dict[str, Any]):
        await self.output_queue.put({"id": message["id"], "result": {"nodeIds": []}})

    async def _forward_and_translate(
        self,
        message: dict[str, Any],
        device_message: dict[str, Any],
        translate: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Forward a client request to the device under the client's own id and finish it with
        `translate` when the reply arrives, instead of waiting for it here.

        Waiting here (send_message_with_result) holds the receive loop for up to WIR_RESULT_TIMEOUT
        and gives up after it: a reply WebKit needs longer to build - the property list of a
        large scope, which the Sources panel fetches on every pause - was silently answered
        with an empty result, and no event reached the client for those five seconds. Forwarding
        under the client's id also lets the withheld-reply watchdog cover the request.
        """
        self._reply_translators[message["id"]] = translate
        await self._send_message_to_target({"id": message["id"], **device_message})

    async def _runtime_get_properties(self, message: dict[str, Any]):
        """
        WebKit answers Runtime.getProperties with a 'properties' array; Chrome's frontend reads
        'result' and renders "No properties" otherwise. WebKit also lacks the
        accessorPropertiesOnly/nonIndexedPropertiesOnly filters, so apply them here. Forwarded
        without blocking (see _forward_and_translate): a large scope's list takes WebKit longer
        than the internal wait allowed, which left the Scope panel empty on every pause in a big
        function and stalled event delivery meanwhile.
        """
        params = message["params"]

        async def translate(reply: dict[str, Any]) -> None:
            if "result" not in reply:
                await self.output_queue.put({"id": message["id"], "result": {"result": []}})
                return
            properties: list[dict[str, Any]] = reply["result"].get("properties", [])
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
            if "internalProperties" in reply["result"]:
                result["internalProperties"] = reply["result"]["internalProperties"]
            await self.output_queue.put({"id": message["id"], "result": result})

        await self._forward_and_translate(
            message,
            {
                "method": "Runtime.getProperties",
                "params": {
                    "objectId": params["objectId"],
                    "ownProperties": params.get("ownProperties", False),
                    "generatePreview": params.get("generatePreview", False),
                },
            },
            translate,
        )

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
        # The script itself cannot be honoured (WebKit has no equivalent), but the world it names
        # must be: Chrome creates a world of that name in every document that loads, and that is
        # how a client gets an isolated world in a frame it never explicitly asked about.
        world_name = message.get("params", {}).get("worldName")
        if isinstance(world_name, str) and world_name and world_name not in self._auto_world_names:
            self._auto_world_names.append(world_name)
        await self.output_queue.put({"id": message["id"], "result": {"identifier": "1"}})

    async def _page_set_lifecycle_events_enabled(self, message: dict[str, Any]):
        """
        WebKit has no Page.setLifecycleEventsEnabled, but the events it gates are not optional:
        Playwright's navigation waits (page.goto, page.reload, waitForNavigation) block on
        Page.lifecycleEvent and ignore the older Page.loadEventFired/domContentEventFired that
        WebKit does emit, so every navigating call hung until its timeout. Record the request and
        synthesize the lifecycle events off those real signals (see _emit_lifecycle_event).
        """
        self._lifecycle_events_enabled = bool(message.get("params", {}).get("enabled", True))
        await self._simple_response(message, None)

    async def _emit_lifecycle_event(
        self, name: str, timestamp: Any, frame_id: Optional[str] = None, loader_id: Optional[str] = None
    ) -> None:
        """Emit one Chrome Page.lifecycleEvent, if the client asked for them."""
        if not self._lifecycle_events_enabled:
            return
        await self.output_queue.put({
            "method": "Page.lifecycleEvent",
            "params": {
                "frameId": frame_id if frame_id is not None else self.frame_id,
                "loaderId": loader_id if loader_id is not None else self._loader_id,
                "name": name,
                # Page.lifecycleEvent.timestamp is a MonotonicTime, like WebKit's own.
                "timestamp": timestamp if isinstance(timestamp, (int, float)) else datetime.now().timestamp(),
            },
        })

    async def _page_frame_navigated(self, message: dict[str, Any]):
        """Forward the navigation and open a new lifecycle for the document it commits."""
        frame = message.get("params", {}).get("frame", {})
        webkit_frame_id = frame.get("id")
        is_top_frame = "parentId" not in frame
        if is_top_frame:
            # A top-frame navigation commits a new document; remember its loader for the
            # lifecycle events that follow.
            self._learn_webkit_frame_id(webkit_frame_id)
            self._loader_id = frame.get("loaderId", "") or ""
            self._top_frame_commits += 1
        # This handler bypasses the pass-through path, so map the frame ids here.
        self._map_frame_ids_outbound(message)
        mapped = message.get("params", {}).get("frame", {})
        client_frame_id = mapped.get("id")
        client_parent_id = mapped.get("parentId")
        if (
            client_parent_id is not None
            and isinstance(client_frame_id, str)
            and client_frame_id not in self._announced_frames
        ):
            # WebKit never sends Page.frameAttached. A client builds its frame model from the live
            # attach/navigate pair and only walks the frame tree once, when it attaches - so every
            # child frame that appeared later (or was recreated by a reload) stayed invisible to
            # it, and a navigation for a frame it does not know is discarded. Announce it first.
            self._announced_frames.add(client_frame_id)
            await self.output_queue.put({
                "method": "Page.frameAttached",
                "params": {"frameId": client_frame_id, "parentFrameId": client_parent_id},
            })
        await self.output_queue.put(message)
        # Chrome opens every document's lifecycle with "init" at commit time.
        await self._emit_lifecycle_event(
            "init",
            message.get("params", {}).get("timestamp"),
            frame_id=self._to_client_frame_id(webkit_frame_id),
            loader_id=frame.get("loaderId", ""),
        )

    async def _page_frame_detached(self, message: dict[str, Any]):
        """Forward the detach and forget the frame, so one that comes back is announced again."""
        self._map_frame_ids_outbound(message)
        frame_id = message.get("params", {}).get("frameId")
        if isinstance(frame_id, str):
            await self._destroy_frame_contexts(frame_id)
            self._announced_frames.discard(frame_id)
            self._frame_execution_ids.pop(frame_id, None)
        await self.output_queue.put(message)

    async def _page_dom_content_event_fired(self, message: dict[str, Any]):
        await self.output_queue.put(message)
        await self._emit_lifecycle_event("DOMContentLoaded", message.get("params", {}).get("timestamp"))

    async def _page_load_event_fired(self, message: dict[str, Any]):
        await self.output_queue.put(message)
        await self._emit_lifecycle_event("load", message.get("params", {}).get("timestamp"))

    async def _evaluate_json_in(self, context_id: Optional[int], expression: str) -> Optional[Any]:
        """_evaluate_json, in one particular frame's execution context."""
        params: dict[str, Any] = {"expression": self._tag_internal(expression), "returnByValue": True}
        if context_id:
            params["contextId"] = context_id
        response = await self.send_message_with_result("Runtime.evaluate", params)
        result = response.get("result", {}).get("result", {})
        if response.get("result", {}).get("wasThrown") or "value" not in result:
            return None
        return result["value"]

    async def _top_frame_context(self) -> Optional[int]:
        """The execution context of the frame the client attached to."""
        return self._frame_execution_ids.get(self.frame_id) or self._default_execution_id or None

    async def _child_frame_context(self, parent_frame_id: str, index: int) -> Optional[tuple[str, int]]:
        """The (frame, context) of a frame's nth child, or None when it cannot be reached."""
        tree = await self.send_message_with_result("Page.getResourceTree", {})
        frame_tree = tree.get("result", {}).get("frameTree")
        if frame_tree is None:
            return None
        self._map_frame_tree_ids(frame_tree)
        child = self._child_frame_at(frame_tree, parent_frame_id, index)
        if child is None:
            return None
        context = self._frame_execution_ids.get(child)
        return (child, context) if context is not None else None

    async def _context_at_point(self, x: int, y: int) -> tuple[Optional[int], int, int]:
        """Find the frame that owns a viewport point, and the point in that frame's coordinates.

        Synthesized input is dispatched by looking the target up in the page, and a document only
        knows its own elements: a point over an <iframe> finds the frame element itself, never
        what the user is aiming at inside it. Follow it down instead, subtracting each frame's
        offset on the way, so a click or a hover lands in the document that actually owns it.
        """
        frame_id = self.frame_id
        # Start with no context at all, so the device evaluates in its own current one; naming a
        # context we tracked earlier risks naming a stale one from a document already replaced.
        context_id: Optional[int] = None
        for _ in range(MAX_FRAME_DESCENT):
            probe = await self._evaluate_json_in(
                context_id,
                "(function () {"
                f"  const el = document.elementFromPoint({x}, {y});"
                "  if (!el || !el.tagName) { return null; }"
                "  const tag = el.tagName.toLowerCase();"
                "  if (tag !== 'iframe' && tag !== 'frame') { return null; }"
                "  const rect = el.getBoundingClientRect();"
                "  const frames = Array.prototype.slice.call(document.querySelectorAll('iframe, frame'));"
                "  return {index: frames.indexOf(el), left: rect.left, top: rect.top};"
                "})()",
            )
            if not isinstance(probe, dict):
                break
            found = cast(dict[str, Any], probe)
            child = await self._child_frame_context(frame_id, int(found["index"]))
            if child is None:
                break
            x -= int(found["left"])
            y -= int(found["top"])
            frame_id, context_id = child[0], child[1]
        return context_id, x, y

    async def _focused_context(self) -> Optional[int]:
        """The execution context of the document that holds the focus.

        Typing is dispatched at the focused element, and a document whose focus sits in a child
        frame reports the frame element as focused - so text aimed at a field inside it was typed
        into nothing at all, silently. The document that really holds the focus is the one that
        both has focus and has something typeable focused in it; a child frame wins over the top,
        which is only reporting the frame element.
        """
        typeable = (
            "(function () {"
            "  const active = document.activeElement;"
            "  if (!active || !document.hasFocus || !document.hasFocus()) { return false; }"
            "  if (active.isContentEditable) { return true; }"
            "  const tag = active.tagName ? active.tagName.toLowerCase() : '';"
            "  return tag === 'input' || tag === 'textarea';"
            "})()"
        )
        # The common case by far: nothing is framed, or the focus is already on a field in the
        # document the session is attached to. Asking it first keeps typing a single round-trip.
        if await self._evaluate_json_in(None, typeable) is True:
            return None
        for frame_id, context_id in self._frame_execution_ids.items():
            if frame_id == self.frame_id:
                continue
            if await self._evaluate_json_in(context_id, typeable) is True:
                return context_id
        return None

    async def _evaluate_json(self, expression: str) -> Optional[Any]:
        """Evaluate an expression that returns JSON-serializable data and give back the value.

        WebKit's Runtime.evaluate honours returnByValue, so the result comes back inline rather
        than as a remote object handle.
        """
        response = await self.send_message_with_result(
            "Runtime.evaluate", {"expression": self._tag_internal(expression), "returnByValue": True}
        )
        result = response.get("result", {}).get("result", {})
        if response.get("result", {}).get("wasThrown") or "value" not in result:
            return None
        return result["value"]

    async def _page_get_layout_metrics(self, message: dict[str, Any]):
        """
        WebKit has no Page.getLayoutMetrics. It is the first call of Chrome's screenshot path
        (the clip rectangle and the device-pixel scale are computed from it), so page.screenshot()
        died on it before any capture was attempted. Measure the page itself instead.
        """
        metrics = await self._evaluate_json(
            "(() => {"
            "  const d = document.documentElement, b = document.body || d;"
            "  const vv = window.visualViewport;"
            "  const width = Math.max(d.scrollWidth, b.scrollWidth, d.clientWidth);"
            "  const height = Math.max(d.scrollHeight, b.scrollHeight, d.clientHeight);"
            "  return {"
            "    x: window.scrollX, y: window.scrollY,"
            "    clientWidth: d.clientWidth || window.innerWidth,"
            "    clientHeight: d.clientHeight || window.innerHeight,"
            "    width: width, height: height,"
            "    scale: vv ? vv.scale : 1,"
            "    offsetX: vv ? vv.offsetLeft : 0, offsetY: vv ? vv.offsetTop : 0,"
            "    pageX: vv ? vv.pageLeft : window.scrollX, pageY: vv ? vv.pageTop : window.scrollY,"
            "    vw: vv ? vv.width : window.innerWidth, vh: vv ? vv.height : window.innerHeight,"
            "    dpr: window.devicePixelRatio || 1"
            "  };"
            "})()"
        )
        if not isinstance(metrics, dict):
            await self._error_response(
                message, {"code": -32000, "message": "the device did not report its layout metrics"}
            )
            return
        m = cast(dict[str, Any], metrics)
        layout_viewport = {
            "pageX": int(m["x"]),
            "pageY": int(m["y"]),
            "clientWidth": int(m["clientWidth"]),
            "clientHeight": int(m["clientHeight"]),
        }
        visual_viewport: dict[str, Any] = {
            "offsetX": m["offsetX"],
            "offsetY": m["offsetY"],
            "pageX": m["pageX"],
            "pageY": m["pageY"],
            "clientWidth": m["vw"],
            "clientHeight": m["vh"],
            "scale": m["scale"],
            "zoom": 1,
        }
        content_size: dict[str, Any] = {"x": 0, "y": 0, "width": m["width"], "height": m["height"]}
        # Everything above is measured in CSS pixels, so the css* variants are the same values.
        # Chrome's client divides contentSize by cssContentSize to recover the device pixel ratio;
        # reporting equal sizes keeps that ratio at 1, which is what the snapshots below are in.
        await self.output_queue.put({
            "id": message["id"],
            "result": {
                "layoutViewport": layout_viewport,
                "visualViewport": visual_viewport,
                "contentSize": content_size,
                "cssLayoutViewport": layout_viewport,
                "cssVisualViewport": visual_viewport,
                "cssContentSize": content_size,
            },
        })

    async def _page_capture_screenshot(self, message: dict[str, Any]):
        """
        WebKit has no Page.captureScreenshot, but it does have Page.snapshotRect - the same call
        the screencast is built on. Translate between them: Chrome asks for a clip in page
        coordinates and wants raw base64 image bytes, WebKit answers a rect with a data URL.
        """
        params = message.get("params", {})
        clip = params.get("clip")
        rect: dict[str, Any]
        if clip:
            rect = {
                "x": int(clip.get("x", 0)),
                "y": int(clip.get("y", 0)),
                "width": int(clip.get("width", 0)),
                "height": int(clip.get("height", 0)),
                # A clip is expressed in document coordinates, which is WebKit's "Page" system.
                "coordinateSystem": "Page",
            }
        else:
            # No clip: capture the visible viewport.
            metrics = await self._evaluate_json(
                "({w: window.innerWidth, h: window.innerHeight, x: window.scrollX, y: window.scrollY})"
            )
            if not isinstance(metrics, dict):
                await self._error_response(
                    message, {"code": -32000, "message": "the device did not report its viewport"}
                )
                return
            m = cast(dict[str, Any], metrics)
            rect = {
                "x": int(m["x"]),
                "y": int(m["y"]),
                "width": int(m["w"]),
                "height": int(m["h"]),
                "coordinateSystem": "Page",
            }
        if rect["width"] <= 0 or rect["height"] <= 0:
            await self._error_response(message, {"code": -32000, "message": "cannot capture an empty rectangle"})
            return
        response = await self.send_message_with_result_across_swaps("Page.snapshotRect", rect)
        data_url = response.get("result", {}).get("dataURL")
        if not data_url:
            await self._error_response(
                message,
                response.get("error") or {"code": -32000, "message": "the device did not answer Page.snapshotRect"},
            )
            return
        # WebKit answers a data: URL; Chrome's captureScreenshot answers the bare base64 payload.
        marker = "base64,"
        index = data_url.find(marker)
        await self.output_queue.put({
            "id": message["id"],
            "result": {"data": data_url[index + len(marker) :] if index != -1 else data_url},
        })

    async def _call_on_object(self, object_id: str, function_declaration: str) -> dict[str, Any]:
        """Runtime.callFunctionOn against a remote object, returning the value by value."""
        return await self.send_message_with_result(
            "Runtime.callFunctionOn",
            {"objectId": object_id, "functionDeclaration": function_declaration, "returnByValue": True},
        )

    async def _dom_scroll_into_view_if_needed(self, message: dict[str, Any]):
        """
        WebKit has no DOM.scrollIntoViewIfNeeded. Chrome clients call it before every click, fill
        or hover to bring the target into view, and Playwright treats the resulting "not found"
        as a retryable condition - so every interaction spun until its timeout with no error
        surfaced. Scroll the element in-page instead, reporting the two failures the caller
        distinguishes (a detached node, and one with no layout box).
        """
        object_id = message.get("params", {}).get("objectId")
        if not object_id:
            # Only the objectId form is used by CDP clients; a nodeId would need a DOM.getDocument
            # round-trip that the callers do not perform.
            await self._error_response(message, {"code": -32000, "message": "objectId is required"})
            return
        response = await self._call_on_object(
            object_id,
            "function() {"
            "  const node = this.nodeType === Node.ELEMENT_NODE ? this : this.parentElement;"
            "  if (!node || !node.isConnected) { return 'detached'; }"
            "  if (!node.getClientRects().length) { return 'nolayout'; }"
            "  node.scrollIntoView({block: 'center', inline: 'center', behavior: 'instant'});"
            "  return 'done';"
            "}",
        )
        outcome = response.get("result", {}).get("result", {}).get("value")
        if outcome == "detached":
            await self._error_response(message, {"code": -32000, "message": "Node is detached from document"})
            return
        if outcome == "nolayout":
            await self._error_response(message, {"code": -32000, "message": "Node does not have a layout object"})
            return
        if outcome != "done":
            await self._error_response(
                message,
                response.get("error") or {"code": -32000, "message": "the device did not scroll the node into view"},
            )
            return
        await self._simple_response(message, None)

    async def _dom_get_content_quads(self, message: dict[str, Any]):
        """
        WebKit has no DOM.getContentQuads. Chrome clients use the quads it returns to pick the
        point to click, so without it an interaction never gets past its actionability check.
        Measure the element's border boxes in-page; each rect becomes a quad of its corners, in
        the viewport coordinates Chrome reports them in.
        """
        object_id = message.get("params", {}).get("objectId")
        if not object_id:
            await self._error_response(message, {"code": -32000, "message": "objectId is required"})
            return
        response = await self._call_on_object(
            object_id,
            "function() {"
            "  const node = this.nodeType === Node.ELEMENT_NODE ? this : this.parentElement;"
            "  if (!node || !node.isConnected) { return null; }"
            "  return Array.from(node.getClientRects()).map("
            "    r => [r.left, r.top, r.right, r.top, r.right, r.bottom, r.left, r.bottom]);"
            "}",
        )
        quads = response.get("result", {}).get("result", {}).get("value")
        if quads is None:
            await self._error_response(
                message,
                response.get("error") or {"code": -32000, "message": "Node is detached from document"},
            )
            return
        # The boxes were measured in the element's own document; a client expects them in the
        # page's coordinates, so shift them by where that frame sits (see _frame_viewport_offset).
        offset_x, offset_y = await self._frame_viewport_offset(self._frame_of_object(cast(str, object_id)))
        if offset_x or offset_y:
            quads = [
                [value + (offset_x if position % 2 == 0 else offset_y) for position, value in enumerate(quad)]
                for quad in cast(list[list[float]], quads)
            ]
        await self.output_queue.put({"id": message["id"], "result": {"quads": quads}})

    def _frame_of_object(self, object_id: str) -> Optional[str]:
        """The frame a remote object lives in, read out of the object id itself.

        WebKit encodes the context an object belongs to in its id (`injectedScriptId`), and the
        contexts are already tracked per frame, so an object can be traced back to its document
        without asking the device anything.
        """
        try:
            context_id = json.loads(object_id).get("injectedScriptId")
        except (ValueError, TypeError, AttributeError):
            return None
        for frame_id, frame_context in self._frame_execution_ids.items():
            if frame_context == context_id:
                return frame_id
        return None

    def _child_frame_at(self, node: Any, parent_frame_id: str, index: int) -> Optional[str]:
        """The id of the `index`-th child frame of `parent_frame_id`, walking a frame tree.

        The frame tree lists a frame's children in document order, which is the order the
        elements appear in - so the nth <iframe> of a document owns the nth child frame. This
        identifies a frame that carries nothing to match on, which a name or a URL cannot: a
        srcdoc or about:blank frame has neither, and several frames may share a URL.
        """
        if not isinstance(node, dict):
            return None
        tree = cast(dict[str, Any], node)
        frame = tree.get("frame")
        children = cast(list[Any], tree.get("childFrames") or [])
        if isinstance(frame, dict) and cast(dict[str, Any], frame).get("id") == parent_frame_id:
            if 0 <= index < len(children):
                child = children[index]
                if isinstance(child, dict):
                    child_frame = cast(dict[str, Any], child).get("frame")
                    if isinstance(child_frame, dict):
                        found = cast(dict[str, Any], child_frame).get("id")
                        return found if isinstance(found, str) else None
            return None
        for child in children:
            found = self._child_frame_at(child, parent_frame_id, index)
            if found is not None:
                return found
        return None

    def _frame_index_path(self, node: Any, target: str, path: Optional[list[int]] = None) -> Optional[list[int]]:
        """The child indices leading from the top frame down to `target`, or None."""
        if not isinstance(node, dict):
            return None
        tree = cast(dict[str, Any], node)
        frame = tree.get("frame")
        here = path or []
        if isinstance(frame, dict) and cast(dict[str, Any], frame).get("id") == target:
            return here
        for index, child in enumerate(cast(list[Any], tree.get("childFrames") or [])):
            found = self._frame_index_path(child, target, [*here, index])
            if found is not None:
                return found
        return None

    async def _frame_viewport_offset(self, frame_id: Optional[str]) -> tuple[float, float]:
        """Where a frame's viewport sits inside the top frame's.

        A document measures its elements against its own viewport, so a box measured inside a
        child frame is offset from the page by however far that frame sits down and across. A
        client places its clicks in page coordinates, so the two have to be reconciled or every
        interaction inside a frame is aimed at the wrong place.
        """
        if frame_id is None or frame_id == self.frame_id:
            return (0.0, 0.0)
        tree = await self.send_message_with_result("Page.getResourceTree", {})
        frame_tree = tree.get("result", {}).get("frameTree")
        if frame_tree is None:
            return (0.0, 0.0)
        self._map_frame_tree_ids(frame_tree)
        path = self._frame_index_path(frame_tree, frame_id)
        if not path:
            return (0.0, 0.0)
        offset_x = offset_y = 0.0
        context_id = await self._top_frame_context()
        current = self.frame_id
        for index in path:
            rect = await self._evaluate_json_in(
                context_id,
                "(function () {"
                f"  const frame = document.querySelectorAll('iframe, frame')[{index}];"
                "  if (!frame) { return null; }"
                "  const rect = frame.getBoundingClientRect();"
                "  return {left: rect.left, top: rect.top};"
                "})()",
            )
            if not isinstance(rect, dict):
                break
            box = cast(dict[str, Any], rect)
            offset_x += float(box["left"])
            offset_y += float(box["top"])
            child = self._child_frame_at(frame_tree, current, index)
            if child is None:
                break
            child_context = self._frame_execution_ids.get(child)
            if child_context is None:
                break
            current, context_id = child, child_context
        return (offset_x, offset_y)

    def _find_frame_in_tree(self, node: Any, name: str, url: str) -> Optional[str]:
        """Find the frame an <iframe> hosts, by the name it was given or the URL it loaded.

        WebKit exposes no handle from a DOM element to its frame, so the two are correlated
        through the frame tree. A name is authoritative when the page sets one; otherwise the URL
        identifies the frame, and an ambiguous match is reported as no match rather than a guess.
        """
        matches: list[str] = []

        def walk(tree: Any) -> None:
            if not isinstance(tree, dict):
                return
            branch = cast(dict[str, Any], tree)
            frame = branch.get("frame")
            if isinstance(frame, dict):
                candidate = cast(dict[str, Any], frame)
                frame_id = candidate.get("id")
                is_child = isinstance(frame_id, str) and candidate.get("parentId") is not None
                identified = (name and candidate.get("name") == name) or (
                    not name and url and candidate.get("url") == url
                )
                if is_child and identified:
                    matches.append(cast(str, frame_id))
            for child in cast(list[Any], branch.get("childFrames") or []):
                walk(child)

        walk(node)
        return matches[0] if len(matches) == 1 else None

    async def _dom_describe_node(self, message: dict[str, Any]):
        """
        WebKit has no DOM.describeNode. A client uses it to resolve an <iframe> element to the
        frame it hosts - that is how frameLocator()/contentFrame() reach into a child frame - and
        reads `node.frameId` out of the answer. Correlate the element with the frame tree.
        """
        object_id = message.get("params", {}).get("objectId")
        if not object_id:
            await self._error_response(message, {"code": -32000, "message": "objectId is required"})
            return
        described = await self._call_on_object(
            object_id,
            "function() {"
            "  if (!this.tagName) { return null; }"
            "  const tag = this.tagName.toLowerCase();"
            "  const frames = Array.prototype.slice.call("
            "      this.ownerDocument.querySelectorAll('iframe, frame'));"
            "  return {"
            "    nodeName: this.tagName,"
            "    localName: tag,"
            "    isFrame: tag === 'iframe' || tag === 'frame',"
            "    index: frames.indexOf(this),"
            "    name: this.getAttribute ? (this.getAttribute('name') || '') : '',"
            "    url: this.src || ''"
            "  };"
            "}",
        )
        value = described.get("result", {}).get("result", {}).get("value")
        if not isinstance(value, dict):
            await self._error_response(message, {"code": -32000, "message": "Node is detached from document"})
            return
        info = cast(dict[str, Any], value)
        backend_node_id = next(_DESCRIBED_NODE_IDS)
        self._described_nodes[backend_node_id] = cast(str, object_id)
        node: dict[str, Any] = {
            "nodeId": 0,
            "backendNodeId": backend_node_id,
            "nodeType": 1,
            "nodeName": info.get("nodeName", ""),
            "localName": info.get("localName", ""),
            "nodeValue": "",
            "childNodeCount": 0,
            "attributes": [],
        }
        if info.get("isFrame"):
            tree = await self.send_message_with_result("Page.getResourceTree", {})
            frame_tree = tree.get("result", {}).get("frameTree")
            self._map_frame_tree_ids(frame_tree)
            # Correlate the element with the frame it hosts. Prefer the name it was given or the
            # URL it loaded, which identify the frame outright: iOS 26 orders a document's entries
            # in the frame tree by when each frame was created, not by where its <iframe> sits in
            # the document, so pairing the nth <iframe> with the nth tree child (the positional
            # fallback below) mis-maps every frame whose DOM position differs from its creation
            # order - which is what left fill()/click() acting on the wrong cross-origin frame.
            # Positional matching stays as the last resort, for a frame that a unique name or URL
            # cannot pick out: a srcdoc or about:blank frame, or several sharing a URL.
            frame_id: Optional[str] = self._find_frame_in_tree(
                frame_tree, cast(str, info.get("name") or ""), cast(str, info.get("url") or "")
            )
            if frame_id is None:
                owner = self._frame_of_object(cast(str, object_id))
                index = info.get("index")
                if owner is not None and isinstance(index, int):
                    frame_id = self._child_frame_at(frame_tree, owner, index)
            if frame_id is not None:
                node["frameId"] = frame_id
        await self.output_queue.put({"id": message["id"], "result": {"node": node}})

    def _frame_at_path(self, node: Any, path: list[int]) -> Optional[str]:
        """The id of the frame reached by walking `path` from the top of a frame tree."""
        current = node
        for index in path:
            if not isinstance(current, dict):
                return None
            children = cast(list[Any], cast(dict[str, Any], current).get("childFrames") or [])
            if not 0 <= index < len(children):
                return None
            current = children[index]
        if not isinstance(current, dict):
            return None
        frame = cast(dict[str, Any], current).get("frame")
        if not isinstance(frame, dict):
            return None
        frame_id = cast(dict[str, Any], frame).get("id")
        return frame_id if isinstance(frame_id, str) else None

    async def _dom_get_frame_owner(self, message: dict[str, Any]):
        """
        WebKit has no DOM.getFrameOwner. A client asks it which element hosts a frame so it can
        measure where that frame sits, which is part of every interaction with something inside
        one - without it the actionability check never completes and the action spins until it
        times out. Answer with a node id of our own, resolved back in _dom_resolve_node.
        """
        frame_id = message.get("params", {}).get("frameId")
        tree = await self.send_message_with_result("Page.getResourceTree", {})
        frame_tree = tree.get("result", {}).get("frameTree")
        path: Optional[list[int]] = None
        if frame_tree is not None and isinstance(frame_id, str):
            self._map_frame_tree_ids(frame_tree)
            path = self._frame_index_path(frame_tree, frame_id)
        if not path:
            # The message a client special-cases into "Frame has been detached."
            await self._error_response(message, {"code": -32000, "message": "Frame with the given id was not found."})
            return
        parent_frame_id = self._frame_at_path(frame_tree, path[:-1])
        if parent_frame_id is None:
            await self._error_response(message, {"code": -32000, "message": "Frame with the given id was not found."})
            return
        backend_node_id = next(_FRAME_OWNER_NODE_IDS)
        self._frame_owner_nodes[backend_node_id] = (parent_frame_id, path[-1])
        await self.output_queue.put({"id": message["id"], "result": {"backendNodeId": backend_node_id}})

    async def _dom_resolve_node(self, message: dict[str, Any]):
        """Resolve a node back to an object. Only the frame-owner ids minted above are handled
        here; anything else is WebKit's own and is passed through."""
        backend_node_id = message.get("params", {}).get("backendNodeId")
        if isinstance(backend_node_id, int):
            described = self._described_nodes.get(backend_node_id)
            if described is not None:
                # A client resolves a node to move it between worlds. The worlds this bridge
                # hands out are all backed by the frame's one real context (see
                # _page_create_isolated_world), so the node needs no moving - but it does need a
                # handle of its own: the client releases the handle it described from, and
                # answering with that same one hands back a reference it has already dropped.
                fresh = await self.send_message_with_result(
                    "Runtime.callFunctionOn",
                    {"objectId": described, "functionDeclaration": "function() { return this; }"},
                )
                remote_object = fresh.get("result", {}).get("result")
                if not isinstance(remote_object, dict) or "objectId" not in cast(dict[str, Any], remote_object):
                    await self._error_response(message, {"code": -32000, "message": "No node with given id found"})
                    return
                node_object = cast(dict[str, Any], remote_object)
                node_object.setdefault("subtype", "node")
                await self.output_queue.put({"id": message["id"], "result": {"object": node_object}})
                return
        owner = self._frame_owner_nodes.get(backend_node_id) if isinstance(backend_node_id, int) else None
        if owner is None:
            await self._send_message_to_target(message)
            return
        parent_frame_id, index = owner
        params: dict[str, Any] = {
            "expression": self._tag_internal(f"document.querySelectorAll('iframe, frame')[{index}]")
        }
        context_id = self._frame_execution_ids.get(parent_frame_id)
        if context_id:
            params["contextId"] = context_id
        response = await self.send_message_with_result("Runtime.evaluate", params)
        remote_object = response.get("result", {}).get("result")
        if not isinstance(remote_object, dict) or "objectId" not in cast(dict[str, Any], remote_object):
            await self._error_response(message, {"code": -32000, "message": "Frame has been detached."})
            return
        await self.output_queue.put({"id": message["id"], "result": {"object": remote_object}})

    async def _page_create_isolated_world(self, message: dict[str, Any]):
        """
        WebKit's Web Inspector has no Page.createIsolatedWorld. Chrome clients (Playwright) create
        an isolated world to run their own helpers off the page's globals and block every evaluate
        until its execution context is announced - so read APIs (page.title(), locator text) hang
        forever otherwise.

        Synthesize the world: mint a context id, announce a Runtime.executionContextCreated for it
        named as requested (so the client binds it to its "utility" world), and answer with that
        id. WebKit cannot actually isolate it, so evaluations addressed to it are rerouted to the
        page's real main-world context in _runtime_evaluate. The isolation is only advisory here;
        reads return correct results, which is what these APIs need.
        """
        params = message.get("params", {})
        # _input_loop already mapped params.frameId back to WebKit's id; report the client's.
        frame_id = self._to_client_frame_id(params.get("frameId"))
        context_id = await self._announce_isolated_world(frame_id, params.get("worldName", ""))
        await self.output_queue.put({"id": message["id"], "result": {"executionContextId": context_id}})

    async def _announce_isolated_world(self, frame_id: Any, world_name: str) -> int:
        """Mint a synthesized isolated world for a frame and announce it. See
        _page_create_isolated_world for why these are synthesized at all."""
        context_id = next(_ISOLATED_WORLD_IDS)
        self._isolated_world_context_ids.add(context_id)
        self._isolated_world_names[context_id] = world_name
        if isinstance(frame_id, str):
            self._isolated_world_frames[context_id] = frame_id
            self._announced_worlds.add((frame_id, world_name))
        await self.output_queue.put({
            "method": "Runtime.executionContextCreated",
            "params": {
                "context": {
                    "id": context_id,
                    "origin": "",
                    "name": world_name,
                    "uniqueId": f"{frame_id}.{context_id}",
                    "auxData": {"isDefault": False, "type": "isolated", "frameId": frame_id},
                }
            },
        })
        await self._install_bindings_for_context(context_id, world_name)
        return context_id

    async def _dom_get_box_model(self, message: dict[str, Any]):
        """
        WebKit has no DOM.getBoxModel. A client measures an element with it - it is how the
        position of the frame an element sits in is worked out, so without a real answer every
        interaction inside a child frame failed its actionability check and retried until it
        timed out. Measure the element in-page, in the page's coordinates.

        This used to be turned into a DOM.highlightNode, which drew the box rather than reporting
        it; highlighting has its own translation (see Overlay.highlightNode).
        """
        object_id = message.get("params", {}).get("objectId")
        if not object_id:
            await self._error_response(message, {"code": -32000, "message": "objectId is required"})
            return
        boxes = await self._call_on_object(
            object_id,
            "function() {"
            "  const node = this.nodeType === Node.ELEMENT_NODE ? this : this.parentElement;"
            "  if (!node || !node.isConnected) { return null; }"
            "  const rect = node.getBoundingClientRect();"
            "  const style = window.getComputedStyle(node);"
            "  const px = name => parseFloat(style.getPropertyValue(name)) || 0;"
            "  return {"
            "    left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,"
            "    width: node.offsetWidth || rect.width, height: node.offsetHeight || rect.height,"
            "    mt: px('margin-top'), mr: px('margin-right'), mb: px('margin-bottom'), ml: px('margin-left'),"
            "    bt: px('border-top-width'), br: px('border-right-width'),"
            "    bb: px('border-bottom-width'), bl: px('border-left-width'),"
            "    pt: px('padding-top'), pr: px('padding-right'),"
            "    pb: px('padding-bottom'), pl: px('padding-left')"
            "  };"
            "}",
        )
        measured = boxes.get("result", {}).get("result", {}).get("value")
        if not isinstance(measured, dict):
            await self._error_response(message, {"code": -32000, "message": "Could not compute box model."})
            return
        box = cast(dict[str, Any], measured)
        offset_x, offset_y = await self._frame_viewport_offset(self._frame_of_object(cast(str, object_id)))

        def quad(left: float, top: float, right: float, bottom: float) -> list[float]:
            left += offset_x
            right += offset_x
            top += offset_y
            bottom += offset_y
            return [left, top, right, top, right, bottom, left, bottom]

        border = quad(box["left"], box["top"], box["right"], box["bottom"])
        padding = quad(
            box["left"] + box["bl"],
            box["top"] + box["bt"],
            box["right"] - box["br"],
            box["bottom"] - box["bb"],
        )
        content = quad(
            box["left"] + box["bl"] + box["pl"],
            box["top"] + box["bt"] + box["pt"],
            box["right"] - box["br"] - box["pr"],
            box["bottom"] - box["bb"] - box["pb"],
        )
        margin = quad(
            box["left"] - box["ml"],
            box["top"] - box["mt"],
            box["right"] + box["mr"],
            box["bottom"] + box["mb"],
        )
        await self.output_queue.put({
            "id": message["id"],
            "result": {
                "model": {
                    "content": content,
                    "padding": padding,
                    "border": border,
                    "margin": margin,
                    "width": int(box["width"]),
                    "height": int(box["height"]),
                }
            },
        })

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
        screencast = ScreenCast(self, params["format"], params["quality"], params["maxWidth"], params["maxHeight"])
        deadline = asyncio.get_event_loop().time() + SWAP_COMMIT_TIMEOUT
        while True:
            target_id = self.target_id
            try:
                await screencast.start()
            except ScreencastUnavailableError as e:
                # The size probe found no page to capture. A process swap swallowed it (DevTools
                # starts the screencast while the page it just opened is still navigating, and
                # unlike the resource tree it never asks again - the screen would stay black for
                # the rest of the session), so re-probe the target that took over.
                if await self._await_target_swap(target_id, deadline):
                    continue
                # Nothing took over: a JSContext debuggable, or a page that went quiet. Refuse
                # rather than keep a screencast that never started - closing the session would
                # then fail on it and leave the target's queue-consumer tasks draining the next.
                await self._error_response(message, {"code": -32000, "message": str(e)})
                return
            break
        self.screencast = screencast
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
        # WebKit only has Page.getResourceTree; ask it for that even when the frontend called the
        # (WebKit-absent) Page.getFrameTree, whose response Chrome reads out of the same frameTree.
        result = await self.send_message_with_result_across_swaps("Page.getResourceTree", message.get("params", {}))
        if "result" not in result:
            # No frame tree to report: a JSContext debuggable implements no Page domain and says
            # so, and a target that stopped answering yields nothing at all. Relay that - a real
            # Node target answers Chrome's frontends with the same error and they carry on.
            await self._error_response(
                message,
                result.get("error")
                or (
                    dict(TARGET_CLOSED_ERROR)
                    if self.target_id in self._destroyed_targets
                    else {"code": -32000, "message": f"the device did not answer {message['method']}"}
                ),
            )
            return
        self.frame = result["result"]["frameTree"]["frame"]
        # The top frame's id must be the id the client attached with (see self.frame_id); learn
        # WebKit's own id for it and rewrite it in the response the client reads.
        self._learn_webkit_frame_id(self.frame.get("id"))
        self._loader_id = self.frame.get("loaderId", "") or self._loader_id
        # Every frame in the tree is reported by the id the client knows it as - the top frame's
        # included, and so is each child's parentId. A child whose parent names WebKit's own id
        # for the top frame refers to a frame the client has never heard of, and it drops the
        # child rather than attaching it to nothing: the whole subtree stays invisible.
        self._map_frame_tree_ids(result["result"]["frameTree"])
        # The client builds frames from this snapshot too; remember them so they are not announced
        # a second time.
        self._remember_frame_tree(result["result"]["frameTree"])
        # result carries our internal request id; answer the frontend with its own id.
        await self.output_queue.put({"id": message["id"], "result": result["result"]})

    def _map_frame_tree_ids(self, node: Any) -> None:
        """Rewrite WebKit's frame ids to the client's throughout a frame tree, in place."""
        if not isinstance(node, dict):
            return
        tree = cast(dict[str, Any], node)
        frame = tree.get("frame")
        if isinstance(frame, dict):
            entry = cast(dict[str, Any], frame)
            for key in ("id", "parentId"):
                if key in entry:
                    entry[key] = self._to_client_frame_id(entry[key])
        for child in cast(list[Any], tree.get("childFrames") or []):
            self._map_frame_tree_ids(child)

    def _remember_frame_tree(self, node: Any) -> None:
        """Record every child frame a frame tree already told the client about."""
        if not isinstance(node, dict):
            return
        tree = cast(dict[str, Any], node)
        frame = tree.get("frame")
        if isinstance(frame, dict):
            frame_id = cast(dict[str, Any], frame).get("id")
            if isinstance(frame_id, str) and cast(dict[str, Any], frame).get("parentId") is not None:
                self._announced_frames.add(frame_id)
        for child in cast(list[Any], tree.get("childFrames") or []):
            self._remember_frame_tree(child)

    async def _override_user_preference(self, name: str, value: Optional[str]) -> None:
        """Page.overrideUserPreference: `value` absent clears the override (WebKit main and iOS 26)."""
        params: dict[str, Any] = {"name": name}
        if value is not None:
            params["value"] = value
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Page.overrideUserPreference",
            "params": params,
        })

    async def _emulation_set_emulated_media(self, message: dict[str, Any]):
        # Chrome carries the media type and the media features in one command; WebKit takes the
        # type (Page.setEmulatedMedia, `media` required) and each feature as a separate user
        # preference override. Features absent from the list are reset, as in Chrome.
        params: dict[str, Any] = message.get("params") or {}
        features: list[dict[str, Any]] = params.get("features") or []
        wanted: dict[str, Optional[str]] = {}
        for feature in features:
            mapping = USER_PREFERENCE_FEATURES.get(str(feature.get("name", "")))
            if mapping is None:
                continue
            name, values = mapping
            wanted[name] = values.get(str(feature.get("value", "")))
        for name in sorted(self._emulated_preferences - set(wanted)):
            wanted[name] = None
        for name, value in wanted.items():
            await self._override_user_preference(name, value)
        self._emulated_preferences = {name for name, value in wanted.items() if value is not None}
        message["method"] = "Page.setEmulatedMedia"
        message["params"] = {"media": params.get("media") or ""}
        await self._send_message_to_target(message)

    async def _emulation_set_auto_dark_mode_override(self, message: dict[str, Any]):
        # `enabled` absent restores the page's own color scheme; so does a valueless override.
        params: dict[str, Any] = message.get("params") or {}
        enabled: Optional[bool] = params.get("enabled")
        message["method"] = "Page.overrideUserPreference"
        message["params"] = {"name": "PrefersColorScheme"}
        if enabled is not None:
            message["params"]["value"] = "Dark" if enabled else "Light"
        await self._send_message_to_target(message)

    async def _debugger_enable(self, message: dict[str, Any]):
        if self.held_events and self._holding_task is None:
            # An adopting frontend: what the target emitted while held follows this response.
            self._replay_after_id = message["id"]
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
        if self.pause_on_start and not self.waiting_for_debugger:
            # Pause mode on a debuggable that could not be held before it ran: stop it on its
            # next statement now that the client's debugger is on. A held one is paused by
            # WebKit itself when released.
            await self._pause_target(self.target_id)

    async def _debugger_set_skip_all_pauses(self, message: dict[str, Any]) -> None:
        # WebKit has no setSkipAllPauses (WebStorm sends it on attach); skipping every pause is
        # what deactivating breakpoints and debugger statements amounts to, and un-skipping is
        # the state _debugger_enable establishes. Both are replayed onto new targets.
        skip = bool(message.get("params", {}).get("skip"))
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Debugger.setBreakpointsActive",
            "params": {"active": not skip},
        })
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Debugger.setPauseOnDebuggerStatements",
            "params": {"enabled": not skip},
        })
        await self._result_response(message, {})

    async def _runtime_run_if_waiting_for_debugger(self, message: dict[str, Any]) -> None:
        await self.release_debugger()
        await self._simple_response(message, None)

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
        params = message["params"]
        if self._flat:
            script_id = self._flat_breakpoint_script(params)
            if script_id is not None:
                # A URL breakpoint does not bind on a URL-less JSContext script; set it by the
                # script's location instead - the only kind that binds - and answer the frontend
                # in the shape it expects from setBreakpointByUrl.
                location: dict[str, Any] = {"scriptId": script_id, "lineNumber": params.get("lineNumber", 0)}
                if "columnNumber" in params:
                    location["columnNumber"] = params["columnNumber"]
                set_params: dict[str, Any] = {"location": location}
                if params.get("condition"):
                    set_params["options"] = {"condition": params["condition"]}
                response = await self.send_message_with_result("Debugger.setBreakpoint", set_params)
                result = response.get("result", {})
                breakpoint_id = result.get("breakpointId") or f"url:{params.get('url')}"
                locations = [result["actualLocation"]] if "actualLocation" in result else []
                await self._result_response(message, {"breakpointId": breakpoint_id, "locations": locations})
                return
            # No such script yet. Its synthetic URL cannot bind on the device (see
            # _debugger_script_parsed), so keep the request and bind it when the script appears,
            # reporting Debugger.breakpointResolved then - what V8 does for a not-yet-loaded file.
            breakpoint_id = f"{params.get('url') or params.get('urlRegex') or ''}:{params.get('lineNumber', 0)}:{params.get('columnNumber', 0)}"
            self._flat_pending_url_breakpoints[breakpoint_id] = dict(params)
            await self._result_response(message, {"breakpointId": breakpoint_id, "locations": []})
            return
        condition = params.pop("condition", "")
        if condition:
            params["options"]["condition"] = condition
        await self._send_message_to_target(message)

    def _flat_breakpoint_script(self, params: dict[str, Any]) -> Optional[str]:
        """The JSContext script a URL breakpoint targets: by exact synthetic URL, or by a urlRegex
        that matches one. None when it targets no known script (then it is forwarded unchanged)."""
        url = params.get("url")
        if url and url in self._flat_script_url_to_id:
            return self._flat_script_url_to_id[url]
        url_regex = params.get("urlRegex")
        if url_regex:
            try:
                pattern = re.compile(url_regex)
            except re.error:
                return None
            for known_url, script_id in self._flat_script_url_to_id.items():
                if pattern.search(known_url):
                    return script_id
        return None

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
        # WebKit only reports the console's inspect() through Inspector.inspect once the Inspector
        # domain is enabled - something no Chrome client sends, as V8 has no such domain.
        await self._send_message_to_target({"id": self.next_internal_id(), "method": "Inspector.enable", "params": {}})
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
        self._translate_user_gesture(params)
        if self._flat:
            # The context the frontend targets is the one synthesized in _runtime_enable, which the
            # debuggable knows nothing about; addressing it explicitly would fail the lookup. It has
            # exactly one context anyway - let it use its default.
            params.pop("contextId", None)
            params.pop("uniqueContextId", None)
        elif params.get("contextId") in self._isolated_world_context_ids:
            # A synthesized isolated world (see _page_create_isolated_world) has no real context on
            # the device; run in the real main-world context of the frame it was created for.
            world_frame = self._isolated_world_frames.get(params["contextId"], self.frame_id)
            real_context = self._frame_execution_ids.get(world_frame)
            if real_context is None and world_frame != self.frame_id:
                # A frame whose context this session never saw - a cross-origin child, which
                # WebKit debugs through a target of its own that this session does not adopt.
                # Refuse: evaluating in the top frame instead would quietly answer questions
                # about the wrong document, which is far worse than saying so.
                await self._error_response(
                    message,
                    {
                        "code": -32000,
                        "message": (
                            f"no execution context for frame {world_frame}; "
                            "a cross-origin child frame is not reachable through this session"
                        ),
                    },
                )
                return
            real_context = real_context or self._default_execution_id
            if real_context:
                params["contextId"] = real_context
            else:
                params.pop("contextId", None)
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

    @staticmethod
    def _translate_user_gesture(params: dict[str, Any]) -> None:
        """Carry a client's "this is a user gesture" flag across to the name WebKit knows.

        Chrome calls it `userGesture`, WebKit `emulateUserGesture`, and an unrecognized parameter
        is simply ignored - so the call ran with no gesture behind it. That is not cosmetic: an
        element inside a cross-origin frame cannot be focused without one, so a client's fill()
        (which focuses the field, then types into whatever holds the focus) quietly typed
        nowhere and left the field empty.
        """
        if "userGesture" in params:
            params["emulateUserGesture"] = bool(params.pop("userGesture"))

    async def _runtime_call_function_on(self, message: dict[str, Any]):
        self._translate_user_gesture(message.setdefault("params", {}))
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
        # Follow the point into the frame that owns it, so a click on something inside an iframe
        # reaches that element rather than the frame it happens to sit in.
        context_id, local_x, local_y = await self._context_at_point(x, y)
        await self._evaluate_json_in(context_id, self._mouse_event_js(type_, local_x, local_y, modifiers, button))
        if type_ == "click":
            await self._evaluate_json_in(
                context_id, self._mouse_event_js("mouseup", local_x, local_y, modifiers, button)
            )

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

    @staticmethod
    def _insert_text_js(text: str) -> str:
        """Build the in-page expression that types `text` into the focused element.

        Writes through the prototype's own value setter rather than assigning the property: a
        framework that tracks its inputs (React and friends) patches the instance property and
        only notices a change made through the native setter, so a plain assignment leaves the
        field looking filled while the application still believes it is empty.
        """
        literal = json.dumps(text)
        return (
            "(function(text) {"
            "  const el = document.activeElement;"
            "  if (!el) { return false; }"
            "  if (el.isContentEditable) {"
            "    el.dispatchEvent(new InputEvent('beforeinput',"
            "        {bubbles: true, cancelable: true, inputType: 'insertText', data: text}));"
            "    document.execCommand('insertText', false, text);"
            "    return true;"
            "  }"
            "  const tag = el.tagName ? el.tagName.toLowerCase() : '';"
            "  if (tag !== 'input' && tag !== 'textarea') { return false; }"
            "  if (el.disabled || el.readOnly) { return false; }"
            "  const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;"
            "  const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');"
            "  const value = el.value || '';"
            "  const start = el.selectionStart === null || el.selectionStart === undefined"
            "      ? value.length : el.selectionStart;"
            "  const end = el.selectionEnd === null || el.selectionEnd === undefined"
            "      ? value.length : el.selectionEnd;"
            "  el.dispatchEvent(new InputEvent('beforeinput',"
            "      {bubbles: true, cancelable: true, inputType: 'insertText', data: text}));"
            "  const next = value.slice(0, start) + text + value.slice(end);"
            "  if (descriptor && descriptor.set) { descriptor.set.call(el, next); } else { el.value = next; }"
            "  try { el.setSelectionRange(start + text.length, start + text.length); } catch (e) {}"
            "  el.dispatchEvent(new InputEvent('input',"
            "      {bubbles: true, inputType: 'insertText', data: text}));"
            "  return true;"
            f"}})({literal})"
        )

    async def _input_insert_text(self, message: dict[str, Any]):
        """
        WebKit has no Input domain, and Input.insertText used to be swallowed by the blanket
        acknowledgement for it - so a client's fill()/insertText() reported success and left the
        field empty, which is worse than an error because a test believes the value went in.
        Type it into the focused element instead.
        """
        text = message.get("params", {}).get("text", "")
        if text:
            await self._type_text(text)
        await self._simple_response(message, None)

    async def _type_text(self, text: str) -> None:
        """Type into whichever document holds the focus (see _focused_context)."""
        await self._type_text_in(await self._focused_context(), text)

    async def _type_text_in(self, context_id: Optional[int], text: str) -> None:
        await self._evaluate_key_handler(context_id, self._insert_text_js(text))

    async def _evaluate_key_handler(self, context_id: Optional[int], expression: str) -> Optional[Any]:
        """_evaluate_json_in for the in-page key handlers, nudging the page when its reply is late.

        WebKit on iOS sometimes holds the reply to an evaluation that edits the focused field
        (a Backspace or a caret move) until the *next* message reaches the page: the handler
        itself has long finished - the page goes on to emit events - but its result only
        arrives right after whatever is sent next. Observed on iOS 26 with the very same
        expression answering instantly most of the time, so it is a wake-up problem on the
        device, not the script. Left alone, the wait ran out, the target was declared
        unresponsive and every following key was skipped. Nudging the page as
        soon as the reply is late frees it within milliseconds (see _nudge_target); nobody waits for the nudge's
        own reply, and a reply to an internal id nobody waits for is dropped on arrival.
        """
        pending = asyncio.ensure_future(self._evaluate_json_in(context_id, expression))
        done, _ = await asyncio.wait({pending}, timeout=KEY_HANDLER_WAKE_DELAY)
        if not done:
            await self._nudge_target()
        return await pending

    async def _nudge_target(self) -> None:
        """Send the page a message that runs no JavaScript, to flush a reply WebKit is withholding.

        Any message reaching the page frees a withheld reply (measured: a step held with its
        paused event was freed by this in ~10 ms, exactly as by a throwaway evaluation). The
        message must not run script, because an evaluation is itself a statement: with the Pause
        button armed, an evaluation used as the nudge paused *inside its own "0"* and the user's
        code then ran unpaused. Re-send the breakpoints-active setting at its current value - a
        real Debugger command with nothing to execute and nothing to change.
        """
        active = self._setup_messages.get("Debugger.setBreakpointsActive", {}).get("active", True)
        await self._send_message_to_target(
            {"id": self.next_internal_id(), "method": "Debugger.setBreakpointsActive", "params": {"active": active}},
            record=False,
        )

    async def _wake_late_replies(self) -> None:
        """Free forwarded client replies that WebKit is withholding.

        iOS 26 WebKit sometimes holds the reply to a client request - and the events that follow
        it, such as the Debugger.paused after a step - until the next message reaches the page:
        the work has finished, but the result only arrives right after whatever is sent next.
        Left alone, a WebStorm/Chrome console evaluate hung until the user's next action, and a
        step-over in a large script stalled about half the time. Runs while any client reply is
        outstanding: each interval, if one has waited longer than the interval, send a single
        throwaway evaluation (one message flushes everything held; its own reply, to an internal
        id, is dropped on arrival). A prompt reply clears its id before the first interval, so a
        normal request is never nudged; a request outstanding past REPLY_WAKE_MAX_AGE (a script
        that never terminates) is dropped from tracking so nudging cannot go on forever.
        """
        while self._reply_wake_pending:
            await asyncio.sleep(REPLY_WAKE_TICK)
            now = asyncio.get_event_loop().time()
            for request_id, sent_at in list(self._reply_wake_pending.items()):
                if now - sent_at > REPLY_WAKE_MAX_AGE:
                    self._reply_wake_pending.pop(request_id, None)
            if any(now - sent_at >= REPLY_WAKE_INTERVAL for sent_at in self._reply_wake_pending.values()):
                await self._nudge_target()

    @staticmethod
    def _key_event_init(params: dict[str, Any]) -> str:
        """The JSON the in-page key handlers take: the key and its modifiers, decoded from CDP's
        modifier bitmask (1 Alt, 2 Ctrl, 4 Meta, 8 Shift)."""
        modifiers = params.get("modifiers") or 0
        return json.dumps({
            "key": params.get("key", ""),
            "code": params.get("code", ""),
            "alt": bool(modifiers & 1),
            "ctrl": bool(modifiers & 2),
            "meta": bool(modifiers & 4),
            "shift": bool(modifiers & 8),
            "repeat": bool(params.get("autoRepeat", False)),
            "keyCode": params.get("windowsVirtualKeyCode") or 0,
        })

    @staticmethod
    def _printable_key_text(params: dict[str, Any]) -> Optional[str]:
        """The character a key event types, or None if it types nothing.

        A key that performs an action rather than producing text (Enter, Tab, the arrows) either
        carries no text or carries a control character, and is handled by the branches below.
        """
        text = params.get("text")
        if not isinstance(text, str) or len(text) != 1 or text < " " or text == "\x7f":
            return None
        return text

    async def _input_dispatch_key_event(self, message: dict[str, Any]):
        params = message["params"]
        key = params["key"]
        type_ = params["type"]
        if key != "Enter":
            await self._editing_key_event(message)
            return
        if type_ == "char":
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
            await self.evaluate_and_result(self._when_editable_js(manipulation))
        await self._simple_response(message, None)

    async def _editing_key_event(self, message: dict[str, Any]) -> None:
        """Every key but Enter, which has its own flow above.

        Each keyDown - including the auto-repeats of a held key - is dispatched to the page as a
        keydown event first, so the page's own shortcut handlers run and can prevent the default
        exactly as they would in a browser; when they do not, the bridge performs it in-page,
        because WebKit has no Input domain: select-all, caret movement (Shift extending the
        selection), Backspace and Delete (see KEY_DOWN_JS). Backspace used to act on keyUp, so a
        held Backspace deleted one character.

        Typing arrives in two shapes. DevTools sends keyDown, then a "char" event carrying the
        character, then keyUp; Playwright never sends "char" at all and puts the character in
        keyDown's own text field, which used to type nothing at all - silently, so a filled-in
        form stayed empty with every call reporting success. Take the character from whichever
        event carries it, and type it exactly once: remember what a keyDown promised, let a
        "char" supersede it, and fall back to typing it on keyUp when no "char" follows.
        """
        params = message["params"]
        type_ = params["type"]
        if type_ in ("keyDown", "rawKeyDown"):
            # The focused document is looked up once per key; its "char" and keyUp reuse it.
            self._key_context = await self._focused_context()
            outcome = await self._evaluate_key_handler(
                self._key_context, f"{KEY_DOWN_JS}({self._key_event_init(params)})"
            )
            self._key_default_prevented = outcome == "prevented"
            self._pending_key_text = None if self._key_default_prevented else self._printable_key_text(params)
        elif type_ == "char":
            self._pending_key_text = None
            text = self._printable_key_text(params)
            if text is not None and not self._key_default_prevented:
                await self._type_text_in(self._key_context, text)
        elif type_ == "keyUp":
            pending, self._pending_key_text = self._pending_key_text, None
            if pending is not None:
                await self._type_text_in(self._key_context, pending)
            self._key_default_prevented = False
            await self._evaluate_key_handler(self._key_context, f"{KEY_UP_JS}({self._key_event_init(params)})")
        await self._simple_response(message, None)

    @staticmethod
    def _when_editable_js(manipulation: str) -> str:
        """`manipulation`, run only when the focused element takes keyboard editing."""
        return (
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

    async def _target_created(self, message: dict[str, Any]):
        # These handlers run inside the receive loop; a device round-trip here (the old code
        # evaluated document.title/location.href) blocks delivery of every other event for the
        # whole session, and while a freshly navigated page is still loading it blocks until the
        # timeout. Rapid link navigation stacks those blocks until the session never catches up.
        # So emit a non-blocking, schema-complete targetInfo (a partial one crashes the frontend
        # SDK); the real url arrives via the device's own Page.frameNavigated.
        target_info = message["params"]["targetInfo"]
        new_target_id = target_info["targetId"]
        if target_info.get("type", PAGE_TARGET_TYPE) != PAGE_TARGET_TYPE:
            # Not every announced target is a page: iOS 26 announces one "frame" target per
            # subframe (and workers as "worker"/"service-worker"). Their backends implement a
            # much smaller domain set - a site-isolated frame has no Page/Network/Audit, and with
            # site isolation off it registers no agents at all - so a session that routed its
            # commands to one answered everything with "'<domain>' domain was not found" and
            # never recovered: no commit or destroy follows to move it back off. Chrome has no
            # counterpart for them either.
            logger.debug(f"ignoring {target_info.get('type')} target {new_target_id}")
            return
        self._page_targets.add(new_target_id)
        if not target_info.get("isProvisional", False):
            # A provisional target becomes current only on didCommitProvisionalTarget; routing
            # commands to it earlier loses them if the load never commits.
            self.target_id = new_target_id
        # New targets start with all agents disabled; without replaying the frontend's setup no
        # Network/Page/Console/Debugger event ever arrives again after a process swap and the
        # session appears dead after a couple of link clicks.
        await self._send_setup_to_target(new_target_id)
        if target_info.get("isPaused", False):
            # Held by Target.setPauseOnStart (see hold_new_targets) - its setup is in place now,
            # so let its load commit; in pause mode, stopped on its first statement.
            if self.pause_on_start:
                await self._pause_target(new_target_id)
            await self.protocol.send_command("Target.resume", targetId=new_target_id)
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
        if destroyed_target_id not in self._page_targets:
            # A target the session deliberately never adopted (see _target_created). Telling the
            # frontend the document changed because a subframe or a worker went away would reset
            # its panels for something it never knew about.
            return
        self._page_targets.discard(destroyed_target_id)
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
        timestamp = datetime.now().timestamp()
        await self.output_queue.put({
            "method": "Page.loadEventFired",
            # MonotonicTime, in seconds - not a formatted string
            "params": {"timestamp": timestamp},
        })
        # A client waiting on the modern lifecycle events must not be left hanging by a load that
        # only ever produced the legacy one (see _page_set_lifecycle_events_enabled).
        await self._emit_lifecycle_event("load", timestamp)
        await self.output_queue.put({"method": "DOM.documentUpdated"})

    @staticmethod
    def _normalize_remote_object_subtypes(obj: Any) -> None:
        """
        Fill in the RemoteObject.subtype Chrome sets and WebKit omits, in place and recursively.

        WebKit describes a promise as `{type: "object", className: "Promise"}` with no subtype;
        Chrome adds `subtype: "promise"`, and a client uses it to tell an object that still has to
        be resolved from a plain one. Only the built-ins in REMOTE_OBJECT_SUBTYPES are mapped, and
        an object that already carries a subtype is left alone.
        """
        if isinstance(obj, dict):
            node = cast(dict[str, Any], obj)
            if node.get("type") == "object" and "subtype" not in node:
                subtype = REMOTE_OBJECT_SUBTYPES.get(cast(str, node.get("className") or ""))
                if subtype is not None:
                    node["subtype"] = subtype
            for value in node.values():
                CdpTarget._normalize_remote_object_subtypes(value)
        elif isinstance(obj, list):
            for value in cast(list[Any], obj):
                CdpTarget._normalize_remote_object_subtypes(value)

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
            self._normalize_remote_object_subtypes(message["result"])
        if "error" in message:
            # Expected protocol-level errors (e.g. element-only DOM queries on text nodes) are
            # already delivered to the frontend, which copes; don't shout about them here.
            logger.debug(f"Target error response: {message}")
            data = message["error"].get("data")
            if data is not None and not isinstance(data, str):
                # WebKit lists the underlying errors under `data`; Chrome's protocol types it as
                # a string, and WebStorm's reader gives up on the whole response otherwise
                # ("Expected a string but was BEGIN_ARRAY") - one per domain a JSContext lacks.
                entries = cast(list[Any], data) if isinstance(data, list) else []
                details = [
                    str(cast(dict[str, Any], entry).get("message", "")) for entry in entries if isinstance(entry, dict)
                ]
                message["error"]["data"] = "; ".join(detail for detail in details if detail) or json.dumps(data)
            if "id" in message and str(message["error"].get("message", "")).endswith("domain already enabled"):
                # Enabled before the frontend asked - by the bridge holding the target, or by WebKit
                # itself when it paused a released context. Chrome's backend treats a repeated
                # enable as a no-op, and the frontend gives up on the domain over an error.
                message = {"id": message["id"], "result": {}}
        if "id" in message:
            self._pending_requests.pop(message["id"], None)
            self._reply_wake_pending.pop(message["id"], None)
            translator = self._reply_translators.pop(message["id"], None)
            if translator is not None:
                # A request forwarded without blocking; its translator answers the client itself.
                await translator(message)
                return
            if message["id"] < 0:
                # Response to a bridge-internal request (setup replay or an abandoned wait);
                # forwarding it would hand the frontend an id it never issued.
                return
            if message["id"] == self._replay_after_id:
                self._replay_after_id = None
                await self.output_queue.put(message)
                for event in self.held_events:
                    await self.output_queue.put(event)
                self.held_events.clear()
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
            # Forwarded-as-is events (Page.frame*, ...) still reference the top frame by WebKit's
            # id; rewrite it to the client's so every frame reference is consistent.
            self._map_frame_ids_outbound(message)
            await self.output_queue.put(message)

    async def _target_did_commit_provisional_target(self, message: dict[str, Any]):
        # The provisional target replaces the committed one only now; from here on route the
        # frontend's commands to it.
        self.target_id = message["params"]["newTargetId"]
        # Normally already done at targetCreated; covers a commit whose creation we never saw.
        # Only page targets are ever committed, so recording it here keeps _target_destroyed
        # recognizing it as one.
        self._page_targets.add(self.target_id)
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
        if not source and self._flat and script_id is not None:
            # A JSContext's own scripts carry no URL (nothing gave them a sourceURL). An editor
            # sets a breakpoint by URL, which cannot match an empty one, so the breakpoint never
            # binds. Give the script a stable synthetic URL so it is addressable, and translate
            # the URL breakpoint back to this script (see _debugger_set_breakpoint_by_url).
            source = f"jscontext:///{script_id}.js"
            params["url"] = source
            self._flat_script_url_to_id[source] = script_id
        if script_id is not None:
            self._script_id_to_url[script_id] = source
        await self.output_queue.put(message)
        if self._flat and script_id is not None:
            await self._bind_pending_url_breakpoints(str(script_id))

    async def _bind_pending_url_breakpoints(self, script_id: str) -> None:
        """Bind the URL breakpoints waiting for this JSContext script and announce each as resolved.

        Runs in the receive loop (scriptParsed is an event), so the binding request is forwarded
        with a reply translator rather than awaited here."""
        for breakpoint_id, request in list(self._flat_pending_url_breakpoints.items()):
            if self._flat_breakpoint_script(request) != script_id:
                continue
            location: dict[str, Any] = {"scriptId": script_id, "lineNumber": request.get("lineNumber", 0)}
            if "columnNumber" in request:
                location["columnNumber"] = request["columnNumber"]
            set_params: dict[str, Any] = {"location": location}
            if request.get("condition"):
                set_params["options"] = {"condition": request["condition"]}

            async def resolved(
                reply: dict[str, Any], breakpoint_id: str = breakpoint_id, location: dict[str, Any] = location
            ) -> None:
                result = reply.get("result", {})
                if "breakpointId" not in result:
                    logger.warning(f"URL breakpoint {breakpoint_id} did not bind: {reply.get('error')}")
                    return
                self._flat_bound_url_breakpoints.setdefault(breakpoint_id, []).append(result["breakpointId"])
                await self.output_queue.put({
                    "method": "Debugger.breakpointResolved",
                    "params": {"breakpointId": breakpoint_id, "location": result.get("actualLocation", location)},
                })

            await self._forward_and_translate(
                {"id": self.next_internal_id()}, {"method": "Debugger.setBreakpoint", "params": set_params}, resolved
            )

    async def _debugger_remove_breakpoint(self, message: dict[str, Any]) -> None:
        breakpoint_id = message.get("params", {}).get("breakpointId")
        if breakpoint_id in self._flat_pending_url_breakpoints or breakpoint_id in self._flat_bound_url_breakpoints:
            self._flat_pending_url_breakpoints.pop(breakpoint_id, None)
            for device_id in self._flat_bound_url_breakpoints.pop(breakpoint_id, []):
                await self._send_message_to_target({
                    "id": self.next_internal_id(),
                    "method": "Debugger.removeBreakpoint",
                    "params": {"breakpointId": device_id},
                })
            await self._result_response(message, {})
            return
        await self._send_message_to_target(message)

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

    @staticmethod
    def _is_real_call_frame(frame: dict[str, Any]) -> bool:
        """Whether a WebKit call frame denotes real source Chrome can locate.

        WebKit puts a native entry frame at the bottom of a stack - scriptId "0", lineNumber -1 -
        for the global/native code beneath the script. Chrome's protocol has no such frame (a
        Location must name a real script at a non-negative line), and js-debug and WebStorm build
        the stack strictly: the bad frame desynced their step handling, so after one step the
        session stopped advancing. V8 never emits it; verified against `node --inspect`, whose
        stacks carry only real script frames.
        """
        location: dict[str, Any] = frame.get("location") or {}
        script_id = location.get("scriptId")
        line_number: int = location.get("lineNumber", -1)
        return bool(script_id) and script_id != "0" and line_number >= 0

    async def _debugger_paused(self, message: dict[str, Any]):
        params = message["params"]
        params["reason"] = DEBUGGER_PAUSED_REASON.get(params["reason"], "other")
        if "breakpointId" in params.get("data", {}):
            params["hitBreakpoints"] = [params["data"]["breakpointId"]]
        # WebKit's CallFrame differs from Chrome's: it carries a bottom native frame Chrome never
        # has (see _is_real_call_frame), omits the required `url`, and uses scope-type enum values
        # Chrome rejects. Untranslated, Chrome's SDK throws while building the paused state and the
        # Sources panel never shows the pause. Drop the native frame and reshape the rest in place.
        frames = [frame for frame in params.get("callFrames", []) if self._is_real_call_frame(frame)]
        # Keep the top frame even if it somehow fails the test, so a pause is never frameless.
        params["callFrames"] = frames or params.get("callFrames", [])[:1]
        for frame in params["callFrames"]:
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
        for frame_id in list(self._frame_execution_ids):
            await self._destroy_frame_contexts(frame_id)
        self._emitted_context_unique_ids.clear()
        self._frame_execution_ids.clear()
        self._announced_worlds.clear()
        await self.output_queue.put({"method": "Runtime.executionContextsCleared"})
        await self.output_queue.put({"method": "DOM.documentUpdated"})

    @staticmethod
    def _is_binding_call(console_message: dict[str, Any]) -> bool:
        parameters: list[dict[str, Any]] = console_message.get("parameters") or []
        return (
            console_message.get("source") == "console-api"
            and len(parameters) == 4
            and parameters[0].get("value") == BINDING_MARKER
        )

    async def _binding_called(self, console_message: dict[str, Any]) -> None:
        """A call of a function installed by Runtime.addBinding (see _install_binding)."""
        parameters: list[dict[str, Any]] = console_message["parameters"]
        context_id = parameters[3].get("value")
        await self.output_queue.put({
            "method": "Runtime.bindingCalled",
            "params": {
                "name": str(parameters[1].get("value", "")),
                "payload": str(parameters[2].get("value", "")),
                "executionContextId": context_id if isinstance(context_id, int) else self._default_execution_id,
            },
        })

    def _error_script_url(self, script_id: Any, url: Any) -> str:
        """The URL of the script an error came from. WebKit stringifies a missing one as
        "undefined"; the script's announced URL (empty for an evaluation) is what Chrome reports."""
        if isinstance(script_id, str) and script_id in self._script_id_to_url:
            return self._script_id_to_url[script_id]
        return "" if not isinstance(url, str) or url == "undefined" else url

    async def _exception_thrown(self, console_message: dict[str, Any]) -> None:
        """Runtime.exceptionThrown from WebKit's error console message.

        WebKit numbers lines and columns from 1 in these messages (a throw on the third line of a
        script reports line 3); Chrome's ExceptionDetails and StackTrace count from 0. Chrome
        describes the exception through a RemoteObject whose description is the "Name: message"
        text, with `text` reduced to "Uncaught" (or "Uncaught (in promise)"); editors format the
        two together.
        """
        text = str(console_message.get("text", ""))
        summary = "Uncaught"
        if text.startswith(UNHANDLED_REJECTION_PREFIX):
            text = text[len(UNHANDLED_REJECTION_PREFIX) :]
            summary = "Uncaught (in promise)"
        class_name = text.split(":", 1)[0].strip() if ":" in text else "Error"
        frames: list[dict[str, Any]] = []
        stack: dict[str, Any] = console_message.get("stackTrace") or {}
        call_frames: list[dict[str, Any]] = stack.get("callFrames") or []
        for frame in call_frames:
            frames.append({
                "functionName": frame.get("functionName", ""),
                "scriptId": str(frame.get("scriptId", "")),
                "url": self._error_script_url(frame.get("scriptId"), frame.get("url")),
                "lineNumber": max(int(frame.get("lineNumber", 1)) - 1, 0),
                "columnNumber": max(int(frame.get("columnNumber", 1)) - 1, 0),
            })
        top = frames[0] if frames else {}
        details: dict[str, Any] = {
            "exceptionId": next(self._exception_ids),
            "text": summary,
            "lineNumber": top.get("lineNumber", max(int(console_message.get("line", 1)) - 1, 0)),
            "columnNumber": top.get("columnNumber", max(int(console_message.get("column", 1)) - 1, 0)),
            "url": top.get("url", self._error_script_url(None, console_message.get("url"))),
            "executionContextId": self._default_execution_id,
            "exception": {"type": "object", "subtype": "error", "className": class_name, "description": text},
        }
        if top.get("scriptId"):
            details["scriptId"] = top["scriptId"]
        if frames:
            details["stackTrace"] = {"callFrames": frames}
        await self.output_queue.put({
            "method": "Runtime.exceptionThrown",
            "params": {"timestamp": datetime.now().timestamp() * 1000, "exceptionDetails": details},
        })

    async def _inspector_inspect(self, message: dict[str, Any]) -> None:
        """The console's inspect(object): WebKit's Inspector.inspect is Chrome's Runtime.inspectRequested."""
        params = message.get("params", {})
        await self.output_queue.put({
            "method": "Runtime.inspectRequested",
            "params": {
                "object": params.get("object", {}),
                "hints": params.get("hints") or {},
                "executionContextId": self._default_execution_id,
            },
        })

    async def _emit_execution_context_destroyed(self, context_id: int, frame_id: Any) -> None:
        await self.output_queue.put({
            "method": "Runtime.executionContextDestroyed",
            "params": {"executionContextId": context_id, "executionContextUniqueId": f"{frame_id}.{context_id}"},
        })

    async def _destroy_frame_contexts(self, frame_id: str) -> None:
        """Announce the end of a frame's contexts - its main world and the isolated worlds
        synthesized for it - before the frame itself goes; Chrome does the same on navigation."""
        for context_id, world_frame in list(self._isolated_world_frames.items()):
            if world_frame == frame_id:
                await self._emit_execution_context_destroyed(context_id, frame_id)
                del self._isolated_world_frames[context_id]
                self._isolated_world_names.pop(context_id, None)
        main_context = self._frame_execution_ids.get(frame_id)
        if main_context is not None:
            await self._emit_execution_context_destroyed(main_context, frame_id)

    def _binding_install_script(self, name: str, context_id: int) -> str:
        return (
            f"globalThis[{json.dumps(name)}] = function (payload) {{ "
            f"console.debug({json.dumps(BINDING_MARKER)}, {json.dumps(name)}, String(payload), {context_id}); }};"
        )

    async def _install_binding(self, name: str, context_id: int) -> None:
        """Define the binding function in one execution context, without waiting for the reply."""
        params: dict[str, Any] = {"expression": self._tag_internal(self._binding_install_script(name, context_id))}
        real_context = self._real_context_id(context_id)
        if real_context is not None:
            params["contextId"] = real_context
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Runtime.evaluate",
            "params": params,
        })

    def _real_context_id(self, context_id: int) -> Optional[int]:
        """The device's context for one the client knows: a synthesized isolated world runs in the
        real main world of its frame; a JSContext has a single, unaddressed context."""
        if self._flat:
            return None
        if context_id in self._isolated_world_context_ids:
            world_frame = self._isolated_world_frames.get(context_id, self.frame_id)
            return self._frame_execution_ids.get(world_frame) or self._default_execution_id or None
        return context_id

    def _binding_contexts(self, world_name: Optional[str]) -> list[int]:
        """The client-visible contexts a binding scoped to `world_name` belongs in right now."""
        if world_name is None:
            if self._flat:
                return [JS_CONTEXT_EXECUTION_ID]
            return sorted(set(self._frame_execution_ids.values()))
        return sorted(cid for cid, name in self._isolated_world_names.items() if name == world_name)

    async def _install_bindings_for_context(self, context_id: int, world_name: Optional[str]) -> None:
        """A context was just announced: give it every binding registered for its kind."""
        for name, scope in self._bindings.items():
            if scope == world_name:
                await self._install_binding(name, context_id)

    async def _runtime_add_binding(self, message: dict[str, Any]) -> None:
        """
        Runtime.addBinding: expose `name` in the page as a function whose calls reach the client as
        Runtime.bindingCalled. Chrome's semantics: no context given = every main world, now and
        after reloads; executionContextName = every isolated world of that name, now and later;
        executionContextId = that one context only. Playwright's exposeFunction/exposeBinding and
        its init-script plumbing are built on this.
        """
        params = message.get("params", {})
        name = str(params.get("name", ""))
        if not name:
            await self._error_response(message, {"code": -32602, "message": "Runtime.addBinding needs a name"})
            return
        if isinstance(params.get("executionContextId"), int):
            await self._install_binding(name, params["executionContextId"])
        else:
            world_name = params.get("executionContextName")
            scope = world_name if isinstance(world_name, str) and world_name else None
            self._bindings[name] = scope
            for context_id in self._binding_contexts(scope):
                await self._install_binding(name, context_id)
        await self._result_response(message, {})

    async def _runtime_remove_binding(self, message: dict[str, Any]) -> None:
        name = str(message.get("params", {}).get("name", ""))
        scope = self._bindings.pop(name, None)
        contexts = self._binding_contexts(scope) if name else []
        if scope is None:
            contexts = sorted(set(contexts) | set(self._isolated_world_names))
        for context_id in contexts:
            params: dict[str, Any] = {"expression": self._tag_internal(f"delete globalThis[{json.dumps(name)}];")}
            real_context = self._real_context_id(context_id)
            if real_context is not None:
                params["contextId"] = real_context
            await self._send_message_to_target({
                "id": self.next_internal_id(),
                "method": "Runtime.evaluate",
                "params": params,
            })
        await self._result_response(message, {})

    async def _runtime_execution_context_created(self, message: dict[str, Any]):
        context = message["params"]["context"]
        # WebKit announces a context per isolated world (and per inspector evaluation batch);
        # forwarding them all with a shared uniqueId makes Chrome's RuntimeModel treat each as
        # a replacement of the selected console context, and pending evaluations lose their
        # results depending on timing. Only the main-world context is forwarded.
        if context["type"] != "normal":
            return
        # The main-world context is the top frame's; learn WebKit's id for it and report the id the
        # client attached with (see self.frame_id).
        self._learn_webkit_frame_id(context["frameId"])
        frame_id = self._to_client_frame_id(context["frameId"])
        unique_id = f"{frame_id}.{context['id']}"
        if unique_id in self._emitted_context_unique_ids:
            # WebKit re-announces the same context; a duplicate executionContextCreated corrupts
            # Chrome's RuntimeModel (it keys contexts by uniqueId), so emit each at most once.
            return
        self._emitted_context_unique_ids.add(unique_id)
        self._frame_execution_ids[frame_id] = context["id"]
        if frame_id == self.frame_id:
            # Only the top frame's context is the page's default. A subframe announces its own,
            # and letting that overwrite the default silently moved every evaluation addressed to
            # "the page" into the last frame that happened to load - an ad or payment iframe.
            self._default_execution_id = context["id"]
        await self._announce_registered_worlds(frame_id)
        message["params"] = {
            "context": {
                "id": context["id"],
                "origin": "default",
                "name": "",
                # must be unique per context - Chrome keys contexts by it
                "uniqueId": unique_id,
                # Chrome carries the frame association in auxData; WebKit reports the frame id at
                # the top level and omits auxData entirely. A CDP client (Playwright's crPage, and
                # DevTools' RuntimeModel) finds the context's frame through auxData.frameId and
                # recognizes the page's main world through auxData.isDefault, so without this the
                # context is never registered and every evaluate against the page hangs.
                "auxData": {"isDefault": True, "type": "default", "frameId": frame_id},
            }
        }
        await self.output_queue.put(message)
        await self._install_bindings_for_context(context["id"], None)

    async def _announce_registered_worlds(self, frame_id: str) -> None:
        """Give a freshly loaded document the isolated worlds the client registered by name."""
        for world_name in self._auto_world_names:
            if (frame_id, world_name) in self._announced_worlds:
                continue
            await self._announce_isolated_world(frame_id, world_name)

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
        if self._is_binding_call(console_message):
            await self._binding_called(console_message)
            return
        if console_message["source"] == JAVASCRIPT_ERROR_SOURCE and console_message.get("level") == "error":
            await self._exception_thrown(console_message)
            return
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
            message["params"]["frameId"] = self._to_client_frame_id(params["frameId"])
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

    # --- Fetch domain (Chrome) over Network interception (WebKit) --------------------------------

    @staticmethod
    def _fetch_headers_to_object(headers: Any) -> dict[str, str]:
        """Chrome carries headers as a [{name, value}] list; WebKit's intercept* want an object."""
        result: dict[str, str] = {}
        if isinstance(headers, list):
            for entry in cast(list[Any], headers):
                if isinstance(entry, dict):
                    name = cast(dict[str, Any], entry).get("name")
                    value = cast(dict[str, Any], entry).get("value")
                    if isinstance(name, str):
                        result[name] = "" if value is None else str(value)
        elif isinstance(headers, dict):
            for name, value in cast(dict[str, Any], headers).items():
                result[str(name)] = "" if value is None else str(value)
        return result

    @staticmethod
    def _fetch_pattern_to_regex(url_pattern: str) -> str:
        """Chrome's Fetch urlPattern is a glob (``*`` any run, ``?`` any char); WebKit takes a regex."""
        escaped = re.escape(url_pattern)
        return "^" + escaped.replace("\\*", ".*").replace("\\?", ".") + "$"

    async def _fetch_enable(self, message: dict[str, Any]) -> None:
        params = message.get("params", {})
        patterns = params.get("patterns") or [{"urlPattern": "*"}]
        self._fetch_handle_auth = bool(params.get("handleAuthRequests", False))
        for pattern in patterns:
            if not isinstance(pattern, dict):
                continue
            spec = cast(dict[str, Any], pattern)
            url = self._fetch_pattern_to_regex(cast(str, spec.get("urlPattern") or "*"))
            stage = "response" if str(spec.get("requestStage", "Request")).lower() == "response" else "request"
            await self._send_message_to_target({
                "id": self.next_internal_id(),
                "method": "Network.addInterception",
                "params": {"url": url, "stage": stage, "isRegex": True},
            })
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Network.setInterceptionEnabled",
            "params": {"enabled": True},
        })
        self._fetch_enabled = True
        await self._result_response(message, {})

    async def _fetch_disable(self, message: dict[str, Any]) -> None:
        self._fetch_enabled = False
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Network.setInterceptionEnabled",
            "params": {"enabled": False},
        })
        await self._result_response(message, {})

    async def _fetch_continue_request(self, message: dict[str, Any]) -> None:
        params = message.get("params", {})
        request_id = params.get("requestId")
        overrides: dict[str, Any] = {"requestId": request_id}
        changed = False
        for key in ("url", "method"):
            if params.get(key) is not None:
                overrides[key] = params[key]
                changed = True
        if params.get("postData") is not None:
            overrides["postData"] = params["postData"]
            changed = True
        if params.get("headers") is not None:
            overrides["headers"] = self._fetch_headers_to_object(params["headers"])
            changed = True
        if changed:
            await self._send_message_to_target({
                "id": self.next_internal_id(),
                "method": "Network.interceptWithRequest",
                "params": overrides,
            })
        else:
            await self._send_message_to_target({
                "id": self.next_internal_id(),
                "method": "Network.interceptContinue",
                "params": {"requestId": request_id, "stage": "request"},
            })
        await self._result_response(message, {})

    async def _fetch_continue_response(self, message: dict[str, Any]) -> None:
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Network.interceptContinue",
            "params": {"requestId": message.get("params", {}).get("requestId"), "stage": "response"},
        })
        await self._result_response(message, {})

    async def _fetch_continue_with_auth(self, message: dict[str, Any]) -> None:
        # WebKit surfaces no auth-challenge event of its own (the on-device dialog owns it), so this
        # reactive path is a best effort: with credentials, inject an Authorization header and let
        # the request go; otherwise just continue it. The reliable way to answer Basic auth here is
        # proactive - continueRequest with an Authorization header on the matching request.
        params = message.get("params", {})
        request_id = params.get("requestId")
        challenge = cast(dict[str, Any], params.get("authChallengeResponse") or {})
        if challenge.get("response") == "ProvideCredentials":
            token = base64.b64encode(
                f"{challenge.get('username', '')}:{challenge.get('password', '')}".encode()
            ).decode()
            await self._send_message_to_target({
                "id": self.next_internal_id(),
                "method": "Network.interceptWithRequest",
                "params": {"requestId": request_id, "headers": {"Authorization": f"Basic {token}"}},
            })
        else:
            await self._send_message_to_target({
                "id": self.next_internal_id(),
                "method": "Network.interceptContinue",
                "params": {"requestId": request_id, "stage": "request"},
            })
        await self._result_response(message, {})

    async def _fetch_fulfill_request(self, message: dict[str, Any]) -> None:
        params = message.get("params", {})
        headers = self._fetch_headers_to_object(params.get("responseHeaders"))
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Network.interceptRequestWithResponse",
            "params": {
                "requestId": params.get("requestId"),
                "content": params.get("body", ""),
                "base64Encoded": True,
                "mimeType": headers.get("Content-Type") or headers.get("content-type") or "text/plain",
                "status": params.get("responseCode", 200),
                "statusText": params.get("responsePhrase", ""),
                "headers": headers,
            },
        })
        await self._result_response(message, {})

    async def _fetch_fail_request(self, message: dict[str, Any]) -> None:
        await self._send_message_to_target({
            "id": self.next_internal_id(),
            "method": "Network.interceptRequestWithError",
            "params": {"requestId": message.get("params", {}).get("requestId"), "errorType": "General"},
        })
        await self._result_response(message, {})

    async def _network_request_will_be_sent(self, message: dict[str, Any]) -> None:
        # Cache what Network.requestIntercepted omits but Fetch.requestPaused needs, then forward
        # the event as the raw path would have. Bound the cache so a long-lived page cannot grow it.
        params = message["params"]
        request_id = params.get("requestId")
        if isinstance(request_id, str):
            if len(self._request_meta) > 512:
                self._request_meta.clear()
            self._request_meta[request_id] = {
                "frameId": self._to_client_frame_id(params.get("frameId")),
                "type": params.get("type"),
            }
        self._map_frame_ids_outbound(message)
        await self.output_queue.put(message)

    async def _network_request_intercepted(self, message: dict[str, Any]) -> None:
        params = message["params"]
        if not self._fetch_enabled:
            # A client driving WebKit's Network interception directly; leave its event untouched.
            await self.output_queue.put(message)
            return
        request_id = params.get("requestId")
        meta = self._request_meta.get(request_id, {}) if isinstance(request_id, str) else {}
        resource_type = meta.get("type")
        await self.output_queue.put({
            "method": "Fetch.requestPaused",
            "params": {
                "requestId": request_id,
                "request": params.get("request", {}),
                "frameId": meta.get("frameId") or self.frame_id,
                "resourceType": resource_type if resource_type in NETWORK_RESOURCE_TYPES else "Other",
                "networkId": request_id,
            },
        })

    async def _network_response_intercepted(self, message: dict[str, Any]) -> None:
        params = message["params"]
        if not self._fetch_enabled:
            await self.output_queue.put(message)
            return
        request_id = params.get("requestId")
        response = params.get("response", {})
        meta = self._request_meta.get(request_id, {}) if isinstance(request_id, str) else {}
        resource_type = meta.get("type")
        headers = response.get("headers", {})
        await self.output_queue.put({
            "method": "Fetch.requestPaused",
            "params": {
                "requestId": request_id,
                "request": {"url": response.get("url", ""), "method": "GET", "headers": {}},
                "frameId": meta.get("frameId") or self.frame_id,
                "resourceType": resource_type if resource_type in NETWORK_RESOURCE_TYPES else "Other",
                "networkId": request_id,
                "responseStatusCode": response.get("status"),
                "responseStatusText": response.get("statusText", ""),
                "responseHeaders": [{"name": str(k), "value": str(v)} for k, v in headers.items()],
            },
        })
