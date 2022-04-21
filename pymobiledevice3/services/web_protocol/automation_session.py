from dataclasses import dataclass
import json
from enum import Enum
from pathlib import Path

RESOURCES = Path(__file__).parent.parent.parent / 'resources' / 'webinspector'
FIND_NODES = (RESOURCES / 'find_nodes.js').read_text()


class By(Enum):
    """
    Set of supported locator strategies.
    """
    ID = 'id'
    XPATH = 'xpath'
    LINK_TEXT = 'link text'
    PARTIAL_LINK_TEXT = 'partial link text'
    NAME = 'name'
    TAG_NAME = 'tag name'
    CLASS_NAME = 'class name'
    CSS_SELECTOR = 'css selector'


class MouseButton(Enum):
    NONE = 'None'
    LEFT = 'Left'
    MIDDLE = 'Middle'
    RIGHT = 'Right'


class MouseInteraction(Enum):
    MOVE = 'Move'
    DOWN = 'Down'
    UP = 'Up'
    SINGLE_CLICK = 'SingleClick'
    DOUBLE_CLICK = 'DoubleClick'


class KeyboardInteractionType(Enum):
    KEY_PRESS = 'KeyPress'
    KEY_RELEASE = 'KeyRelease'
    INSERT_BY_KEY = 'InsertByKey'


class KeyModifier(Enum):
    CAPS_LOCK = 'CapsLock'
    CONTROL = 'Control'
    SHIFT = 'Shift'
    META = 'Meta'
    ALT = 'Alt'


VIRTUAL_KEYS = {
    '\ue001': ('Cancel', None),
    '\ue002': ('Help', None),
    '\ue003': ('Backspace', None),
    '\ue004': ('Tab', None),
    '\ue005': ('Clear', None),
    '\ue006': ('Return', None),
    '\ue007': ('Enter', None),
    '\ue008': ('Shift', KeyModifier.SHIFT),
    '\ue050': ('Shift', KeyModifier.SHIFT),
    '\ue009': ('Control', KeyModifier.CONTROL),
    '\ue051': ('Control', KeyModifier.CONTROL),
    '\ue00a': ('Alternate', KeyModifier.ALT),
    '\ue052': ('Alternate', KeyModifier.ALT),
    '\ue00b': ('Pause', None),
    '\ue00c': ('Escape', None),
    '\ue00d': ('Space', None),
    '\ue00e': ('PageUp', None),
    '\ue054': ('PageUp', None),
    '\ue00f': ('PageDown', None),
    '\ue055': ('PageDown', None),
    '\ue010': ('End', None),
    '\ue056': ('End', None),
    '\ue011': ('Home', None),
    '\ue057': ('Home', None),
    '\ue012': ('LeftArrow', None),
    '\ue058': ('LeftArrow', None),
    '\ue013': ('UpArrow', None),
    '\ue059': ('UpArrow', None),
    '\ue014': ('RightArrow', None),
    '\ue05a': ('RightArrow', None),
    '\ue015': ('DownArrow', None),
    '\ue05b': ('DownArrow', None),
    '\ue016': ('Insert', None),
    '\ue05c': ('Insert', None),
    '\ue017': ('Delete', None),
    '\ue05d': ('Delete', None),
    '\ue018': ('Semicolon', None),
    '\ue019': ('Equals', None),
    '\ue01a': ('NumberPad0', None),
    '\ue01b': ('NumberPad1', None),
    '\ue01c': ('NumberPad2', None),
    '\ue01d': ('NumberPad3', None),
    '\ue01e': ('NumberPad4', None),
    '\ue01f': ('NumberPad5', None),
    '\ue020': ('NumberPad6', None),
    '\ue021': ('NumberPad7', None),
    '\ue022': ('NumberPad8', None),
    '\ue023': ('NumberPad9', None),
    '\ue024': ('NumberPadMultiply', None),
    '\ue025': ('NumberPadAdd', None),
    '\ue026': ('NumberPadSeparator', None),
    '\ue027': ('NumberPadSubtract', None),
    '\ue028': ('NumberPadDecimal', None),
    '\ue029': ('NumberPadDivide', None),
    '\ue031': ('Function1', None),
    '\ue032': ('Function2', None),
    '\ue033': ('Function3', None),
    '\ue034': ('Function4', None),
    '\ue035': ('Function5', None),
    '\ue036': ('Function6', None),
    '\ue037': ('Function7', None),
    '\ue038': ('Function8', None),
    '\ue039': ('Function9', None),
    '\ue03a': ('Function10', None),
    '\ue03b': ('Function11', None),
    '\ue03c': ('Function12', None),
    '\ue03d': ('Meta', KeyModifier.META),
    '\ue053': ('Meta', KeyModifier.META),
}

MODIFIER_TO_KEY = {
    KeyModifier.SHIFT: 'Shift',
    KeyModifier.CONTROL: 'Control',
    KeyModifier.ALT: 'Alternate',
    KeyModifier.META: 'Meta',
}


@dataclass
class Point:
    x: int
    y: int


@dataclass
class Size:
    width: int
    height: int


@dataclass
class Rect:
    x: int
    y: int
    width: int
    height: int


class AutomationSession:
    def __init__(self, protocol):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        self.protocol = protocol
        self.top_level_handle = ''
        self.current_handle = ''
        self.current_parent_handle = ''
        self.implicit_wait_timeout = 0
        self.page_load_timeout = 3000000
        self.script_timeout = -1

    @property
    def id_(self):
        return self.protocol.id_

    def start_session(self):
        handle = self.protocol.createBrowsingContext()['handle']
        self.switch_to_top_level_browsing_context(handle)

    def stop_session(self):
        self.top_level_handle = ''
        self.current_handle = ''
        self.current_parent_handle = ''
        for handle in self.get_window_handles():
            self.protocol.closeBrowsingContext(handle=handle)

    def create_window(self, type_):
        type_ = type_.capitalize()
        params = {'presentationHint': type_} if type_ else {}
        return self.protocol.createBrowsingContext(**params)['handle']

    def close_window(self):
        if not self.top_level_handle:
            return
        handle = self.top_level_handle
        self.protocol.closeBrowsingContext(handle=handle)

    def maximize_window(self):
        self.protocol.maximizeWindowOfBrowsingContext(handle=self.top_level_handle)

    def hide_window(self):
        self.protocol.hideWindowOfBrowsingContext(handle=self.top_level_handle)

    def get_browsing_context(self):
        return self.protocol.getBrowsingContext(handle=self.top_level_handle)['context']

    def get_window_handles(self):
        contexts = self.protocol.getBrowsingContexts()
        return [c['handle'] for c in contexts['contexts']]

    def set_window_frame(self, x=None, y=None, width=None, height=None):
        params = {}
        if x is not None and y is not None:
            params['origin'] = {'x': x, 'y': y}
        if width is not None and height is not None:
            params['size'] = {'width': width, 'height': height}
        self.protocol.setWindowFrameOfBrowsingContext(handle=self.top_level_handle, **params)

    def add_single_cookie(self, cookie):
        self.protocol.addSingleCookie(browsingContextHandle=self.top_level_handle, cookie=cookie)

    def delete_all_cookies(self):
        self.protocol.deleteAllCookies(browsingContextHandle=self.top_level_handle)

    def delete_single_cookie(self, name):
        self.protocol.deleteSingleCookie(browsingContextHandle=self.top_level_handle, cookieName=name)

    def get_all_cookies(self):
        return self.protocol.getAllCookies(browsingContextHandle=self.top_level_handle)['cookies']

    def execute_script(self, script, args, async_=False):
        parameters = {
            'browsingContextHandle': self.top_level_handle,
            'function': 'function(){\n' + script + '\n}',
            'arguments': list(map(json.dumps, args)),
        }
        if self.current_handle:
            parameters['frameHandle'] = self.current_handle
        if async_:
            parameters['expectsImplicitCallbackArgument'] = True
        if self.script_timeout != -1:
            parameters['callbackTimeout'] = self.script_timeout
        result = self.protocol.evaluateJavaScriptFunction(**parameters, wait_for_response=not async_)
        if async_:
            return result
        else:
            return json.loads(result['result'])

    def evaluate_js_function(self, function, *args, implicit_callback=False, include_frame=True):
        params = {
            'browsingContextHandle': self.top_level_handle,
            'function': function,
            'arguments': list(map(json.dumps, args)),
        }
        if include_frame and self.current_handle:
            params['frameHandle'] = self.current_handle
        if implicit_callback:
            params['expectsImplicitCallbackArgument'] = True
        result = self.protocol.evaluateJavaScriptFunction(**params)
        return json.loads(result['result'])

    def find_elements(self, by, value, single: bool = True, root=None):
        self.wait_for_navigation_to_complete()
        by = by.value if isinstance(by, By) else by
        if by == By.ID.value:
            by = By.CSS_SELECTOR.value
            value = '[id="%s"]' % value
        elif by == By.TAG_NAME.value:
            by = By.CSS_SELECTOR.value
        elif by == By.CLASS_NAME.value:
            by = By.CSS_SELECTOR.value
            value = ".%s" % value
        elif by == By.NAME.value:
            by = By.CSS_SELECTOR.value
            value = '[name="%s"]' % value

        parameters = {
            'browsingContextHandle': self.top_level_handle,
            'function': FIND_NODES,
            'arguments': list(map(json.dumps, [by, root, value, single, self.implicit_wait_timeout])),
            'expectsImplicitCallbackArgument': True,
        }
        if self.current_handle:
            parameters['frameHandle'] = self.current_handle
        if self.implicit_wait_timeout:
            parameters['callbackTimeout'] = self.implicit_wait_timeout + 1000
        result = json.loads(self.protocol.evaluateJavaScriptFunction(**parameters)['result'])
        return result

    def screenshot_as_base64(self, scroll=False, node_id='', clip=True):
        params = {'handle': self.top_level_handle, 'clipToViewport': clip}
        if self.current_handle:
            params['frameHandle'] = self.current_handle
        if scroll:
            params['scrollIntoViewIfNeeded'] = True
        if node_id:
            params['nodeHandle'] = node_id
        return self.protocol.takeScreenshot(**params)['data']

    def switch_to_top_level_browsing_context(self, top_level_handle):
        self.top_level_handle = top_level_handle
        self.current_handle = ''
        self.current_parent_handle = ''

    def switch_to_browsing_context(self, handle):
        self.current_handle = handle
        if not self.current_handle:
            self.current_parent_handle = ''
            return

        resp = self.protocol.resolveParentFrameHandle(browsingContextHandle=self.top_level_handle,
                                                      frameHandle=self.current_handle)
        self.current_parent_handle = resp['result']

    def switch_to_browsing_context_frame(self, context, frame):
        self.protocol.switchToBrowsingContext(browsingContextHandle=context, frameHandle=frame)

    def navigate_broswing_context(self, url):
        self.protocol.navigateBrowsingContext(
            handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout, url=url
        )

    def go_back_in_browsing_context(self):
        self.protocol.goBackInBrowsingContext(
            handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout
        )

    def go_forward_in_browsing_context(self):
        self.protocol.goForwardInBrowsingContext(
            handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout
        )

    def reload_browsing_context(self):
        self.protocol.reloadBrowsingContext(
            handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout
        )

    def switch_to_frame(self, frame_ordinal=None, frame_handle=None):
        params = {'browsingContextHandle': self.top_level_handle}
        if self.current_handle:
            params['frameHandle'] = self.current_handle
        if frame_ordinal is not None:
            params['ordinal'] = frame_ordinal
        elif frame_handle is not None:
            params['nodeHandle'] = frame_handle.node_id
        resp = self.protocol.resolveChildFrameHandle(**params)['result']
        self.switch_to_browsing_context_frame(self.top_level_handle, resp)
        self.switch_to_browsing_context(resp)

    def switch_to_window(self, handle):
        self.switch_to_browsing_context_frame(handle, '')
        self.switch_to_top_level_browsing_context(handle)

    def perform_keyboard_interactions(self, interactions):
        for interaction in interactions:
            type_ = interaction['type']
            interaction['type'] = type_.value if isinstance(type_, KeyboardInteractionType) else type_
        self.protocol.performKeyboardInteractions(handle=self.top_level_handle, interactions=interactions)

    def perform_mouse_interaction(self, x, y, button: MouseButton, interaction: MouseInteraction, modifiers=None):
        modifiers = [] if modifiers is None else modifiers
        self.protocol.performMouseInteraction(handle=self.top_level_handle, position={'x': x, 'y': y},
                                              button=button.value, interaction=interaction.value, modifiers=modifiers)

    def perform_interaction_sequence(self, sources, steps):
        params = {
            'handle': self.top_level_handle,
            'inputSources': sources,
            'steps': steps,
        }
        if self.current_handle:
            params['frameHandle'] = self.current_handle
        self.protocol.performInteractionSequence(**params)

    def wait_for_navigation_to_complete(self):
        params = {'browsingContextHandle': self.top_level_handle, 'pageLoadTimeout': self.page_load_timeout}
        if self.current_handle:
            params['frameHandle'] = self.current_handle
        self.protocol.waitForNavigationToComplete(**params)

    def accept_current_javascript_dialog(self):
        self.protocol.acceptCurrentJavaScriptDialog(browsingContextHandle=self.top_level_handle)

    def dismiss_current_javascript_dialog(self):
        self.protocol.dismissCurrentJavaScriptDialog(browsingContextHandle=self.top_level_handle)

    def set_user_input_for_current_javascript_prompt(self, user_input):
        self.protocol.setUserInputForCurrentJavaScriptPrompt(
            browsingContextHandle=self.top_level_handle, userInput=user_input
        )

    def message_of_current_javascript_dialog(self):
        return self.protocol.messageOfCurrentJavaScriptDialog(browsingContextHandle=self.top_level_handle)['message']

    def compute_element_layout(self, node_id, scroll_if_needed, coordinate_system):
        return self.protocol.computeElementLayout(
            browsingContextHandle=self.top_level_handle, nodeHandle=node_id,
            scrollIntoViewIfNeeded=scroll_if_needed, coordinateSystem=coordinate_system,
            frameHandle='' if self.current_handle is None else self.current_handle
        )

    def select_option_element(self, node_id):
        self.protocol.selectOptionElement(
            browsingContextHandle=self.top_level_handle, nodeHandle=node_id,
            frameHandle='' if self.current_handle is None else self.current_handle
        )
