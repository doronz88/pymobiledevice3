import importlib.resources
import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional, Union

import pymobiledevice3.resources

if TYPE_CHECKING:
    from pymobiledevice3.services.web_protocol.element import WebElement

RESOURCES = importlib.resources.files(pymobiledevice3.resources) / "webinspector"
FIND_NODES = (RESOURCES / "find_nodes.js").read_text()


class By(Enum):
    """
    Set of supported locator strategies.
    """

    ID = "id"
    XPATH = "xpath"
    LINK_TEXT = "link text"
    PARTIAL_LINK_TEXT = "partial link text"
    NAME = "name"
    TAG_NAME = "tag name"
    CLASS_NAME = "class name"
    CSS_SELECTOR = "css selector"


class MouseButton(Enum):
    NONE = "None"
    LEFT = "Left"
    MIDDLE = "Middle"
    RIGHT = "Right"


class MouseInteraction(Enum):
    MOVE = "Move"
    DOWN = "Down"
    UP = "Up"
    SINGLE_CLICK = "SingleClick"
    DOUBLE_CLICK = "DoubleClick"


class KeyboardInteractionType(Enum):
    KEY_PRESS = "KeyPress"
    KEY_RELEASE = "KeyRelease"
    INSERT_BY_KEY = "InsertByKey"


class KeyModifier(Enum):
    CAPS_LOCK = "CapsLock"
    CONTROL = "Control"
    SHIFT = "Shift"
    META = "Meta"
    ALT = "Alt"


VIRTUAL_KEYS: dict[str, tuple[str, Optional[KeyModifier]]] = {
    "\ue001": ("Cancel", None),
    "\ue002": ("Help", None),
    "\ue003": ("Backspace", None),
    "\ue004": ("Tab", None),
    "\ue005": ("Clear", None),
    "\ue006": ("Return", None),
    "\ue007": ("Enter", None),
    "\ue008": ("Shift", KeyModifier.SHIFT),
    "\ue050": ("Shift", KeyModifier.SHIFT),
    "\ue009": ("Control", KeyModifier.CONTROL),
    "\ue051": ("Control", KeyModifier.CONTROL),
    "\ue00a": ("Alternate", KeyModifier.ALT),
    "\ue052": ("Alternate", KeyModifier.ALT),
    "\ue00b": ("Pause", None),
    "\ue00c": ("Escape", None),
    "\ue00d": ("Space", None),
    "\ue00e": ("PageUp", None),
    "\ue054": ("PageUp", None),
    "\ue00f": ("PageDown", None),
    "\ue055": ("PageDown", None),
    "\ue010": ("End", None),
    "\ue056": ("End", None),
    "\ue011": ("Home", None),
    "\ue057": ("Home", None),
    "\ue012": ("LeftArrow", None),
    "\ue058": ("LeftArrow", None),
    "\ue013": ("UpArrow", None),
    "\ue059": ("UpArrow", None),
    "\ue014": ("RightArrow", None),
    "\ue05a": ("RightArrow", None),
    "\ue015": ("DownArrow", None),
    "\ue05b": ("DownArrow", None),
    "\ue016": ("Insert", None),
    "\ue05c": ("Insert", None),
    "\ue017": ("Delete", None),
    "\ue05d": ("Delete", None),
    "\ue018": ("Semicolon", None),
    "\ue019": ("Equals", None),
    "\ue01a": ("NumberPad0", None),
    "\ue01b": ("NumberPad1", None),
    "\ue01c": ("NumberPad2", None),
    "\ue01d": ("NumberPad3", None),
    "\ue01e": ("NumberPad4", None),
    "\ue01f": ("NumberPad5", None),
    "\ue020": ("NumberPad6", None),
    "\ue021": ("NumberPad7", None),
    "\ue022": ("NumberPad8", None),
    "\ue023": ("NumberPad9", None),
    "\ue024": ("NumberPadMultiply", None),
    "\ue025": ("NumberPadAdd", None),
    "\ue026": ("NumberPadSeparator", None),
    "\ue027": ("NumberPadSubtract", None),
    "\ue028": ("NumberPadDecimal", None),
    "\ue029": ("NumberPadDivide", None),
    "\ue031": ("Function1", None),
    "\ue032": ("Function2", None),
    "\ue033": ("Function3", None),
    "\ue034": ("Function4", None),
    "\ue035": ("Function5", None),
    "\ue036": ("Function6", None),
    "\ue037": ("Function7", None),
    "\ue038": ("Function8", None),
    "\ue039": ("Function9", None),
    "\ue03a": ("Function10", None),
    "\ue03b": ("Function11", None),
    "\ue03c": ("Function12", None),
    "\ue03d": ("Meta", KeyModifier.META),
    "\ue053": ("Meta", KeyModifier.META),
}

MODIFIER_TO_KEY = {
    KeyModifier.SHIFT: "Shift",
    KeyModifier.CONTROL: "Control",
    KeyModifier.ALT: "Alternate",
    KeyModifier.META: "Meta",
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
    def __init__(self, protocol: Any):
        """
        :param pymobiledevice3.services.web_protocol.session_protocol.SessionProtocol protocol: Session protocol.
        """
        self.protocol = protocol
        self.top_level_handle = ""
        self.current_handle = ""
        self.current_parent_handle = ""
        self.implicit_wait_timeout = 0
        self.page_load_timeout = 3000000
        self.script_timeout = -1

    def get_id(self):
        return self.protocol.id_

    async def start_session(self):
        handle = (await self.protocol.createBrowsingContext())["handle"]
        await self.switch_to_top_level_browsing_context(handle)

    async def stop_session(self):
        self.top_level_handle = ""
        self.current_handle = ""
        self.current_parent_handle = ""
        for handle in await self.get_window_handles():
            await self.protocol.closeBrowsingContext(handle=handle)

    async def create_window(self, type_: str):
        type_ = type_.capitalize()
        params = {"presentationHint": type_} if type_ else {}
        return (await self.protocol.createBrowsingContext(**params))["handle"]

    async def close_window(self):
        if not self.top_level_handle:
            return
        handle = self.top_level_handle
        await self.protocol.closeBrowsingContext(handle=handle)

    async def maximize_window(self):
        await self.protocol.maximizeWindowOfBrowsingContext(handle=self.top_level_handle)

    async def hide_window(self):
        await self.protocol.hideWindowOfBrowsingContext(handle=self.top_level_handle)

    async def get_browsing_context(self):
        return (await self.protocol.getBrowsingContext(handle=self.top_level_handle))["context"]

    async def get_window_handles(self):
        contexts = await self.protocol.getBrowsingContexts()
        return [c["handle"] for c in contexts["contexts"]]

    async def set_window_frame(
        self,
        x: Optional[int] = None,
        y: Optional[int] = None,
        width: Optional[int] = None,
        height: Optional[int] = None,
    ):
        params = {}
        if x is not None and y is not None:
            params["origin"] = {"x": x, "y": y}
        if width is not None and height is not None:
            params["size"] = {"width": width, "height": height}
        await self.protocol.setWindowFrameOfBrowsingContext(handle=self.top_level_handle, **params)

    async def add_single_cookie(self, cookie: dict[str, Any]):
        await self.protocol.addSingleCookie(browsingContextHandle=self.top_level_handle, cookie=cookie)

    async def delete_all_cookies(self):
        await self.protocol.deleteAllCookies(browsingContextHandle=self.top_level_handle)

    async def delete_single_cookie(self, name: str):
        await self.protocol.deleteSingleCookie(browsingContextHandle=self.top_level_handle, cookieName=name)

    async def get_all_cookies(self):
        return (await self.protocol.getAllCookies(browsingContextHandle=self.top_level_handle))["cookies"]

    async def execute_script(self, script: str, args: Iterable[Any], async_: bool = False):
        parameters: dict[str, Any] = {
            "browsingContextHandle": self.top_level_handle,
            "function": "function(){\n" + script + "\n}",
            "arguments": list(map(json.dumps, args)),
        }
        if self.current_handle:
            parameters["frameHandle"] = self.current_handle
        if async_:
            parameters["expectsImplicitCallbackArgument"] = True
        if self.script_timeout != -1:
            parameters["callbackTimeout"] = self.script_timeout
        result = await self.protocol.evaluateJavaScriptFunction(**parameters, wait_for_response=not async_)
        if async_:
            return result
        else:
            return json.loads(result["result"])

    async def evaluate_js_function(
        self, function: str, *args: Any, implicit_callback: bool = False, include_frame: bool = True
    ):
        params: dict[str, Any] = {
            "browsingContextHandle": self.top_level_handle,
            "function": function,
            "arguments": list(map(json.dumps, args)),
        }
        if include_frame and self.current_handle:
            params["frameHandle"] = self.current_handle
        if implicit_callback:
            params["expectsImplicitCallbackArgument"] = True
        result = await self.protocol.evaluateJavaScriptFunction(**params)
        return json.loads(result["result"])

    async def find_elements(
        self, by: Union[By, str], value: Optional[str], single: bool = True, root: Optional[str] = None
    ):
        await self.wait_for_navigation_to_complete()
        by = by.value if isinstance(by, By) else by
        if by == By.ID.value:
            by = By.CSS_SELECTOR.value
            value = f'[id="{value}"]'
        elif by == By.TAG_NAME.value:
            by = By.CSS_SELECTOR.value
        elif by == By.CLASS_NAME.value:
            by = By.CSS_SELECTOR.value
            value = f".{value}"
        elif by == By.NAME.value:
            by = By.CSS_SELECTOR.value
            value = f'[name="{value}"]'

        parameters: dict[str, Any] = {
            "browsingContextHandle": self.top_level_handle,
            "function": FIND_NODES,
            "arguments": list(map(json.dumps, [by, root, value, single, self.implicit_wait_timeout])),
            "expectsImplicitCallbackArgument": True,
        }
        if self.current_handle:
            parameters["frameHandle"] = self.current_handle
        if self.implicit_wait_timeout:
            parameters["callbackTimeout"] = self.implicit_wait_timeout + 1000
        result = json.loads((await self.protocol.evaluateJavaScriptFunction(**parameters))["result"])
        return result

    async def screenshot_as_base64(self, scroll: bool = False, node_id: str = "", clip: bool = True):
        params: dict[str, Any] = {"handle": self.top_level_handle, "clipToViewport": clip}
        if self.current_handle:
            params["frameHandle"] = self.current_handle
        if scroll:
            params["scrollIntoViewIfNeeded"] = True
        if node_id:
            params["nodeHandle"] = node_id
        return (await self.protocol.takeScreenshot(**params))["data"]

    async def switch_to_top_level_browsing_context(self, top_level_handle: str):
        self.top_level_handle = top_level_handle
        self.current_handle = ""
        self.current_parent_handle = ""

    async def switch_to_browsing_context(self, handle: Optional[str]):
        self.current_handle = handle
        if not self.current_handle:
            self.current_parent_handle = ""
            return

        resp = await self.protocol.resolveParentFrameHandle(
            browsingContextHandle=self.top_level_handle, frameHandle=self.current_handle
        )
        self.current_parent_handle = resp["result"]

    async def switch_to_browsing_context_frame(self, context: str, frame: str):
        await self.protocol.switchToBrowsingContext(browsingContextHandle=context, frameHandle=frame)

    async def navigate_broswing_context(self, url: str):
        await self.protocol.navigateBrowsingContext(
            handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout, url=url
        )

    async def go_back_in_browsing_context(self):
        await self.protocol.goBackInBrowsingContext(
            handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout
        )

    async def go_forward_in_browsing_context(self):
        await self.protocol.goForwardInBrowsingContext(
            handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout
        )

    async def reload_browsing_context(self):
        await self.protocol.reloadBrowsingContext(handle=self.top_level_handle, pageLoadTimeout=self.page_load_timeout)

    async def switch_to_frame(self, frame_ordinal: Any = None, frame_handle: Optional["WebElement"] = None):
        params = {"browsingContextHandle": self.top_level_handle}
        if self.current_handle:
            params["frameHandle"] = self.current_handle
        if frame_ordinal is not None:
            params["ordinal"] = frame_ordinal
        elif frame_handle is not None:
            params["nodeHandle"] = frame_handle.node_id
        resp = (await self.protocol.resolveChildFrameHandle(**params))["result"]
        await self.switch_to_browsing_context_frame(self.top_level_handle, resp)
        await self.switch_to_browsing_context(resp)

    async def switch_to_window(self, handle: str):
        await self.switch_to_browsing_context_frame(handle, "")
        await self.switch_to_top_level_browsing_context(handle)

    async def perform_keyboard_interactions(self, interactions: list[dict[str, Any]]):
        for interaction in interactions:
            type_ = interaction["type"]
            interaction["type"] = type_.value if isinstance(type_, KeyboardInteractionType) else type_
        await self.protocol.performKeyboardInteractions(handle=self.top_level_handle, interactions=interactions)

    async def perform_mouse_interaction(
        self, x: int, y: int, button: MouseButton, interaction: MouseInteraction, modifiers: Optional[list[Any]] = None
    ):
        modifiers = [] if modifiers is None else modifiers
        await self.protocol.performMouseInteraction(
            handle=self.top_level_handle,
            position={"x": x, "y": y},
            button=button.value,
            interaction=interaction.value,
            modifiers=modifiers,
        )

    async def perform_interaction_sequence(self, sources: list[dict[str, Any]], steps: list[dict[str, Any]]):
        params: dict[str, Any] = {
            "handle": self.top_level_handle,
            "inputSources": sources,
            "steps": steps,
        }
        if self.current_handle:
            params["frameHandle"] = self.current_handle
        await self.protocol.performInteractionSequence(**params)

    async def wait_for_navigation_to_complete(self):
        params: dict[str, Any] = {
            "browsingContextHandle": self.top_level_handle,
            "pageLoadTimeout": self.page_load_timeout,
        }
        if self.current_handle:
            params["frameHandle"] = self.current_handle
        await self.protocol.waitForNavigationToComplete(**params)

    async def accept_current_javascript_dialog(self):
        await self.protocol.acceptCurrentJavaScriptDialog(browsingContextHandle=self.top_level_handle)

    async def dismiss_current_javascript_dialog(self):
        await self.protocol.dismissCurrentJavaScriptDialog(browsingContextHandle=self.top_level_handle)

    async def set_user_input_for_current_javascript_prompt(self, user_input: str):
        await self.protocol.setUserInputForCurrentJavaScriptPrompt(
            browsingContextHandle=self.top_level_handle, userInput=user_input
        )

    async def message_of_current_javascript_dialog(self):
        return (await self.protocol.messageOfCurrentJavaScriptDialog(browsingContextHandle=self.top_level_handle))[
            "message"
        ]

    async def compute_element_layout(self, node_id: str, scroll_if_needed: bool, coordinate_system: str):
        return await self.protocol.computeElementLayout(
            browsingContextHandle=self.top_level_handle,
            nodeHandle=node_id,
            scrollIntoViewIfNeeded=scroll_if_needed,
            coordinateSystem=coordinate_system,
            frameHandle="" if self.current_handle is None else self.current_handle,
        )

    async def select_option_element(self, node_id: str):
        await self.protocol.selectOptionElement(
            browsingContextHandle=self.top_level_handle,
            nodeHandle=node_id,
            frameHandle="" if self.current_handle is None else self.current_handle,
        )
