from pymobiledevice3.exceptions import WirError
from pymobiledevice3.services.web_protocol.automation_session import (
    MODIFIER_TO_KEY,
    RESOURCES,
    VIRTUAL_KEYS,
    KeyboardInteractionType,
    MouseButton,
    MouseInteraction,
    Point,
    Rect,
    Size,
)
from pymobiledevice3.services.web_protocol.selenium_api import By, SeleniumApi

IS_EDITABLE = (RESOURCES / "is_editable.js").read_text()
ELEMENT_CLEAR = (RESOURCES / "element_clear.js").read_text()
GET_ATTRIBUTE = (RESOURCES / "get_attribute.js").read_text()
ELEMENT_ATTRIBUTE = (RESOURCES / "element_attribute.js").read_text()
IS_DISPLAYED = (RESOURCES / "is_displayed.js").read_text()
IS_ENABLED = (RESOURCES / "is_enabled.js").read_text()
FOCUS = (RESOURCES / "focus.js").read_text()


class WebElement(SeleniumApi):
    def __init__(self, session, id_):
        """
        :param pymobiledevice3.services.web_protocol.automation_session.AutomationSession session: Automation session.
        :param dict id_: Element id.
        """
        self.session = session
        self.id_ = id_
        self.node_id = id_[f"session-node-{self.session.id_}"]

    async def clear(self):
        """Clears the text if it's a text entry element."""
        if not self.is_editable():
            return
        rect, center, _is_obscured = await self._compute_layout()
        if rect is None or center is None:
            return
        await self._evaluate_js_function(ELEMENT_CLEAR)

    async def click(self):
        """Clicks the element."""
        rect, center, is_obscured = await self._compute_layout(use_viewport=True)
        if rect is None or is_obscured or center is None:
            return
        if self.tag_name == "option":
            await self._select_option_element()
        else:
            await self.session.perform_mouse_interaction(
                center.x, center.y, MouseButton.LEFT, MouseInteraction.SINGLE_CLICK
            )

    async def find_element(self, by=By.ID, value=None):
        """Find an element given a By strategy and locator."""
        elem = await self.session.find_elements(by, value, root=self.id_)
        return None if elem is None else WebElement(self.session, elem)

    async def find_elements(self, by=By.ID, value=None):
        """Find elements given a By strategy and locator."""
        elements = await self.session.find_elements(by, value, single=False, root=self.id_)
        return [WebElement(self.session, elem) for elem in elements]

    async def get_attribute(self, name: str) -> str:
        """Gets the given attribute or property of the element."""
        return await self.session.execute_script(f"return ({GET_ATTRIBUTE}).apply(null, arguments);", self.id_, name)

    async def get_dom_attribute(self, name: str) -> str:
        """Gets the given attribute of the element."""
        return await self._evaluate_js_function(ELEMENT_ATTRIBUTE, name)

    async def get_property(self, name: str) -> str:
        """Gets the given property of the element."""
        return await self._evaluate_js_function(f"function(element) {{ return element.{name}; }}")

    async def is_displayed(self) -> bool:
        """Whether the element is visible to a user."""
        return await self.session.execute_script(f"return ({IS_DISPLAYED}).apply(null, arguments);", self.id_)

    async def is_enabled(self) -> bool:
        """Returns whether the element is enabled."""
        return await self._evaluate_js_function(IS_ENABLED)

    async def is_selected(self) -> bool:
        """Returns whether the element is selected. Can be used to check if a checkbox or radio button is selected."""
        return bool(await self.get_dom_attribute("selected"))

    @property
    async def location(self) -> Point:
        """The location of the element in the renderable canvas."""
        rect = await self.rect
        return Point(x=rect.x, y=rect.y)

    @property
    async def location_once_scrolled_into_view(self) -> Point:
        """Returns the top lefthand corner location on the screen, or ``None`` if the element is not visible."""
        rect = await self.session.execute_script(
            "arguments[0].scrollIntoView(true); return arguments[0].getBoundingClientRect(); ", self.id_
        )
        return Point(x=round(rect["x"]), y=round(rect["y"]))

    @property
    async def rect(self) -> Rect:
        """The size and location of the element."""
        return (await self._compute_layout(scroll_if_needed=False))[0]

    @property
    async def screenshot_as_base64(self) -> str:
        """Gets the screenshot of the current element as a base64 encoded string."""
        return await self.session.screenshot_as_base64(scroll=True, node_id=self.node_id)

    async def send_keys(self, value):
        """
        Simulates typing into the element.
        :param value: A string for typing, or setting form fields.
        """
        await self._evaluate_js_function(FOCUS)
        interactions = []
        sticky_modifier = set()
        for key in value:
            if key in VIRTUAL_KEYS:
                virtual_key, modifier = VIRTUAL_KEYS[key]
                interaction = {"type": KeyboardInteractionType.INSERT_BY_KEY, "key": virtual_key}
                if modifier is not None:
                    sticky_modifier ^= {modifier}
                    interaction["type"] = (
                        KeyboardInteractionType.KEY_PRESS
                        if modifier in sticky_modifier
                        else KeyboardInteractionType.KEY_RELEASE
                    )
                interactions.append(interaction)
            else:
                interactions.append({"type": KeyboardInteractionType.INSERT_BY_KEY, "text": key})
        for modifier in sticky_modifier:
            interactions.append({"type": KeyboardInteractionType.KEY_RELEASE, "key": MODIFIER_TO_KEY[modifier]})
        await self.session.perform_keyboard_interactions(interactions)

    @property
    async def size(self) -> Size:
        """The size of the element."""
        rect = await self.rect
        return Size(height=rect.height, width=rect.width)

    async def submit(self):
        """Submits a form."""
        form = await self.find_element(By.XPATH, "./ancestor-or-self::form")
        submit_code = (
            "var e = arguments[0].ownerDocument.createEvent('Event');"
            "e.initEvent('submit', true, true);"
            "if (arguments[0].dispatchEvent(e)) { arguments[0].submit() }"
        )
        await self.session.execute_script(submit_code, form.id_)

    @property
    async def tag_name(self) -> str:
        """This element's ``tagName`` property."""
        return await self._evaluate_js_function("function(element) { return element.tagName.toLowerCase() }")

    @property
    async def text(self) -> str:
        """The text of the element."""
        return await self._evaluate_js_function(
            'function(element) { return element.innerText.replace(/^[^\\S\\xa0]+|[^\\S\\xa0]+$/g, "") }'
        )

    async def touch(self) -> None:
        """Simulate touch interaction on the element."""
        _rect, center, _is_obscured = await self._compute_layout(use_viewport=True)
        await self.session.perform_interaction_sequence(
            [{"sourceId": self.session.id_, "sourceType": "Touch"}],
            [{"states": [{"sourceId": self.session.id_, "location": {"x": center.x, "y": center.y}}]}],
        )

    async def value_of_css_property(self, property_name) -> str:
        """The value of a CSS property."""
        return await self._evaluate_js_function(
            "function(element) {"
            f' return document.defaultView.getComputedStyle(element).getPropertyValue("{property_name}"); '
            "}"
        )

    async def is_editable(self) -> bool:
        """Returns whether the element is editable."""
        return await self._evaluate_js_function(IS_EDITABLE)

    async def _compute_layout(self, scroll_if_needed=True, use_viewport=False):
        try:
            result = await self.session.compute_element_layout(
                self.node_id, scroll_if_needed, "LayoutViewport" if use_viewport else "Page"
            )
        except WirError:
            return

        origin = result["rect"]["origin"]
        size = result["rect"]["size"]
        rect = Rect(x=round(origin["x"]), y=round(origin["y"]), width=size["width"], height=size["height"])
        center = Point(x=result["inViewCenterPoint"]["x"], y=result["inViewCenterPoint"]["y"])
        return rect, center, result["isObscured"]

    async def _select_option_element(self):
        await self.session.select_option_element(self.node_id)

    async def _evaluate_js_function(self, function, *args):
        return await self.session.evaluate_js_function(function, self.id_, *args)

    def __eq__(self, other):
        return self.id_ == other.id_
