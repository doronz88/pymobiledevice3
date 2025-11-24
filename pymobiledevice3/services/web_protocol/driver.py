from dataclasses import asdict, dataclass
from typing import Optional

from pymobiledevice3.services.web_protocol.automation_session import RESOURCES, Point, Rect, Size
from pymobiledevice3.services.web_protocol.element import WebElement
from pymobiledevice3.services.web_protocol.selenium_api import By, SeleniumApi
from pymobiledevice3.services.web_protocol.switch_to import SwitchTo

ENTER_FULLSCREEN = (RESOURCES / "enter_fullscreen.js").read_text()


@dataclass
class Cookie:
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    expires: int = 0
    httpOnly: bool = False
    secure: bool = False
    session: bool = True
    sameSite: str = "None"

    @classmethod
    def from_automation(cls, d):
        d.pop("size")
        return cls(**d)


class WebDriver(SeleniumApi):
    def __init__(self, session):
        """
        :param pymobiledevice3.services.web_protocol.automation_session.AutomationSession session: Automation session.
        """
        self.session = session
        self.switch_to = SwitchTo(session)

    async def add_cookie(self, cookie: Cookie):
        """Adds a cookie to your current session."""
        if isinstance(cookie, Cookie):
            cookie = asdict(cookie)
        await self.session.add_single_cookie(cookie)

    async def back(self):
        """Goes one step backward in the browser history."""
        await self.session.wait_for_navigation_to_complete()
        await self.session.go_back_in_browsing_context()
        await self.session.switch_to_browsing_context("")

    async def close(self):
        """Closes the current window."""
        await self.session.close_window()

    @property
    async def current_url(self):
        """Gets the URL of the current page."""
        await self.session.wait_for_navigation_to_complete()
        return (await self.session.get_browsing_context())["url"]

    @property
    async def current_window_handle(self):
        """Returns the handle of the current window."""
        return (await self.session.get_browsing_context())["handle"]

    async def delete_all_cookies(self):
        """Delete all cookies in the scope of the session."""
        await self.session.delete_all_cookies()

    async def delete_cookie(self, name: str):
        """Deletes a single cookie with the given name."""
        await self.session.delete_single_cookie(name)

    async def execute_async_script(self, script: str, *args):
        """
        Asynchronously Executes JavaScript in the current window/frame.
        :param script: The JavaScript to execute.
        :param args: Any applicable arguments for your JavaScript.
        """
        return await self.session.execute_script(script, args, async_=True)

    async def execute_script(self, script: str, *args):
        """
        Synchronously Executes JavaScript in the current window/frame.
        :param script: The JavaScript to execute.
        :param args: Any applicable arguments for your JavaScript.
        """
        return await self.session.execute_script(script, args)

    async def find_element(self, by=By.ID, value=None) -> Optional[WebElement]:
        """Find an element given a By strategy and locator."""
        elem = await self.session.find_elements(by, value)
        return None if elem is None else WebElement(self.session, elem)

    async def find_elements(self, by=By.ID, value=None) -> list[WebElement]:
        """Find elements given a By strategy and locator."""
        elements = await self.session.find_elements(by, value, single=False)
        return [WebElement(self.session, elem) for elem in elements]

    async def forward(self):
        """Goes one step forward in the browser history."""
        await self.session.wait_for_navigation_to_complete()
        await self.session.go_forward_in_browsing_context()
        await self.session.switch_to_browsing_context("")

    async def fullscreen_window(self):
        """Invokes the window manager-specific 'full screen' operation."""
        await self.session.evaluate_js_function(ENTER_FULLSCREEN, implicit_callback=True)

    async def get(self, url: str):
        """Loads a web page in the current browser session."""
        await self.session.wait_for_navigation_to_complete()
        await self.session.navigate_broswing_context(url)
        await self.session.switch_to_browsing_context("")

    async def get_cookie(self, name: str) -> Cookie:
        """Get a single cookie by name. Returns the cookie if found, None if not."""
        for cookie in await self.get_cookies():
            if cookie.name == name:
                return cookie

    async def get_cookies(self) -> list[Cookie]:
        """Returns cookies visible in the current session."""
        return list(map(Cookie.from_automation, await self.session.get_all_cookies()))

    @property
    async def screenshot_as_base64(self) -> str:
        """Gets the screenshot of the current window as a base64 encoded string."""
        return await self.session.screenshot_as_base64()

    async def get_window_position(self) -> Point:
        """Gets the x,y position of the current window."""
        rect = await self.get_window_rect()
        return Point(x=rect.x, y=rect.y)

    async def get_window_rect(self) -> Rect:
        """Gets the x, y coordinates of the window as well as height and width of the current window."""
        context = await self.session.get_browsing_context()
        return Rect(
            context["windowOrigin"]["x"],
            context["windowOrigin"]["y"],
            context["windowSize"]["width"],
            context["windowSize"]["height"],
        )

    async def get_window_size(self) -> Size:
        """Gets the width and height of the current window."""
        rect = await self.get_window_rect()
        return Size(height=rect.height, width=rect.width)

    def implicitly_wait(self, time_to_wait):
        """Sets a sticky timeout to implicitly wait for an element to be found, or a command to complete."""
        self.session.implicit_wait_timeout = time_to_wait * 1000

    async def maximize_window(self):
        """Maximizes the current window."""
        await self.session.maximize_window()

    async def minimize_window(self):
        """Invokes the window manager-specific 'minimize' operation."""
        await self.session.hide_window()

    @property
    async def page_source(self) -> str:
        """Gets the source of the current page."""
        return await self.session.evaluate_js_function("function() { return document.documentElement.outerHTML; }")

    async def refresh(self):
        """Refreshes the current page."""
        await self.session.wait_for_navigation_to_complete()
        await self.session.reload_browsing_context()
        await self.session.switch_to_browsing_context("")

    async def set_window_position(self, x, y):
        """Sets the x,y position of the current window."""
        await self.set_window_rect(x=int(x, 0), y=int(y, 0))

    async def set_window_rect(self, x=None, y=None, width=None, height=None):
        """Sets the x, y coordinates of the window as well as height and width of the current window."""
        await self.session.set_window_frame(x, y, width, height)

    async def set_window_size(self, width, height):
        """Sets the width and height of the current window."""
        await self.set_window_rect(width=int(width, 0), height=int(height, 0))

    async def start_session(self):
        """Creates a new session."""
        await self.session.start_session()

    @property
    async def title(self) -> str:
        """Returns the title of the current page."""
        await self.session.wait_for_navigation_to_complete()
        return await self.session.evaluate_js_function("function() { return document.title; }")

    @property
    async def window_handles(self) -> list[str]:
        """Returns the handles of all windows within the current session."""
        return await self.session.get_window_handles()
