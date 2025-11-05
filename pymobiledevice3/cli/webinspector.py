import asyncio
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from contextlib import asynccontextmanager
from functools import update_wrapper
from typing import Optional

import click
import inquirer3
import IPython
import uvicorn
from inquirer3.themes import GreenPassion
from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion.base import CompleteEvent, Completer, Completion, Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import style_from_pygments_cls
from pygments import formatters, highlight, lexers
from pygments.styles import get_style_by_name

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import (
    InspectorEvaluateError,
    LaunchingApplicationError,
    RemoteAutomationNotEnabledError,
    WebInspectorNotEnabledError,
    WirError,
)
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.services.web_protocol.cdp_server import app
from pymobiledevice3.services.web_protocol.driver import By, Cookie, WebDriver
from pymobiledevice3.services.web_protocol.inspector_session import InspectorSession
from pymobiledevice3.services.webinspector import SAFARI, ApplicationPage, WebinspectorService

SCRIPT = """
function inspectedPage_evalResult_getCompletions(primitiveType) {{
    var resultSet={{}};
    var object = primitiveType;
    for(var o=object;o;o=o.__proto__) {{

        try{{
            var names=Object.getOwnPropertyNames(o);
            for(var i=0;i<names.length;++i)
                resultSet[names[i]]=true;
        }} catch(e){{}}
    }}
    return resultSet;
}}

try {{
    inspectedPage_evalResult_getCompletions({object})
}} catch (e) {{}}
"""

JS_RESERVED_WORDS = [
    "abstract",
    "arguments",
    "await",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "double",
    "else",
    "enum",
    "eval",
    "export",
    "extends",
    "false",
    "final",
    "finally",
    "float",
    "for",
    "function",
    "goto",
    "if",
    "implements",
    "import",
    "in",
    "instanceof",
    "int",
    "interface",
    "let",
    "long",
    "native",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "volatile",
    "while",
    "with",
    "yield",
]

OSUTILS = get_os_utils()
logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group()
def webinspector() -> None:
    """Access webinspector services"""
    pass


def catch_errors(func):
    def catch_function(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except LaunchingApplicationError:
            logger.error("Unable to launch application (try to unlock device)")
        except WebInspectorNotEnabledError:
            logger.error("Web inspector is not enable")
        except RemoteAutomationNotEnabledError:
            logger.error("Remote automation is not enable")

    return update_wrapper(catch_function, func)


def reload_pages(inspector: WebinspectorService):
    inspector.get_open_pages()
    # Best effort.
    inspector.flush_input(2)


def create_webinspector_and_launch_app(lockdown: LockdownClient, timeout: float, app: str):
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect(timeout)
    application = inspector.open_app(app)
    return inspector, application


@webinspector.command(cls=Command)
@click.option("-t", "--timeout", default=3, show_default=True, type=float)
@catch_errors
def opened_tabs(service_provider: LockdownClient, timeout):
    """
    Show all currently opened tabs.

    \b
    Opt-in:
       iOS >= 18: Settings -> Apps -> Safari -> Advanced -> Web Inspector

       iOS < 18: Settings -> Safari -> Advanced -> Web Inspector
    """
    inspector = WebinspectorService(lockdown=service_provider)
    inspector.connect(timeout)
    application_pages = inspector.get_open_application_pages(timeout=timeout)
    for application_page in application_pages:
        print(application_page)
    inspector.close()


@webinspector.command(cls=Command)
@click.argument("url")
@click.option("-t", "--timeout", default=3, show_default=True, type=float)
@catch_errors
def launch(service_provider: LockdownClient, url, timeout):
    """
    Launch a specific URL in Safari.

    \b
    Opt-in (iOS >= 18):
        Settings -> Apps -> Safari -> Advanced -> Web Inspector
        Settings -> Apps -> Safari -> Advanced -> Remote Automation

    Opt-in (iOS < 18):
        Settings -> Safari -> Advanced -> Web Inspector
        Settings -> Safari -> Advanced -> Remote Automation

    """
    inspector, safari = create_webinspector_and_launch_app(service_provider, timeout, SAFARI)
    session = inspector.automation_session(safari)
    driver = WebDriver(session)
    print("Starting session")
    driver.start_session()
    print("Getting URL")
    driver.get(url)
    OSUTILS.wait_return()
    session.stop_session()
    inspector.close()


SHELL_USAGE = """
# This shell allows you to control the web with selenium like API.
# The first thing you should do is creating a session:
driver.start_session()

# Then, you can navigate by using the get method:
driver.get("https://google.com")

# You can search for a specific element using the `By` enum:
driver.find_element(By.TAG_NAME, 'input')

# You can also add cookies:
driver.add_cookie(
    Cookie(name='tz', value='UTC', domain='.github.com', path='/', expires=0, httpOnly=False, secure=True,
    session=True, sameSite='None')
)

# See selenium api for more features.
"""


@webinspector.command(cls=Command)
@click.option("-t", "--timeout", default=3, show_default=True, type=float)
@catch_errors
def shell(service_provider: LockdownClient, timeout):
    """
    Create an IPython shell for interacting with a WebView.

    \b
    Opt-in (iOS >= 18):
        Settings -> Apps -> Safari -> Advanced -> Web Inspector
        Settings -> Apps -> Safari -> Advanced -> Remote Automation

    Opt-in (iOS < 18):
        Settings -> Safari -> Advanced -> Web Inspector
        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector, safari = create_webinspector_and_launch_app(service_provider, timeout, SAFARI)
    session = inspector.automation_session(safari)
    driver = WebDriver(session)
    try:
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
            user_ns={
                "driver": driver,
                "Cookie": Cookie,
                "By": By,
            },
        )
    finally:
        session.stop_session()
        inspector.close()


@webinspector.command(cls=Command)
@click.option("-t", "--timeout", default=3, show_default=True, type=float)
@click.option("--automation", is_flag=True, help="Use remote automation")
@click.option("--no-open-safari", is_flag=True, help="Avoid opening the Safari app")
@click.argument("url", required=False, default="")
@catch_errors
def js_shell(
    service_provider: LockdownServiceProvider, timeout: float, automation: bool, no_open_safari: bool, url: str
) -> None:
    """
    Create a javascript shell. This interpreter runs on your local machine,
    but evaluates each expression on the remote

    \b
    Opt-in:
        iOS >= 18: Settings -> Apps -> Safari -> Advanced -> Web Inspector
        iOS < 18: Settings -> Safari -> Advanced -> Web Inspector
    \b
    for automation also enable:
        iOS >= 18: Settings -> Apps -> Safari -> Advanced -> Remote Automation
        iOS < 18: Settings -> Safari -> Advanced -> Remote Automation
    """

    js_shell_class = AutomationJsShell if automation else InspectorJsShell
    asyncio.run(run_js_shell(js_shell_class, service_provider, timeout, url, not no_open_safari))


udid = ""


def create_app():
    inspector = WebinspectorService(lockdown=create_using_usbmux(udid))
    app.state.inspector = inspector
    return app


@webinspector.command(cls=Command)
@click.option("--host", default="127.0.0.1")
@click.option("--port", type=click.INT, default=9222)
def cdp(service_provider: LockdownClient, host, port):
    """
    Start a CDP server for debugging WebViews.

    \b
    In order to debug the WebView that way, open in Google Chrome:
        chrome://inspect/#devices
    """
    global udid
    udid = service_provider.udid
    uvicorn.run(
        "pymobiledevice3.cli.webinspector:create_app",
        host=host,
        port=port,
        factory=True,
        ws_ping_timeout=None,
        ws="wsproto",
        loop="asyncio",
    )


def get_js_completions(jsshell: "JsShell", obj: str, prefix: str) -> list[Completion]:
    if obj in JS_RESERVED_WORDS:
        return []

    completions = []
    try:
        for key in asyncio.get_running_loop().run_until_complete(
            jsshell.evaluate_expression(SCRIPT.format(object=obj), return_by_value=True)
        ):
            if not key.startswith(prefix):
                continue
            completions.append(Completion(key.removeprefix(prefix), display=key))
    except Exception:
        # ignore every possible exception
        pass
    return completions


class JsShellCompleter(Completer):
    def __init__(self, jsshell: "JsShell"):
        self.jsshell = jsshell

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        text = f"globalThis.{document.text_before_cursor}"
        text = re.findall("[a-zA-Z_][a-zA-Z_0-9.]+", text)
        if len(text) == 0:
            return []
        text = text[-1]
        if "." in text:
            js_obj, prefix = text.rsplit(".", 1)
        else:
            js_obj = text
            prefix = ""

        return get_js_completions(self.jsshell, js_obj, prefix)


class JsShell(ABC):
    def __init__(self) -> None:
        super().__init__()
        self.prompt_session = PromptSession(
            lexer=PygmentsLexer(lexers.JavascriptLexer),
            auto_suggest=AutoSuggestFromHistory(),
            style=style_from_pygments_cls(get_style_by_name("stata-dark")),
            history=FileHistory(self.webinspector_history_path()),
            completer=JsShellCompleter(self),
        )

    @classmethod
    @abstractmethod
    def create(cls, lockdown: LockdownServiceProvider, timeout: float, open_safari: bool) -> None:
        pass

    @abstractmethod
    async def evaluate_expression(self, exp, return_by_value: bool = False):
        pass

    @abstractmethod
    async def navigate(self, url: str):
        pass

    async def js_iter(self):
        with patch_stdout(True):
            exp = await self.prompt_session.prompt_async(HTML('<style fg="cyan"><b>&gt;</b></style> '))

        if not exp.strip():
            return

        result = await self.evaluate_expression(exp)
        colorful_result = highlight(
            f"{result}", lexers.JavascriptLexer(), formatters.Terminal256Formatter(style="stata-dark")
        )
        print(colorful_result, end="")

    async def start(self, url: str = ""):
        if url:
            await self.navigate(url)
        while True:
            try:
                await self.js_iter()
            except (WirError, InspectorEvaluateError) as e:
                logger.error(e)
            except KeyboardInterrupt:  # KeyboardInterrupt Control-C
                pass
            except EOFError:  # Control-D
                return

    @staticmethod
    def webinspector_history_path() -> str:
        return str(get_home_folder() / "webinspector_history")


class AutomationJsShell(JsShell):
    def __init__(self, driver: WebDriver):
        super().__init__()
        self.driver = driver

    @classmethod
    @asynccontextmanager
    async def create(cls, lockdown: LockdownClient, timeout: float, open_safari: bool) -> "AutomationJsShell":
        inspector, application = create_webinspector_and_launch_app(lockdown, timeout, SAFARI)
        automation_session = inspector.automation_session(application)
        driver = WebDriver(automation_session)
        driver.start_session()
        try:
            yield cls(driver)
        finally:
            automation_session.stop_session()
            inspector.close()

    async def evaluate_expression(self, exp: str, return_by_value: bool = False):
        return self.driver.execute_script(f"return {exp}")

    async def navigate(self, url: str):
        self.driver.get(url)


class InspectorJsShell(JsShell):
    def __init__(self, inspector_session: InspectorSession):
        super().__init__()
        self.inspector_session = inspector_session

    @classmethod
    @asynccontextmanager
    async def create(cls, lockdown: LockdownClient, timeout: float, open_safari: bool) -> "InspectorJsShell":
        inspector = WebinspectorService(lockdown=lockdown)
        inspector.connect(timeout)
        if open_safari:
            _ = inspector.open_app(SAFARI)
        application_page = cls.query_page(inspector, bundle_identifier=SAFARI if open_safari else None)
        if application_page is None:
            raise click.exceptions.Exit()

        inspector_session = await inspector.inspector_session(application_page.application, application_page.page)
        await inspector_session.console_enable()
        await inspector_session.runtime_enable()

        try:
            yield cls(inspector_session)
        finally:
            inspector.close()

    async def evaluate_expression(self, exp: str, return_by_value: bool = False):
        return await self.inspector_session.runtime_evaluate(exp, return_by_value=return_by_value)

    async def navigate(self, url: str):
        await self.inspector_session.navigate_to_url(url)

    @staticmethod
    def query_page(
        inspector: WebinspectorService, bundle_identifier: Optional[str] = None
    ) -> Optional[ApplicationPage]:
        available_pages = inspector.get_open_application_pages(timeout=1)
        if bundle_identifier is not None:
            available_pages = [
                application_page
                for application_page in available_pages
                if application_page.application.bundle == bundle_identifier
            ]
        if not available_pages:
            logger.error("Unable to find available pages (try to unlock device)")
            return None

        page_query = [inquirer3.List("page", message="choose page", choices=available_pages, carousel=True)]
        page = inquirer3.prompt(page_query, theme=GreenPassion(), raise_keyboard_interrupt=True)["page"]
        return page


async def run_js_shell(
    js_shell_class: type[JsShell], lockdown: LockdownServiceProvider, timeout: float, url: str, open_safari: bool
) -> None:
    async with js_shell_class.create(lockdown, timeout, open_safari) as js_shell_instance:
        await js_shell_instance.start(url)
