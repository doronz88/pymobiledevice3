import asyncio
import inspect
import logging
import re
from abc import ABC, abstractmethod
from asyncio import CancelledError
from collections.abc import AsyncIterator, Iterable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from functools import update_wrapper
from string import Template
from typing import Annotated, Any, Optional

import inquirer3
import IPython
import nest_asyncio
import typer
import uvicorn
from inquirer3.themes import GreenPassion
from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion.base import CompleteEvent, Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import style_from_pygments_cls
from pygments import formatters, highlight, lexers
from pygments.styles import get_style_by_name
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import (
    InspectorEvaluateError,
    LaunchingApplicationError,
    RemoteAutomationNotEnabledError,
    WebInspectorNotEnabledError,
    WirError,
)
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.services.web_protocol.cdp_server import app
from pymobiledevice3.services.web_protocol.driver import By, Cookie, WebDriver
from pymobiledevice3.services.web_protocol.inspector_session import InspectorSession
from pymobiledevice3.services.webinspector import SAFARI, Application, ApplicationPage, WebinspectorService

SCRIPT = Template("""
function inspectedPage_evalResult_getCompletions(primitiveType) {
    let resultSet = {};
    let object = primitiveType;
    for (let o = object; o; o = o.__proto__) {
        try {
            let names = Object.getOwnPropertyNames(o);
            for (let i = 0; i < names.length; ++i)
                resultSet[names[i]] = true;
        } catch(e) {}
    }
    return resultSet;
}

try {
    inspectedPage_evalResult_getCompletions(${object})
} catch (e) {}
""")

JS_RESERVED_WORDS = frozenset({
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
})

OSUTILS = get_os_utils()
logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="webinspector",
    help=(
        "Control Safari/WebViews (tabs, automation, JS shells, CDP). "
        "Requires Web Inspector and Remote Automation enabled on the device."
    ),
    no_args_is_help=True,
)


def catch_errors(func):
    errors = {
        LaunchingApplicationError: "Unable to launch application (try to unlock device)",
        WebInspectorNotEnabledError: "Web inspector is not enabled",
        RemoteAutomationNotEnabledError: "Remote automation is not enabled",
    }

    def handle_error(e):
        logger.error(next(msg for exc, msg in errors.items() if isinstance(e, exc)))

    if inspect.iscoroutinefunction(func):

        async def catch_function(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except tuple(errors) as e:
                handle_error(e)

    else:

        def catch_function(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except tuple(errors) as e:
                handle_error(e)

    return update_wrapper(catch_function, func)


async def reload_pages(inspector: WebinspectorService) -> None:
    await inspector.get_open_pages()
    # Best effort.
    await inspector.flush_input(2)


async def create_webinspector_and_launch_app(
    lockdown: LockdownServiceProvider, timeout: float, app: str
) -> tuple[WebinspectorService, Application]:
    inspector = WebinspectorService(lockdown=lockdown)
    await inspector.connect(timeout)
    application = await inspector.open_app(app)
    return inspector, application


async def opened_tabs_task(service_provider: LockdownServiceProvider, timeout: float) -> None:
    inspector = WebinspectorService(lockdown=service_provider)
    await inspector.connect(timeout)
    application_pages = await inspector.get_open_application_pages(timeout=timeout)
    for application_page in application_pages:
        print(application_page)
    await inspector.close()


@cli.command()
@catch_errors
def opened_tabs(
    service_provider: ServiceProviderDep,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Seconds to wait for WebInspector to respond."),
    ] = 3.0,
) -> None:
    """
    Show all currently opened tabs.

    \b
    Opt-in:
       iOS >= 18: Settings -> Apps -> Safari -> Advanced -> Web Inspector

       iOS < 18: Settings -> Safari -> Advanced -> Web Inspector
    """
    asyncio.run(opened_tabs_task(service_provider, timeout), debug=True)


@catch_errors
async def launch_task(service_provider: LockdownServiceProvider, url, timeout) -> None:
    inspector, safari = await create_webinspector_and_launch_app(service_provider, timeout, SAFARI)
    session = await inspector.automation_session(safari)
    driver = WebDriver(session)
    print("Starting session")
    await driver.start_session()
    print("Getting URL")
    await driver.get(url)
    OSUTILS.wait_return()
    await session.stop_session()
    await inspector.close()


@cli.command()
@catch_errors
def launch(
    service_provider: ServiceProviderDep,
    url: str,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Seconds to wait for WebInspector to respond."),
    ] = 3.0,
) -> None:
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
    asyncio.run(launch_task(service_provider, url, timeout), debug=True)


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


@catch_errors
async def shell_task(service_provider: LockdownServiceProvider, timeout: float) -> None:
    inspector, safari = await create_webinspector_and_launch_app(service_provider, timeout, SAFARI)
    session = await inspector.automation_session(safari)
    driver = WebDriver(session)
    try:
        nest_asyncio.apply()
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
            user_ns={
                "driver": driver,
                "Cookie": Cookie,
                "By": By,
            },
        )
    finally:
        await session.stop_session()
        await inspector.close()


@cli.command()
@catch_errors
def shell(
    service_provider: ServiceProviderDep,
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Seconds to wait for WebInspector to respond."),
    ] = 3.0,
) -> None:
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
    asyncio.run(shell_task(service_provider, timeout), debug=True)


@cli.command()
@catch_errors
def js_shell(
    service_provider: ServiceProviderDep,
    url: str = "",
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Seconds to wait for WebInspector to respond."),
    ] = 3.0,
    automation: Annotated[
        bool,
        typer.Option(help="Use remote automation (requires Remote Automation toggle)."),
    ] = False,
    open_safari: Annotated[
        bool,
        typer.Option(help="Use an existing WebView; skip auto-opening Safari."),
    ] = False,
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
    asyncio.run(run_js_shell(js_shell_class, service_provider, timeout, url, open_safari))


udid = ""


def create_app():
    inspector = WebinspectorService(lockdown=create_using_usbmux(udid))
    app.state.inspector = inspector
    return app


@cli.command()
def cdp(service_provider: ServiceProviderDep, host: str = "127.0.0.1", port: int = 9222) -> None:
    """
    Start a CDP server for debugging WebViews.

    \b
    In order to debug the WebView that way, open in Google Chrome:
        chrome://inspect/#devices
    """
    global udid
    udid = service_provider.udid
    uvicorn.run(
        f"{__name__}:{create_app.__name__}",
        host=host,
        port=port,
        factory=True,
        ws_ping_timeout=None,
        ws="wsproto",
        loop="asyncio",
    )


async def get_js_completions(jsshell: "JsShell", obj: str, prefix: str) -> AsyncIterator[Completion]:
    if obj in JS_RESERVED_WORDS:
        return

    try:
        for key in await jsshell.evaluate_expression(SCRIPT.substitute(object=obj), return_by_value=True):
            if not key.startswith(prefix):
                continue
            yield Completion(key.removeprefix(prefix), display=key)
    except (Exception, CancelledError):
        # ignore every possible exception
        pass


class JsShellCompleter(Completer):
    def __init__(self, jsshell: "JsShell") -> None:
        self.jsshell: JsShell = jsshell

    async def get_completions_async(
        self,
        document: Document,
        complete_event: CompleteEvent,
    ) -> AsyncIterator[Completion]:
        # Build the JS expression we want to inspect
        text = f"globalThis.{document.text_before_cursor}"

        # Extract identifiers / dotted paths
        matches = re.findall(r"[a-zA-Z_][a-zA-Z_0-9.]+", text)
        if not matches:
            # async *generator*: just end, don't return a list
            return

        text = matches[-1]
        if "." in text:
            js_obj, prefix = text.rsplit(".", 1)
        else:
            js_obj = text
            prefix = ""

        # This should return an iterable of Completion (or something we can wrap)
        async for completion in get_js_completions(self.jsshell, js_obj, prefix):
            yield completion

    # Optional: keep sync completions empty so PTK knows we prefer async
    def get_completions(
        self,
        document: Document,
        complete_event: CompleteEvent,
    ) -> Iterable[Completion]:
        return []


class JsShell(ABC):
    def __init__(self) -> None:
        super().__init__()
        self.prompt_session: PromptSession = PromptSession(
            lexer=PygmentsLexer(lexers.JavascriptLexer),
            auto_suggest=AutoSuggestFromHistory(),
            style=style_from_pygments_cls(get_style_by_name("stata-dark")),
            history=FileHistory(self.webinspector_history_path()),
            completer=JsShellCompleter(self),
        )

    @classmethod
    @abstractmethod
    def create(
        cls, lockdown: LockdownServiceProvider, timeout: float, open_safari: bool
    ) -> "AbstractAsyncContextManager[JsShell]": ...

    @abstractmethod
    async def evaluate_expression(self, exp, return_by_value: bool = False) -> Any: ...

    @abstractmethod
    async def navigate(self, url: str) -> None: ...

    async def js_iter(self) -> None:
        with patch_stdout(True):
            exp = await self.prompt_session.prompt_async(HTML('<style fg="cyan"><b>&gt;</b></style> '))

        if not exp.strip():
            return

        result = await self.evaluate_expression(exp)
        colorful_result = highlight(
            f"{result}", lexers.JavascriptLexer(), formatters.Terminal256Formatter(style="stata-dark")
        )
        print(colorful_result, end="")

    async def start(self, url: str = "") -> None:
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
    def __init__(self, driver: WebDriver) -> None:
        super().__init__()
        self.driver: WebDriver = driver

    @classmethod
    @asynccontextmanager
    async def create(
        cls, lockdown: LockdownServiceProvider, timeout: float, open_safari: bool
    ) -> "AsyncIterator[AutomationJsShell]":
        inspector, application = await create_webinspector_and_launch_app(lockdown, timeout, SAFARI)
        automation_session = await inspector.automation_session(application)
        driver = WebDriver(automation_session)
        await driver.start_session()
        try:
            yield cls(driver)
        finally:
            await automation_session.stop_session()
            await inspector.close()

    async def evaluate_expression(self, exp: str, return_by_value: bool = False) -> Any:
        return await self.driver.execute_script(f"return {exp}")

    async def navigate(self, url: str) -> None:
        await self.driver.get(url)


class InspectorJsShell(JsShell):
    def __init__(self, inspector_session: InspectorSession) -> None:
        super().__init__()
        self.inspector_session: InspectorSession = inspector_session

    @classmethod
    @asynccontextmanager
    async def create(
        cls, lockdown: LockdownServiceProvider, timeout: float, open_safari: bool
    ) -> "AsyncIterator[InspectorJsShell]":
        inspector = WebinspectorService(lockdown=lockdown)
        await inspector.connect(timeout)
        if open_safari:
            _ = await inspector.open_app(SAFARI)
        application_page = await cls.query_page(inspector, bundle_identifier=SAFARI if open_safari else None)
        if application_page is None:
            raise typer.Exit()

        inspector_session = await inspector.inspector_session(application_page.application, application_page.page)
        await inspector_session.console_enable()
        await inspector_session.runtime_enable()

        try:
            yield cls(inspector_session)
        finally:
            await inspector.close()

    async def evaluate_expression(self, exp: str, return_by_value: bool = False) -> Any:
        return await self.inspector_session.runtime_evaluate(exp, return_by_value=return_by_value)

    async def navigate(self, url: str):
        await self.inspector_session.navigate_to_url(url)

    @staticmethod
    async def query_page(
        inspector: WebinspectorService, bundle_identifier: Optional[str] = None
    ) -> Optional[ApplicationPage]:
        available_pages = await inspector.get_open_application_pages(timeout=1)
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
