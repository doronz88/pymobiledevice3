import asyncio
import contextlib
import inspect
import logging
import re
from abc import ABC, abstractmethod
from asyncio import CancelledError
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Iterable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from functools import update_wrapper
from pathlib import Path
from string import Template
from typing import Annotated, Any, Optional, cast

import typer
import uvicorn
from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion.base import CompleteEvent, Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import style_from_pygments_cls
from pygments import formatters, highlight, lexers
from pygments import styles as _pygments_styles
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, prompt_selection
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    InspectorEvaluateError,
    LaunchingApplicationError,
    RemoteAutomationNotEnabledError,
    WebInspectorNotEnabledError,
    WirError,
)
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.services.web_protocol.cdp_server import app, find_chrome
from pymobiledevice3.services.web_protocol.cdp_trace import ProtocolTrace
from pymobiledevice3.services.web_protocol.driver import By, Cookie, WebDriver
from pymobiledevice3.services.web_protocol.inspector_session import InspectorSession
from pymobiledevice3.services.webinspector import SAFARI, ApplicationPage, WebinspectorService
from pymobiledevice3.utils import start_ipython_shell

SCRIPT = Template("""
function inspectedPage_evalResult_getCompletions(primitiveType) {
    let resultSet = {};
    let object = primitiveType;
    for (let o = object; o; o = o.__proto__) {
        try {
            let names = Object.getOwnPropertyNames(o);
            for (let i = 0; i < names.length; ++i) {
                if (names[i] in resultSet)
                    continue;
                // read the kind from the descriptor - accessing the value could invoke getters
                let d = Object.getOwnPropertyDescriptor(o, names[i]);
                resultSet[names[i]] = d && 'value' in d ? typeof d.value : 'accessor';
            }
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


class _GetAccessToDebug(logging.Filter):
    """Treat uvicorn's access log for GET requests as DEBUG.

    The landing page polls GET /api/targets (and fetches icons) every second, which floods the
    default output; those lines are only useful when debugging. A GET is relabelled DEBUG and
    dropped unless debug logging is on (the app's stream handler has no level of its own, so
    relabelling alone would not hide it); POSTs and the rest are left untouched. uvicorn logs
    access as '%s - "%s %s HTTP/%s" %d' with args (client, method, path, http_version, status).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 2 and args[1] == "GET":
            record.levelno = logging.DEBUG
            record.levelname = "DEBUG"
            return logging.getLogger().isEnabledFor(logging.DEBUG)
        return True


cli = InjectingTyper(
    name="webinspector",
    help=(
        "Control Safari/WebViews (tabs, automation, JS shells, CDP). "
        "Requires Web Inspector and Remote Automation enabled on the device."
    ),
    no_args_is_help=True,
)


def catch_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    errors: dict[type[Exception], str] = {
        LaunchingApplicationError: "Unable to launch application (try to unlock device)",
        WebInspectorNotEnabledError: "Web inspector is not enabled",
        RemoteAutomationNotEnabledError: "Remote automation is not enabled",
    }

    def handle_error(e: Exception) -> None:
        logger.error(next(msg for exc, msg in errors.items() if isinstance(e, exc)))

    if inspect.iscoroutinefunction(func):

        async def async_catch_function(*args: Any, **kwargs: Any):
            try:
                return await func(*args, **kwargs)
            except tuple(errors) as e:
                handle_error(e)

        catch_function = async_catch_function
    else:

        def sync_catch_function(*args: Any, **kwargs: Any):
            try:
                return func(*args, **kwargs)
            except tuple(errors) as e:
                handle_error(e)

        catch_function = sync_catch_function

    return update_wrapper(catch_function, func)


async def reload_pages(inspector: WebinspectorService) -> None:
    await inspector.get_open_pages()
    # Best effort.
    await inspector.flush_input(2)


@asynccontextmanager
async def webinspector_service(lockdown: LockdownServiceProvider) -> AsyncGenerator[WebinspectorService, None]:
    inspector = WebinspectorService(lockdown=lockdown)
    try:
        await inspector.connect()
        async with inspector:
            yield inspector
    finally:
        await inspector.close()


@cli.command()
@catch_errors
@async_command
async def opened_tabs(
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
    async with webinspector_service(service_provider) as inspector:
        application_pages = await inspector.get_open_application_pages(timeout=timeout)
        for application_page in application_pages:
            print(application_page)


@cli.command()
@catch_errors
@async_command
async def launch(
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
    async with webinspector_service(service_provider) as inspector:
        safari = await inspector.open_app(SAFARI)
        session = await inspector.automation_session(safari)
        driver = WebDriver(session)
        try:
            print("Starting session")
            await driver.start_session()
            print("Getting URL")
            await driver.get(url)
            OSUTILS.wait_return()
        finally:
            await session.stop_session()


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


@cli.command()
@catch_errors
@async_command
async def shell(
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
    async with webinspector_service(service_provider) as inspector:
        safari = await inspector.open_app(SAFARI)
        session = await inspector.automation_session(safari)
        driver = WebDriver(session)
        try:
            start_ipython_shell(
                header=highlight(
                    SHELL_USAGE, cast(Any, lexers).PythonLexer(), formatters.Terminal256Formatter(style="native")
                ),
                user_ns={
                    "driver": driver,
                    "Cookie": Cookie,
                    "By": By,
                },
            )
        finally:
            await session.stop_session()


@cli.command()
@catch_errors
@async_command
async def js_shell(
    service_provider: ServiceProviderDep,
    url: str = "",
    timeout: Annotated[
        float,
        typer.Option("--timeout", "-t", help="Seconds to wait for WebInspector to respond."),
    ] = 10.0,
    automation: Annotated[
        bool,
        typer.Option(help="Use remote automation (requires Remote Automation toggle)."),
    ] = False,
    bundle_identifier: Annotated[
        Optional[str],
        typer.Option(
            "--bundle-id",
            help=(
                "Target app bundle identifier. Inspector: filter open pages (omit for all). "
                "Automation: launch app (omit for Safari)."
            ),
        ),
    ] = None,
    console_enable: Annotated[
        Optional[bool],
        typer.Option(
            "--console-enable/--no-console-enable",
            help="Enable console events for Inspector mode. Cannot be combined with --automation.",
        ),
    ] = None,
    open_safari: Annotated[
        bool,
        typer.Option(help="Open Safari before selecting a page."),
    ] = False,
    no_replayed_log: Annotated[
        bool,
        typer.Option(
            "--no-replayed-log",
            help="Don't print the console history the page replays on attach (webinspector.console.replay).",
        ),
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

    if automation and console_enable is not None:
        raise typer.BadParameter("--console-enable/--no-console-enable cannot be combined with --automation.")

    if no_replayed_log:
        logging.getLogger("webinspector.console.replay").setLevel(logging.CRITICAL + 1)

    js_shell_class = AutomationJsShell if automation else InspectorJsShell
    create_kwargs = {}
    if console_enable is not None:
        create_kwargs["console_enable"] = console_enable
    await run_js_shell(js_shell_class, service_provider, timeout, url, open_safari, bundle_identifier, **create_kwargs)


@cli.command()
@async_command
async def cdp(
    service_provider: ServiceProviderDep,
    host: str = "127.0.0.1",
    port: int = 9222,
    chrome: Optional[str] = None,
    pause_new_targets: Annotated[
        bool,
        typer.Option(
            "--pause-new-targets",
            help="Attach to every JSContext an app creates before it runs and stop it on its first "
            'statement (Safari\'s "Automatically Pause Connecting to JSContexts"); open it from the '
            "landing page to land on the pause. Sets the initial state of the landing page's "
            '"Pause new JSContexts on launch" switch.',
        ),
    ] = False,
    trace: Annotated[
        Optional[Path],
        typer.Option(
            "--trace",
            help="Record every protocol message, in both directions, to this JSON-lines file - attach it to a bug report.",
        ),
    ] = None,
) -> None:
    """
    Start a CDP server for debugging WebViews and inspectable JSContexts.

    \b
    A client that auto-attaches with waitForDebuggerOnStart (VS Code, Playwright, Puppeteer)
    is attached to every JSContext an application creates before the context runs, and holds
    it until the client releases it - the equivalent of Safari's "Automatically Show Web
    Inspector for JSContexts". WKWebView pages cannot be held before they run; they are
    attached the moment they appear, and their cross-site navigations are held until the
    client's breakpoints reached the new process.

    \b
    --pause-new-targets (or the switch on the landing page) is Safari's "Automatically Pause
    Connecting to JSContexts": every new JSContext is stopped on its first statement and
    listed as paused; opening it lands DevTools on that pause.

    \b
    Open the following URL in Google Chrome and pick a page to inspect:
        http://127.0.0.1:9222/

    \b
    Chrome-compatible debugger clients can attach through the browser-level endpoint
    advertised by /json/version. For VS Code, use a launch.json configuration such as:
        {"type": "chrome", "request": "attach", "address": "127.0.0.1", "port": 9222,
         "urlFilter": "*", "webRoot": "${workspaceFolder}"}

    \b
    Prefer this over chrome://inspect: chrome://inspect routes the DevTools frontend through
    Chrome's browser-process relay (network target), which deadlocks under sustained console
    traffic and freezes the console/screen. The URL above serves the DevTools frontend so it
    connects to this bridge directly, bypassing that relay.

    \b
    The frontend is fetched from the hosted build; when that is unreachable (offline), it is
    served from a local Chrome instead. Pass --chrome <path> if Chrome is not on PATH or in a
    default install location.
    """
    app.state.inspector = WebinspectorService(lockdown=service_provider)
    # A device disconnect stops the bridge with a device-disconnected error, which
    # pymobiledevice3's own --reconnect (a top-level option) then retries by re-running the command.
    device_disconnected = asyncio.Event()
    app.state.inspector.on_connection_lost = device_disconnected.set
    app.state.chrome_path = find_chrome(chrome)
    app.state.pause_new_targets = pause_new_targets
    recorder = ProtocolTrace(trace) if trace is not None else None
    if recorder is not None:
        app.state.trace = recorder
        app.state.inspector.trace = recorder.device_hook
        typer.echo(f"Recording the protocol trace to {trace}")
    print(f"Web Inspector ready. Open in Google Chrome: http://{host}:{port}/")
    logging.getLogger("uvicorn.access").addFilter(_GetAccessToDebug())
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            ws_ping_timeout=None,
            ws="wsproto",
        )
    )
    serve_task = asyncio.ensure_future(server.serve())
    disconnect_task = asyncio.ensure_future(device_disconnected.wait())
    try:
        await asyncio.wait({serve_task, disconnect_task}, return_when=asyncio.FIRST_COMPLETED)
        if device_disconnected.is_set():
            server.should_exit = True
            await serve_task
            # Raised to pymobiledevice3's top-level handler: with --reconnect it waits for the
            # device and re-runs the command, otherwise it reports the disconnect and stops.
            raise ConnectionTerminatedError("the device disconnected")
        await serve_task
    finally:
        disconnect_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await disconnect_task
        if recorder is not None:
            recorder.close()


async def get_js_completions(jsshell: "JsShell", obj: str, prefix: str) -> AsyncIterator[Completion]:
    if obj in JS_RESERVED_WORDS:
        return

    try:
        completions = await jsshell.evaluate_expression(SCRIPT.substitute(object=obj), return_by_value=True)
        for key in sorted(completions, key=str.lower):
            if not key.startswith(prefix):
                continue
            kind = completions[key]
            yield Completion(
                key.removeprefix(prefix),
                display=key,
                display_meta="ƒ" if kind == "function" else "",
            )
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
    ) -> AsyncGenerator[Completion, None]:
        # Build the JS expression we want to inspect
        text = f"globalThis.{document.text_before_cursor}"

        # Extract identifiers / dotted paths ($ is a legal JS identifier character)
        matches = re.findall(r"[a-zA-Z_$][a-zA-Z_$0-9.]+", text)
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
        self.prompt_session: PromptSession[str] = PromptSession(
            lexer=PygmentsLexer(cast(Any, lexers).JavascriptLexer),
            auto_suggest=AutoSuggestFromHistory(),
            style=style_from_pygments_cls(cast(Any, _pygments_styles).get_style_by_name("stata-dark")),
            history=FileHistory(self.webinspector_history_path()),
            completer=JsShellCompleter(self),
        )

    @classmethod
    @abstractmethod
    def create(
        cls,
        lockdown: LockdownServiceProvider,
        timeout: float,
        open_safari: bool,
        bundle_identifier: Optional[str] = None,
        **kwargs: Any,
    ) -> "AbstractAsyncContextManager[JsShell]": ...

    @abstractmethod
    async def evaluate_expression(self, exp: str, return_by_value: bool = False) -> Any: ...

    @abstractmethod
    async def navigate(self, url: str) -> None: ...

    async def js_iter(self) -> None:
        with patch_stdout(True):
            exp = await self.prompt_session.prompt_async(HTML('<style fg="cyan"><b>&gt;</b></style> '))

        if not exp.strip():
            return

        result = await self.evaluate_expression(exp)
        colorful_result = cast(
            str,
            highlight(
                f"{result}",
                cast(Any, lexers).JavascriptLexer(),
                cast(Any, formatters).Terminal256Formatter(style="stata-dark"),
            ),
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
        cls,
        lockdown: LockdownServiceProvider,
        timeout: float,
        open_safari: bool,
        bundle_identifier: Optional[str] = None,
        **kwargs: Any,
    ) -> "AsyncGenerator[AutomationJsShell, None]":
        if bundle_identifier is None:
            bundle_identifier = SAFARI
        async with webinspector_service(lockdown) as inspector:
            application = await inspector.open_app(bundle_identifier)
            automation_session = await inspector.automation_session(application)
            driver = WebDriver(automation_session)
            await driver.start_session()
            try:
                yield cls(driver)
            finally:
                await automation_session.stop_session()

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
        cls,
        lockdown: LockdownServiceProvider,
        timeout: float,
        open_safari: bool,
        bundle_identifier: Optional[str] = None,
        *,
        console_enable: bool = True,
        **kwargs: Any,
    ) -> "AsyncGenerator[InspectorJsShell, None]":
        async with webinspector_service(lockdown) as inspector:
            if open_safari:
                _ = await inspector.open_app(SAFARI)
            application_page = await cls.query_page(
                inspector, bundle_identifier=SAFARI if open_safari else bundle_identifier
            )
            if application_page is None:
                raise typer.Exit()

            inspector_session = await inspector.inspector_session(application_page.application, application_page.page)
            if console_enable:
                await inspector_session.console_enable()
            await inspector_session.runtime_enable()

            yield cls(inspector_session)

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
            logger.error(
                "Unable to find available pages, try different filters or try to unlock the page"
                if bundle_identifier is not None
                else "Unable to find available pages (try to unlock the page)"
            )
            return None

        if len(available_pages) == 1:
            return available_pages[0]

        return prompt_selection(available_pages, "choose page")


async def run_js_shell(
    js_shell_class: type[JsShell],
    lockdown: LockdownServiceProvider,
    timeout: float,
    url: str,
    open_safari: bool,
    bundle_identifier: Optional[str] = None,
    **create_kwargs: Any,
) -> None:
    async with js_shell_class.create(
        lockdown, timeout, open_safari, bundle_identifier, **create_kwargs
    ) as js_shell_instance:
        await js_shell_instance.start(url)
