import asyncio
import logging
from functools import update_wrapper

import IPython
import click
import inquirer
import uvicorn
from inquirer.themes import GreenPassion
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import style_from_pygments_cls
from pygments import highlight, lexers, formatters
from pygments.styles import get_style_by_name

from pymobiledevice3.cli.cli_common import Command, wait_return
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import WirError, InspectorEvaluateError, LaunchingApplicationError, \
    WebInspectorNotEnabledError, RemoteAutomationNotEnabledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.cdp_server import app
from pymobiledevice3.services.web_protocol.driver import WebDriver, Cookie, By
from pymobiledevice3.services.webinspector import WebinspectorService, SAFARI, Application, Page

logger = logging.getLogger(__name__)


def get_prompt_session() -> PromptSession:
    webinspector_history_file = get_home_folder() / 'webinspector_history'
    return PromptSession(lexer=PygmentsLexer(lexers.JavascriptLexer), auto_suggest=AutoSuggestFromHistory(),
                         style=style_from_pygments_cls(get_style_by_name('stata-dark')),
                         history=FileHistory(str(webinspector_history_file)))


def print_colorful_javascript(result: str):
    colorful_result = highlight(f'{result}', lexers.JavascriptLexer(),
                                formatters.TerminalTrueColorFormatter(style='stata-dark'))
    print(colorful_result, end='')


@click.group()
def cli():
    """ webinspector cli """
    pass


@cli.group()
def webinspector():
    """ webinspector options """
    pass


def catch_errors(func):
    def catch_function(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except LaunchingApplicationError:
            logger.error('Unable to launch application (try to unlock device)')
        except WebInspectorNotEnabledError:
            logger.error('Web inspector is not enable')
        except RemoteAutomationNotEnabledError:
            logger.error('Remote automation is not enable')

    return update_wrapper(catch_function, func)


def reload_pages(inspector: WebinspectorService):
    inspector.get_open_pages()
    # Best effort.
    inspector.flush_input(2)


@webinspector.command(cls=Command)
@click.option('-v', '--verbose', is_flag=True)
@click.option('-t', '--timeout', default=3, show_default=True, type=float)
@catch_errors
def opened_tabs(lockdown: LockdownClient, verbose, timeout):
    """
    Show All opened tabs.
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector
    """
    inspector = WebinspectorService(lockdown=lockdown, loop=asyncio.get_event_loop())
    inspector.connect(timeout)
    while not inspector.connected_application:
        inspector.flush_input()
    reload_pages(inspector)
    for app_id, app_ in inspector.connected_application.items():
        if app_id not in inspector.application_pages:
            continue
        if verbose:
            print(f'{app_.name}    id: {app_id}')
        else:
            print(app_.name)
        for page_id, page in inspector.application_pages[app_id].items():
            if verbose:
                print(f' - {page.web_url}    id: {page_id}')
            else:
                print(f' - {page.web_url}')
    inspector.close()


@webinspector.command(cls=Command)
@click.argument('url')
@click.option('-t', '--timeout', default=3, show_default=True, type=float)
@catch_errors
def launch(lockdown: LockdownClient, url, timeout):
    """
    Open a specific URL in Safari.
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector

        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect(timeout)
    safari = inspector.open_app(SAFARI)
    session = inspector.automation_session(safari)
    driver = WebDriver(session)
    print('Starting session')
    driver.start_session()
    print('Getting URL')
    driver.get(url)
    wait_return()
    session.stop_session()
    inspector.close()


SHELL_USAGE = '''
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
'''


@webinspector.command(cls=Command)
@click.option('-t', '--timeout', default=3, show_default=True, type=float)
@catch_errors
def shell(lockdown: LockdownClient, timeout):
    """
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector

        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect(timeout)
    safari = inspector.open_app(SAFARI)
    session = inspector.automation_session(safari)
    driver = WebDriver(session)
    try:
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'driver': driver,
                'Cookie': Cookie,
                'By': By,
            })
    finally:
        session.stop_session()
        inspector.close()


def automation_js_shell(inspector: WebinspectorService, app: Application, url: str = ''):
    automation_session = inspector.automation_session(app)

    driver = WebDriver(automation_session)
    try:
        driver.start_session()
        if url:
            driver.get(url)

        asyncio.run(automation_js_loop(driver))
    finally:
        automation_session.stop_session()
        inspector.close()


async def automation_js_loop(driver: WebDriver):
    prompt_session = get_prompt_session()
    while True:
        try:
            with patch_stdout(True):
                exp = await prompt_session.prompt_async(HTML('<style fg="cyan"><b>&gt;</b></style> '))

            if not exp.strip():
                continue

            result = driver.execute_script(f'return {exp}')
            print_colorful_javascript(result)
        except WirError as e:
            logger.error(e)
        except KeyboardInterrupt:
            pass
        except EOFError:  # Control-D
            break


def inspector_js_shell(inspector: WebinspectorService, app: Application, url: str = ''):
    reload_pages(inspector)
    available_pages = list(inspector.get_open_pages().get('Safari', []))
    if not available_pages:
        logger.error('Unable to find available pages (try to unlock device)')
        return
    else:
        page_query = [inquirer.List('page', message='choose page', choices=available_pages, carousel=True)]
        page = inquirer.prompt(page_query, theme=GreenPassion(), raise_keyboard_interrupt=True)['page']

    asyncio.run(inspector_js_loop(inspector, app, page, url))


async def inspector_js_loop(inspector: WebinspectorService, app: Application, page: Page, url: str = ''):
    inspector_session = await inspector.inspector_session(app, page)
    await inspector_session.runtime_enable()
    if url:
        await inspector_session.navigate_to_url(url)

    prompt_session = get_prompt_session()
    while True:
        try:
            with patch_stdout(True):
                exp = await prompt_session.prompt_async(HTML('<style fg="cyan"><b>&gt;</b></style> '))

            if not exp.strip():
                continue

            result = await inspector_session.runtime_evaluate(exp)
            print_colorful_javascript(result)

        except (KeyboardInterrupt, InspectorEvaluateError):  # KeyboardInterrupt Control-C
            pass
        except EOFError:  # Control-D
            return


@webinspector.command(cls=Command)
@click.option('-t', '--timeout', default=3, show_default=True, type=float)
@click.option('--automation', is_flag=True, help='Use remote automation')
@click.argument('url', required=False, default='')
@catch_errors
def js_shell(lockdown: LockdownClient, timeout, automation, url):
    """
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector

    for automation also enable:

        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect(timeout)
    safari_app = inspector.open_app(SAFARI)

    if automation:
        automation_js_shell(inspector, safari_app, url)
    else:
        inspector_js_shell(inspector, safari_app, url)


udid = ''


def create_app():
    inspector = WebinspectorService(lockdown=LockdownClient(udid))
    app.state.inspector = inspector
    return app


@webinspector.command(cls=Command)
@click.option('--host', default='127.0.0.1')
@click.option('--port', type=click.INT, default=9222)
def cdp(lockdown: LockdownClient, host, port):
    global udid
    udid = lockdown.udid
    uvicorn.run('pymobiledevice3.cli.webinspector:create_app', host=host, port=port, factory=True,
                ws_ping_timeout=None, ws='wsproto', loop='asyncio')
