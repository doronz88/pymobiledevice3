import asyncio
import logging

import IPython
import click
import inquirer
import uvicorn
from inquirer.themes import GreenPassion
from pygments import highlight, lexers, formatters

from pymobiledevice3.cli.cli_common import Command, wait_return
from pymobiledevice3.cli.cli_common import print_json
from pymobiledevice3.exceptions import WirError, InspectorEvaluateError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.cdp_server import app
from pymobiledevice3.services.web_protocol.driver import WebDriver, Cookie, By
from pymobiledevice3.services.webinspector import WebinspectorService, SAFARI, Application, Page

logger = logging.getLogger(__name__)

@click.group()
def cli():
    """ webinspector cli """
    pass


@cli.group()
def webinspector():
    """ webinspector options """
    pass


def reload_pages(inspector: WebinspectorService):
    inspector.get_open_pages()
    # Best effort.
    inspector.flush_input(2)


@webinspector.command(cls=Command)
@click.option('-v', '--verbose', is_flag=True)
def opened_tabs(lockdown: LockdownClient, verbose):
    """
    Show All opened tabs.
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector
    """
    inspector = WebinspectorService(lockdown=lockdown, loop=asyncio.get_event_loop())
    inspector.connect()
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
def launch(lockdown: LockdownClient, url):
    """
    Open a specific URL in Safari.
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector

        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect()
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
def shell(lockdown: LockdownClient):
    """
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector

        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect()
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


@webinspector.command(cls=Command)
@click.argument('url', required=False, default='')
@click.option('-t', '--timeout', default=3, show_default=True, type=float)
def automation_jsshell(lockdown: LockdownClient, url, timeout):
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
        driver.start_session()
        if url:
            driver.get(url)
        while True:
            exp = input('> ')
            try:
                print(driver.execute_script(f'return {exp}'))
            except WirError as e:
                print(e)
    finally:
        session.stop_session()
        inspector.close()


async def inspector_js_loop(inspector: WebinspectorService, app: Application, page: Page):
    inspector_session = await inspector.inspector_session(app, page)
    await inspector_session.runtime_enable()
    while True:
        exp = input('> ')
        try:
            print_json(await inspector_session.runtime_evaluate(exp))
        except InspectorEvaluateError:
            pass
        except NotImplementedError:
            pass


@webinspector.command(cls=Command)
@click.option('-t', '--timeout', default=3, show_default=True, type=float)
def inspector_jsshell(lockdown: LockdownClient, timeout):
    """
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector
    """
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect(timeout)
    try:
        safari_app = inspector.open_app(SAFARI)
    except TimeoutError:
        logger.error(f'Unable to launch application by bundle `{SAFARI}`')
        return

    reload_pages(inspector)
    available_pages = (list(inspector.get_open_pages().get('Safari', [])))
    if not available_pages:
        logger.error('Unable to find available pages (try to unlock device)')
        return
    else:
        page_query = [inquirer.List('page', message='choose page', choices=available_pages, carousel=True)]
        try:
            page = inquirer.prompt(page_query, theme=GreenPassion(), raise_keyboard_interrupt=True)['page']
        except KeyboardInterrupt:
            raise

    asyncio.run(inspector_js_loop(inspector, safari_app, page))


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
