import time

import click
import IPython

from pymobiledevice3.cli.cli_common import Command, wait_return
from pymobiledevice3.exceptions import WirError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.webinspector import WebinspectorService, SAFARI
from pymobiledevice3.services.web_protocol.driver import WebDriver, Cookie, By


@click.group()
def cli():
    """ webinspector cli """
    pass


@cli.group()
def webinspector():
    """ webinspector options """
    pass


@webinspector.command(cls=Command)
def opened_tabs(lockdown: LockdownClient):
    """
    Show All opened tabs.
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector
    """
    inspector = WebinspectorService(lockdown=lockdown)
    with inspector.connect():
        # Best effort.
        time.sleep(1)
        apps = inspector.get_open_pages()
        for app_name in apps:
            print(app_name)
            for page in apps[app_name]:
                print(f' - {page.web_url}')


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
    with inspector.connect():
        safari = inspector.open_app(SAFARI)
        with inspector.automation_session(safari) as session:
            driver = WebDriver(session)
            driver.start_session()
            driver.get(url)
            wait_return()


@webinspector.command(cls=Command)
def shell(lockdown: LockdownClient):
    """
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector

        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector = WebinspectorService(lockdown=lockdown)
    with inspector.connect():
        safari = inspector.open_app(SAFARI)
        with inspector.automation_session(safari) as session:
            driver = WebDriver(session)
            IPython.embed(user_ns={
                'driver': driver,
                'Cookie': Cookie,
                'By': By,
            })


@webinspector.command(cls=Command)
@click.argument('url', required=False, default='')
def jsshell(lockdown: LockdownClient, url):
    """
    Opt in:

        Settings -> Safari -> Advanced -> Web Inspector

        Settings -> Safari -> Advanced -> Remote Automation
    """
    inspector = WebinspectorService(lockdown=lockdown)
    with inspector.connect():
        safari = inspector.open_app(SAFARI)
        with inspector.automation_session(safari) as session:
            driver = WebDriver(session)
            driver.start_session()
            if url:
                driver.get(url)
            while True:
                exp = input('> ')
                try:
                    print(driver.execute_script(f'return {exp}'))
                except WirError as e:
                    print(e)
