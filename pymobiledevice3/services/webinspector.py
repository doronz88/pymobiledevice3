import asyncio
from dataclasses import dataclass, fields
from enum import Enum
import logging
import uuid
import json

import nest_asyncio

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.web_protocol.automation_session import AutomationSession
from pymobiledevice3.exceptions import WebInspectorNotEnabled, RemoteAutomationNotEnabled

SAFARI = 'com.apple.mobilesafari'


def key_to_pid(key):
    return int(key.split(':')[1])


class WirTypes(Enum):
    AUTOMATION = 'WIRTypeAutomation'
    ITML = 'WIRTypeITML'
    JAVASCRIPT = 'WIRTypeJavaScript'
    PAGE = 'WIRTypePage'
    SERVICE_WORKER = 'WIRTypeServiceWorker'
    WEB = 'WIRTypeWeb'
    WEB_PAGE = 'WIRTypeWebPage'
    AUTOMATICALLY_PAUSE = 'WIRAutomaticallyPause'


class AutomationAvailability(Enum):
    NOT_AVAILABLE = 'WIRAutomationAvailabilityNotAvailable'
    AVAILABLE = 'WIRAutomationAvailabilityAvailable'
    UNKNOWN = 'WIRAutomationAvailabilityUnknown'


@dataclass
class Page:
    id_: int
    type_: WirTypes
    web_url: str = ''
    web_title: str = ''
    automation_is_paired_key: bool = False
    automation_name: str = ''
    automation_version: str = ''
    automation_session_id: str = ''
    automation_connection_id: str = ''

    @classmethod
    def from_page_dictionary(cls, page_dict):
        p = cls(page_dict['WIRPageIdentifierKey'], WirTypes(page_dict['WIRTypeKey']))
        if p.type_ in (WirTypes.WEB, WirTypes.WEB_PAGE):
            p.web_title = page_dict['WIRTitleKey']
            p.web_url = page_dict['WIRURLKey']
        if p.type_ == WirTypes.AUTOMATION:
            p.automation_is_paired_key = page_dict['WIRAutomationTargetIsPairedKey']
            p.automation_name = page_dict['WIRAutomationTargetNameKey']
            p.automation_version = page_dict['WIRAutomationTargetVersionKey']
            p.automation_session_id = page_dict['WIRSessionIdentifierKey']
            if 'WIRConnectionIdentifierKey' in page_dict:
                p.automation_connection_id = page_dict['WIRConnectionIdentifierKey']
        return p

    def update(self, page_dict):
        new_p = self.from_page_dictionary(page_dict)
        for field in fields(self):
            setattr(self, field.name, getattr(new_p, field.name))


@dataclass
class Application:
    id_: str
    bundle: str
    pid: int
    name: str
    availability: AutomationAvailability
    active: int
    proxy: bool
    ready: bool
    host: str = ''

    @classmethod
    def from_application_dictionary(cls, app_dict):
        return cls(
            app_dict['WIRApplicationIdentifierKey'],
            app_dict['WIRApplicationBundleIdentifierKey'],
            key_to_pid(app_dict['WIRApplicationIdentifierKey']),
            app_dict['WIRApplicationNameKey'],
            AutomationAvailability(app_dict['WIRAutomationAvailabilityKey']),
            app_dict['WIRIsApplicationActiveKey'],
            app_dict['WIRIsApplicationProxyKey'],
            app_dict['WIRIsApplicationReadyKey'],
            app_dict.get('WIRHostApplicationIdentifierKey', ''),
        )


class WebinspectorService:
    SERVICE_NAME = 'com.apple.webinspector'

    def __init__(self, lockdown: LockdownClient, loop=None):
        if loop is None:
            try:
                # When deprecating python3.6, replace with get_running_loop.
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()

        nest_asyncio.apply()
        self.loop = loop
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = None  # type: ServiceConnection
        self.connection_id = str(uuid.uuid4()).upper()
        self.state = None
        self.connected_application = {}
        self.application_pages = {}
        self.wir_message_results = {}
        self.wir_events = []
        self.receive_handlers = {
            '_rpc_reportCurrentState:': self._handle_report_current_state,
            '_rpc_reportConnectedApplicationList:': self._handle_report_connected_application_list,
            '_rpc_reportConnectedDriverList:': self._handle_report_connected_driver_list,
            '_rpc_applicationSentListing:': self._handle_application_sent_listing,
            '_rpc_applicationUpdated:': self._handle_application_updated,
            '_rpc_applicationConnected:': self._handle_application_connected,
            '_rpc_applicationSentData:': self._handle_application_sent_data,
            '_rpc_applicationDisconnected:': self._handle_application_disconnected,
        }
        self._recv_task = None  # type: asyncio.Task | None

    def connect(self, timeout=None):
        self.service = self.await_(self.lockdown.aio_start_service(self.SERVICE_NAME))
        self.await_(self._report_identifier())
        try:
            self._handle_recv(self.await_(asyncio.wait_for(self._recv_message(), timeout)))
        except asyncio.TimeoutError as e:
            raise WebInspectorNotEnabled from e
        self._recv_task = self.loop.create_task(self._receiving_task())

    def close(self):
        self._recv_task.cancel()
        try:
            self.await_(self._recv_task)
        except asyncio.CancelledError:
            pass
        self.await_(self.service.aio_close())

    async def _recv_message(self):
        while True:
            try:
                return await self.service.aio_recv_plist()
            except asyncio.IncompleteReadError:
                await asyncio.sleep(0)

    async def _receiving_task(self):
        while True:
            self._handle_recv(await self._recv_message())

    def automation_session(self, app):
        if self.state == 'WIRAutomationAvailabilityNotAvailable':
            raise RemoteAutomationNotEnabled()
        session_id = str(uuid.uuid4()).upper()
        self.await_(self._forward_automation_session_request(session_id, app.id_))
        self.await_(self._forward_get_listing(app.id_))
        page = self.await_(self._wait_for_page(session_id))
        self.await_(self._forward_socket_setup(session_id, app.id_, page.id_))
        self.await_(self._forward_get_listing(app.id_))
        while not page.automation_connection_id:
            self.await_(asyncio.sleep(0))
        return AutomationSession(SessionProtocol(self, session_id, app, page))

    def get_open_pages(self):
        apps = {}
        self.await_(asyncio.gather(*[self._forward_get_listing(app) for app in self.connected_application]))
        for app in self.connected_application:
            if self.application_pages.get(app, False):
                apps[self.connected_application[app].name] = self.application_pages[app].values()
        return apps

    def open_app(self, bundle) -> Application:
        self.await_(self._request_application_launch(bundle))
        self.get_open_pages()
        return self.await_(self._wait_for_application(bundle))

    async def send_socket_data(self, session_id, app_id, page_id, data):
        await self._forward_socket_data(session_id, app_id, page_id, data)

    async def start_cdp(self, session_id, app_id, page_id):
        await self._forward_socket_setup(session_id, app_id, page_id, pause=False)

    def find_page_id(self, page_id):
        for app_id in self.application_pages:
            for page in self.application_pages[app_id]:
                if page == page_id:
                    return self.connected_application[app_id], self.application_pages[app_id][page_id]

    def flush_input(self, duration=0):
        return self.await_(asyncio.sleep(duration))

    def await_(self, awaitable):
        return self.loop.run_until_complete(asyncio.ensure_future(awaitable, loop=self.loop))

    def _handle_recv(self, plist):
        self.receive_handlers[plist['__selector']](plist['__argument'])

    def _handle_report_current_state(self, arg):
        self.state = arg['WIRAutomationAvailabilityKey']

    def _handle_report_connected_application_list(self, arg):
        self.connected_application = {}
        for key, application in arg['WIRApplicationDictionaryKey'].items():
            self.connected_application[key] = Application.from_application_dictionary(application)

    def _handle_report_connected_driver_list(self, arg):
        pass

    def _handle_application_sent_listing(self, arg):
        if arg['WIRApplicationIdentifierKey'] in self.application_pages:
            for id_, page in arg['WIRListingKey'].items():
                if id_ in self.application_pages[arg['WIRApplicationIdentifierKey']]:
                    self.application_pages[arg['WIRApplicationIdentifierKey']][id_].update(page)
                else:
                    self.application_pages[arg['WIRApplicationIdentifierKey']][id_] = Page.from_page_dictionary(page)
        else:
            pages = {}
            for id_, page in arg['WIRListingKey'].items():
                pages[id_] = Page.from_page_dictionary(page)
            self.application_pages[arg['WIRApplicationIdentifierKey']] = pages

    def _handle_application_updated(self, arg):
        app = Application.from_application_dictionary(arg)
        self.connected_application[app.id_] = app

    def _handle_application_connected(self, arg):
        app = Application.from_application_dictionary(arg)
        self.connected_application[app.id_] = app

    def _handle_application_sent_data(self, arg):
        response = json.loads(arg['WIRMessageDataKey'])
        if 'id' in response:
            self.wir_message_results[response['id']] = response
        else:
            self.wir_events.append(response)

    def _handle_application_disconnected(self, arg):
        self.connected_application.pop(arg['WIRApplicationIdentifierKey'], None)
        self.application_pages.pop(arg['WIRApplicationIdentifierKey'], None)

    async def _report_identifier(self):
        await self._send_message('_rpc_reportIdentifier:')

    async def _forward_get_listing(self, app_id):
        self.logger.debug(f'Listing app with id {app_id}')
        await self._send_message('_rpc_forwardGetListing:', {'WIRApplicationIdentifierKey': app_id})

    async def _request_application_launch(self, bundle):
        await self._send_message('_rpc_requestApplicationLaunch:', {'WIRApplicationBundleIdentifierKey': bundle})

    async def _forward_automation_session_request(self, session_id, app_id):
        await self._send_message('_rpc_forwardAutomationSessionRequest:', {
            'WIRApplicationIdentifierKey': app_id,
            'WIRSessionCapabilitiesKey': {
                'org.webkit.webdriver.webrtc.allow-insecure-media-capture': True,
                'org.webkit.webdriver.webrtc.suppress-ice-candidate-filtering': False,
            },
            'WIRSessionIdentifierKey': session_id
        })

    async def _forward_socket_setup(self, session_id, app_id, page_id, pause=True):
        message = {
            'WIRApplicationIdentifierKey': app_id,
            'WIRPageIdentifierKey': page_id,
            'WIRSenderKey': session_id
        }
        if not pause:
            message['WIRAutomaticallyPause'] = False
        await self._send_message('_rpc_forwardSocketSetup:', message)

    async def _forward_socket_data(self, session_id, app_id, page_id, data):
        await self._send_message('_rpc_forwardSocketData:', {
            'WIRApplicationIdentifierKey': app_id,
            'WIRPageIdentifierKey': page_id,
            'WIRSessionIdentifierKey': session_id,
            'WIRSocketDataKey': json.dumps(data).encode(),
        })

    async def _forward_indicate_web_view(self, app_id, page_id, enable: bool):
        await self._send_message('_rpc_forwardIndicateWebView'), {
            'WIRApplicationIdentifierKey': app_id,
            'WIRPageIdentifierKey': page_id,
            'WIRIndicateEnabledKey': enable,
        }

    async def _send_message(self, selector, args=None):
        if args is None:
            args = {}
        args['WIRConnectionIdentifierKey'] = self.connection_id
        await self.service.aio_send_plist({'__selector': selector, '__argument': args})

    def _page_by_automation_session(self, session_id):
        for app_id in self.application_pages:
            for page in self.application_pages[app_id]:
                if page.type_ == WirTypes.AUTOMATION and page.automation_session_id == session_id:
                    return page

    async def _wait_for_page(self, session_id):
        while True:
            for app in self.application_pages.values():
                for page in app.values():
                    if page.type_ == WirTypes.AUTOMATION and page.automation_session_id == session_id:
                        return page
            await asyncio.sleep(0)

    async def _wait_for_application(self, bundle='', app_id=''):
        while True:
            for app in self.connected_application.values():
                if bundle and app.bundle == bundle:
                    return app
                if app_id and app.id_ == app_id:
                    return app
            await asyncio.sleep(0)
