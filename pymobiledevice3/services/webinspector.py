from contextlib import contextmanager
from dataclasses import dataclass, fields
from enum import Enum
import logging
import ssl
import uuid
import json

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.web_protocol.automation_session import AutomationSession

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

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)
        self.connection_id = str(uuid.uuid4()).upper()
        self.state = None
        self.connected_application = {}
        self.application_pages = {}
        self.wir_message_results = {}
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

    @contextmanager
    def connect(self):
        self._report_identifier()
        try:
            yield
        finally:
            self.service.close()

    @contextmanager
    def automation_session(self, app):
        session_id = str(uuid.uuid4()).upper()
        self._forward_automation_session_request(session_id, app.id_)
        self._forward_get_listing(app.id_)
        page = self._wait_for_page(session_id)
        self._forward_socket_setup(session_id, app.id_, page.id_)
        self._forward_get_listing(app.id_)
        while not page.automation_connection_id:
            self.flush_input()
        session = AutomationSession(SessionProtocol(self, session_id, app, page))
        try:
            yield session
        finally:
            session.stop_session()

    def get_open_pages(self):
        apps = {}
        for app in self.connected_application:
            self._forward_get_listing(app)
            if self.application_pages.get(app, False):
                apps[self.connected_application[app].name] = self.application_pages[app].values()
        return apps

    def open_app(self, bundle) -> Application:
        self._request_application_launch(bundle)
        self.get_open_pages()
        return self._wait_for_application(bundle)

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

    def _handle_application_disconnected(self, arg):
        del self.connected_application[arg['WIRApplicationIdentifierKey']]
        del self.application_pages[arg['WIRApplicationIdentifierKey']]

    def _report_identifier(self):
        self._send_message('_rpc_reportIdentifier:')

    def _forward_get_listing(self, app_id):
        self.logger.debug(f'Listing app with id {app_id}')
        self._send_message('_rpc_forwardGetListing:', {'WIRApplicationIdentifierKey': app_id})

    def _request_application_launch(self, bundle):
        self._send_message('_rpc_requestApplicationLaunch:', {'WIRApplicationBundleIdentifierKey': bundle})

    def _forward_automation_session_request(self, session_id, app_id):
        self._send_message('_rpc_forwardAutomationSessionRequest:', {
            'WIRApplicationIdentifierKey': app_id,
            'WIRSessionCapabilitiesKey': {
                'org.webkit.webdriver.webrtc.allow-insecure-media-capture': True,
                'org.webkit.webdriver.webrtc.suppress-ice-candidate-filtering': False,
            },
            'WIRSessionIdentifierKey': session_id
        })

    def _forward_socket_setup(self, session_id, app_id, page_id):
        self._send_message('_rpc_forwardSocketSetup:', {
            'WIRApplicationIdentifierKey': app_id,
            'WIRPageIdentifierKey': page_id,
            'WIRSenderKey': session_id
        })

    def forward_socket_data(self, session_id, app_id, page_id, data):
        self._send_message('_rpc_forwardSocketData:', {
            'WIRApplicationIdentifierKey': app_id,
            'WIRPageIdentifierKey': page_id,
            'WIRSessionIdentifierKey': session_id,
            'WIRSocketDataKey': json.dumps(data).encode(),
        })

    def _send_message(self, selector, args=None):
        if args is None:
            args = {}
        args['WIRConnectionIdentifierKey'] = self.connection_id
        self.service.send_plist({'__selector': selector, '__argument': args})

    def flush_input(self):
        self.service.setblocking(False)
        try:
            while True:
                self._handle_recv(self.service.recv_plist())
        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        finally:
            self.service.setblocking(True)

    def _page_by_automation_session(self, session_id):
        for app_id in self.application_pages:
            for page in self.application_pages[app_id]:
                if page.type_ == WirTypes.AUTOMATION and page.automation_session_id == session_id:
                    return page

    def _wait_for_page(self, session_id):
        while True:
            for app in self.application_pages.values():
                for page in app.values():
                    if page.type_ == WirTypes.AUTOMATION and page.automation_session_id == session_id:
                        return page
            self.flush_input()

    def _wait_for_application(self, bundle):
        while True:
            for app in self.connected_application.values():
                if app.bundle == bundle:
                    return app
            self.flush_input()
