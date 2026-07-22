import asyncio
import contextlib
import json
import uuid
from dataclasses import dataclass, fields
from enum import Enum
from typing import Optional, Union

from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    LaunchingApplicationError,
    RemoteAutomationNotEnabledError,
    WebInspectorNotEnabledError,
)
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.services.notification_proxy import NotificationProxyService
from pymobiledevice3.services.web_protocol.automation_session import AutomationSession
from pymobiledevice3.services.web_protocol.inspector_session import InspectorSession
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol

SAFARI = "com.apple.mobilesafari"
WEBINSPECTORD_DISABLED_NOTIFICATION = "com.apple.webinspectord.disabled"


def key_to_pid(key: str) -> int:
    return int(key.split(":")[1])


class WirTypes(Enum):
    AUTOMATION = "WIRTypeAutomation"
    ITML = "WIRTypeITML"
    JAVASCRIPT = "WIRTypeJavaScript"
    PAGE = "WIRTypePage"
    SERVICE_WORKER = "WIRTypeServiceWorker"
    WEB = "WIRTypeWeb"
    WEB_PAGE = "WIRTypeWebPage"
    AUTOMATICALLY_PAUSE = "WIRAutomaticallyPause"


class AutomationAvailability(Enum):
    NOT_AVAILABLE = "WIRAutomationAvailabilityNotAvailable"
    AVAILABLE = "WIRAutomationAvailabilityAvailable"
    UNKNOWN = "WIRAutomationAvailabilityUnknown"


@dataclass
class Page:
    """A single inspectable target (web page, automation target, etc.) reported by an application."""

    id_: int
    type_: WirTypes
    web_url: str = ""
    web_title: str = ""
    automation_is_paired_key: bool = False
    automation_name: str = ""
    automation_version: str = ""
    automation_session_id: str = ""
    automation_connection_id: str = ""

    @classmethod
    def from_page_dictionary(cls, page_dict: dict) -> "Page":
        p = cls(page_dict["WIRPageIdentifierKey"], WirTypes(page_dict["WIRTypeKey"]))
        if p.type_ in (WirTypes.WEB, WirTypes.WEB_PAGE):
            p.web_title = page_dict["WIRTitleKey"]
            p.web_url = page_dict["WIRURLKey"]
        if p.type_ == WirTypes.AUTOMATION:
            p.automation_is_paired_key = page_dict["WIRAutomationTargetIsPairedKey"]
            p.automation_name = page_dict["WIRAutomationTargetNameKey"]
            p.automation_version = page_dict["WIRAutomationTargetVersionKey"]
            p.automation_session_id = page_dict["WIRSessionIdentifierKey"]
            if "WIRConnectionIdentifierKey" in page_dict:
                p.automation_connection_id = page_dict["WIRConnectionIdentifierKey"]
        return p

    def update(self, page_dict: dict):
        new_p = self.from_page_dictionary(page_dict)
        for field in fields(self):
            setattr(self, field.name, getattr(new_p, field.name))

    def __str__(self):
        return f"id: {self.id_}, title: {self.web_title}, url: {self.web_url}"


@dataclass
class Application:
    """An application reported by `webinspectord` as available for web inspection or automation."""

    id_: str
    bundle: str
    pid: int
    name: str
    availability: AutomationAvailability
    active: int
    proxy: bool
    ready: bool
    host: str = ""

    @classmethod
    def from_application_dictionary(cls, app_dict) -> "Application":
        return cls(
            app_dict["WIRApplicationIdentifierKey"],
            app_dict["WIRApplicationBundleIdentifierKey"],
            key_to_pid(app_dict["WIRApplicationIdentifierKey"]),
            app_dict["WIRApplicationNameKey"],
            AutomationAvailability(app_dict["WIRAutomationAvailabilityKey"]),
            app_dict["WIRIsApplicationActiveKey"],
            app_dict["WIRIsApplicationProxyKey"],
            app_dict["WIRIsApplicationReadyKey"],
            app_dict.get("WIRHostApplicationIdentifierKey", ""),
        )


@dataclass
class ApplicationPage:
    application: Application
    page: Page

    def __str__(self) -> str:
        return f"<{self.application.name}({self.application.pid}) TYPE:{self.page.type_.value} URL:{self.page.web_url}>"


class WebinspectorService(LockdownService):
    """Client for the `com.apple.webinspector` service (`webinspectord`).

    Drives Safari/WebKit remote inspection and WebDriver automation: enumerates inspectable
    applications and their pages, launches applications, and forwards the inspector/automation
    socket traffic used to build `InspectorSession` and `AutomationSession` objects.

    The service maintains a background receive task that dispatches incoming RPC notifications
    and keeps the cached application/page state up to date. Call `connect` before issuing any
    requests and `close` when done.
    """

    SERVICE_NAME = "com.apple.webinspector"
    RSD_SERVICE_NAME = "com.apple.webinspector.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, self.SERVICE_NAME if isinstance(lockdown, LockdownClient) else self.RSD_SERVICE_NAME)
        self.connection_id = str(uuid.uuid4()).upper()
        self.state = None
        self.connected_application = {}
        self.application_pages = {}
        self.wir_message_results = {}
        self.wir_events = []
        self.receive_handlers = {
            "_rpc_reportCurrentState:": self._handle_report_current_state,
            "_rpc_reportConnectedApplicationList:": self._handle_report_connected_application_list,
            "_rpc_reportConnectedDriverList:": self._handle_report_connected_driver_list,
            "_rpc_applicationSentListing:": self._handle_application_sent_listing,
            "_rpc_applicationUpdated:": self._handle_application_updated,
            "_rpc_applicationConnected:": self._handle_application_connected,
            "_rpc_applicationSentData:": self._handle_application_sent_data,
            "_rpc_applicationDisconnected:": self._handle_application_disconnected,
        }
        self._recv_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        """Establish the WebInspector session and start the background receive task.

        Performs the initial handshake (reporting this client's identifier and processing the
        first reply) while watching for a disabled notification, then spawns the task that keeps
        consuming incoming messages. Safe to call repeatedly; subsequent calls are a no-op once
        the receive task is running.

        :raises WebInspectorNotEnabledError: Web Inspector is disabled on the device.
        """
        if self._recv_task is not None:
            return

        await self._connect_or_raise_disabled()
        self._recv_task = asyncio.create_task(self._receiving_task())

    async def close(self):
        """Cancel the background receive task and close the underlying service connection."""
        if self._recv_task is not None:
            self._recv_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionTerminatedError):
                await self._recv_task
            self._recv_task = None
        await super().close()

    async def _recv_message(self):
        while True:
            try:
                return await self.service.recv_plist()
            except asyncio.IncompleteReadError:
                await asyncio.sleep(0)

    async def _wait_for_disabled_notification(self, notification_proxy: NotificationProxyService) -> None:
        async for event in notification_proxy.receive_notification():
            if event.get("Name") == WEBINSPECTORD_DISABLED_NOTIFICATION:
                raise WebInspectorNotEnabledError

    async def _connect_or_raise_disabled(self) -> None:
        async with NotificationProxyService(self.lockdown) as notification_proxy:
            await notification_proxy.notify_register_dispatch(WEBINSPECTORD_DISABLED_NOTIFICATION)
            disabled_task = asyncio.create_task(self._wait_for_disabled_notification(notification_proxy))
            try:
                # Keep the disabled notification watcher active for the full WebInspector handshake. A disabled
                # device may report either the explicit notification or an abrupt service termination.
                await self._await_or_raise_disabled(super().connect(), disabled_task)
                await self._await_or_raise_disabled(self._report_identifier(), disabled_task)
                await self._handle_recv(await self._await_or_raise_disabled(self._recv_message(), disabled_task))
            finally:
                disabled_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await disabled_task

    async def _await_or_raise_disabled(self, coro, disabled_task: asyncio.Task):
        task = asyncio.create_task(coro)
        done, _ = await asyncio.wait(
            {task, disabled_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if disabled_task in done:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await disabled_task
        try:
            return await task
        except ConnectionTerminatedError as e:
            raise WebInspectorNotEnabledError from e

    async def _receiving_task(self):
        while True:
            await self._handle_recv(await self._recv_message())

    async def automation_session(self, app: Application) -> AutomationSession:
        """Start a WebDriver automation session against an application.

        Requests a new automation session, waits for the corresponding automation page to appear,
        sets up its forwarding socket, and waits until the page reports an automation connection id.

        :param app: The application to automate.
        :returns: A connected automation session.
        :raises RemoteAutomationNotEnabledError: Remote automation is not available on the device.
        """
        if self.state == "WIRAutomationAvailabilityNotAvailable":
            raise RemoteAutomationNotEnabledError()
        session_id = str(uuid.uuid4()).upper()
        await self._forward_automation_session_request(session_id, app.id_)
        await self._forward_get_listing(app.id_)
        page = await self._wait_for_page(session_id)
        await self._forward_socket_setup(session_id, app.id_, page.id_)
        await self._forward_get_listing(app.id_)
        while not page.automation_connection_id:
            await asyncio.sleep(0)
        return AutomationSession(SessionProtocol(self, session_id, app, page))

    async def inspector_session(self, app: Application, page: Page) -> InspectorSession:
        """Open a Web Inspector session against a specific page of an application.

        :param app: The application owning the page.
        :param page: The page to inspect.
        :returns: A connected inspector session. For non-JavaScript pages the session waits for the
            inspection target before returning.
        """
        session_id = str(uuid.uuid4()).upper()
        return await InspectorSession.create(
            SessionProtocol(self, session_id, app, page, method_prefix=""),
            wait_target=page.type_ != WirTypes.JAVASCRIPT,
        )

    async def get_open_pages(self) -> dict:
        """Request and return the currently open pages of all connected applications.

        :returns: A mapping of application name to the collection of its `Page` objects, including
            only applications that currently report at least one page.
        """
        apps = {}
        await asyncio.gather(*[self._forward_get_listing(app) for app in self.connected_application])
        for app in self.connected_application:
            if self.application_pages.get(app, False):
                apps[self.connected_application[app].name] = self.application_pages[app].values()
        return apps

    async def get_open_application_pages(self, timeout: float) -> list[ApplicationPage]:
        """Enumerate all inspectable application/page pairs across connected applications.

        Queries the connected applications and then waits for `webinspectord` to report their
        listings before collecting the results.

        :param timeout: Seconds to wait for the device to reply with the application listings.
        :returns: A list of `ApplicationPage` pairs, one per reported page.
        """
        # Query all connected applications
        await self._get_connected_applications()

        # Give some time for `webinspectord` to reply with all inspectable applications
        await asyncio.sleep(timeout)

        result = []
        for app in self.connected_application:
            if self.application_pages.get(app, False):
                for page in self.application_pages[app].values():
                    result.append(ApplicationPage(self.connected_application[app], page))
        return result

    async def open_app(self, bundle: str, timeout: Union[float, int] = 3) -> Application:
        """Launch an application by bundle identifier and wait for it to connect.

        :param bundle: The bundle identifier of the application to launch.
        :param timeout: Seconds to wait for the application to appear as connected.
        :returns: The connected application.
        :raises LaunchingApplicationError: The application did not connect within the timeout.
        """
        await self._request_application_launch(bundle)
        await self.get_open_pages()
        try:
            return await asyncio.wait_for(self._wait_for_application(bundle), timeout)
        except TimeoutError as e:
            raise LaunchingApplicationError() from e

    async def send_socket_data(self, session_id: str, app_id: str, page_id: int, data: dict):
        """Forward an inspector/automation protocol message to a page's socket.

        :param session_id: The session identifier owning the socket.
        :param app_id: The target application identifier.
        :param page_id: The target page identifier.
        :param data: The protocol message to send; serialized to JSON before forwarding.
        """
        await self._forward_socket_data(session_id, app_id, page_id, data)

    async def setup_inspector_socket(self, session_id: str, app_id: str, page_id: int):
        """Set up a forwarding socket for an inspector session without auto-pausing the target.

        :param session_id: The session identifier to associate with the socket.
        :param app_id: The target application identifier.
        :param page_id: The target page identifier.
        """
        await self._forward_socket_setup(session_id, app_id, page_id, pause=False)

    def find_page_id(self, page_id: str) -> tuple[Application, Page]:
        """Look up the application and page for a known page identifier.

        :param page_id: The page identifier to search for.
        :returns: A tuple of the owning application and the matching page.
        :raises KeyError: No page with the given identifier is currently known.
        """
        for app_id in self.application_pages:
            for page in self.application_pages[app_id]:
                if page == page_id:
                    return self.connected_application[app_id], self.application_pages[app_id][page_id]
        raise KeyError(f"Page with id {page_id} not found")

    async def flush_input(self, duration: Union[float, int] = 0):
        """Yield control for the given duration to let pending incoming messages be processed.

        :param duration: Seconds to sleep while the background receive task drains input.
        """
        return await asyncio.sleep(duration)

    async def _handle_recv(self, plist):
        await self.receive_handlers[plist["__selector"]](plist["__argument"])

    async def _handle_report_current_state(self, arg):
        self.state = arg["WIRAutomationAvailabilityKey"]

    async def _handle_report_connected_application_list(self, arg):
        self.connected_application = {}
        for key, application in arg["WIRApplicationDictionaryKey"].items():
            self.connected_application[key] = Application.from_application_dictionary(application)

            # Immediately also query the application pages
            await self._forward_get_listing(self.connected_application[key].id_)

    async def _handle_report_connected_driver_list(self, arg):
        pass

    async def _handle_application_sent_listing(self, arg):
        if arg["WIRApplicationIdentifierKey"] in self.application_pages:
            # Update existing application pages
            for id_, page in arg["WIRListingKey"].items():
                if id_ in self.application_pages[arg["WIRApplicationIdentifierKey"]]:
                    self.application_pages[arg["WIRApplicationIdentifierKey"]][id_].update(page)
                else:
                    self.application_pages[arg["WIRApplicationIdentifierKey"]][id_] = Page.from_page_dictionary(page)
        else:
            # Add new application pages
            pages = {}
            for id_, page in arg["WIRListingKey"].items():
                pages[id_] = Page.from_page_dictionary(page)
            self.application_pages[arg["WIRApplicationIdentifierKey"]] = pages

    async def _handle_application_updated(self, arg):
        app = Application.from_application_dictionary(arg)
        self.connected_application[app.id_] = app

    async def _handle_application_connected(self, arg):
        app = Application.from_application_dictionary(arg)
        self.connected_application[app.id_] = app

    async def _handle_application_sent_data(self, arg):
        response = json.loads(arg["WIRMessageDataKey"])

        if "id" in response:
            self.wir_message_results[response["id"]] = response
        else:
            self.wir_events.append(response)

    async def _handle_application_disconnected(self, arg):
        self.connected_application.pop(arg["WIRApplicationIdentifierKey"], None)
        self.application_pages.pop(arg["WIRApplicationIdentifierKey"], None)

    async def _report_identifier(self):
        await self._send_message("_rpc_reportIdentifier:")

    async def _forward_get_listing(self, app_id):
        self.logger.debug(f"Listing app with id {app_id}")
        await self._send_message("_rpc_forwardGetListing:", {"WIRApplicationIdentifierKey": app_id})

    async def _request_application_launch(self, bundle: str):
        await self._send_message("_rpc_requestApplicationLaunch:", {"WIRApplicationBundleIdentifierKey": bundle})

    async def _get_connected_applications(self) -> None:
        await self._send_message("_rpc_getConnectedApplications:", {})

    async def _forward_automation_session_request(self, session_id: str, app_id: str):
        await self._send_message(
            "_rpc_forwardAutomationSessionRequest:",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRSessionCapabilitiesKey": {
                    "org.webkit.webdriver.webrtc.allow-insecure-media-capture": True,
                    "org.webkit.webdriver.webrtc.suppress-ice-candidate-filtering": False,
                },
                "WIRSessionIdentifierKey": session_id,
            },
        )

    async def _forward_socket_setup(self, session_id: str, app_id: str, page_id: int, pause: bool = True):
        message = {
            "WIRApplicationIdentifierKey": app_id,
            "WIRPageIdentifierKey": page_id,
            "WIRSenderKey": session_id,
            "WIRMessageDataTypeChunkSupportedKey": 0,
        }
        if not pause:
            message["WIRAutomaticallyPause"] = False
        await self._send_message("_rpc_forwardSocketSetup:", message)

    async def _forward_socket_data(self, session_id: str, app_id: str, page_id: int, data: dict):
        await self._send_message(
            "_rpc_forwardSocketData:",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRPageIdentifierKey": page_id,
                "WIRSessionIdentifierKey": session_id,
                "WIRSenderKey": session_id,
                "WIRSocketDataKey": json.dumps(data).encode(),
            },
        )

    async def _forward_indicate_web_view(self, app_id: str, page_id: int, enable: bool):
        await self._send_message(
            "_rpc_forwardIndicateWebView",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRPageIdentifierKey": page_id,
                "WIRIndicateEnabledKey": enable,
            },
        )

    async def _send_message(self, selector: str, args=None):
        if args is None:
            args = {}
        args["WIRConnectionIdentifierKey"] = self.connection_id
        await self.service.send_plist({"__selector": selector, "__argument": args})

    def _page_by_automation_session(self, session_id: str) -> Page:
        for app_id in self.application_pages:
            for page in self.application_pages[app_id]:
                if page.type_ == WirTypes.AUTOMATION and page.automation_session_id == session_id:
                    return page
        raise KeyError(f"Automation session with id {session_id} not found")

    async def _wait_for_page(self, session_id: str):
        while True:
            for app in self.application_pages.values():
                for page in app.values():
                    if page.type_ == WirTypes.AUTOMATION and page.automation_session_id == session_id:
                        return page
            await asyncio.sleep(0)

    async def _wait_for_application(self, bundle: str = "", app_id: str = "") -> Application:
        while True:
            for app in self.connected_application.values():
                if bundle and app.bundle == bundle:
                    return app
                if app_id and app.id_ == app_id:
                    return app
            await asyncio.sleep(0)
