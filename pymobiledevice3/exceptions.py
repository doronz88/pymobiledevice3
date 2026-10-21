__all__ = [
    "AccessDeniedError",
    "AfcException",
    "AfcFileNotFoundError",
    "AlreadyMountedError",
    "AmfiError",
    "ArbitrationError",
    "ArgumentError",
    "BackupFilterPasswordRequiredError",
    "BadCommandError",
    "BadDevError",
    "CannotStopSessionError",
    "CloudConfigurationAlreadyPresentError",
    "ConnectionFailedError",
    "ConnectionFailedToUsbmuxdError",
    "ConnectionTerminatedError",
    "CoreDeviceError",
    "DeprecationError",
    "DeveloperModeError",
    "DeveloperModeIsNotEnabledError",
    "DeviceAlreadyInUseError",
    "DeviceFeatureNotSupportedError",
    "DeviceHasPasscodeSetError",
    "DeviceNotFoundError",
    "DeviceVersionNotSupportedError",
    "DisableMemoryLimitError",
    "DvtDirListError",
    "DvtException",
    "ExtractingStackshotError",
    "FatalPairingError",
    "FeatureNotSupportedError",
    "GetProhibitedError",
    "IRecvError",
    "IRecvNoDeviceConnectedError",
    "IncorrectModeError",
    "InspectorEvaluateError",
    "InternalError",
    "InvalidConnectionError",
    "InvalidHostIDError",
    "InvalidServiceError",
    "LaunchingApplicationError",
    "LockdownError",
    "MCProtectedError",
    "MessageNotSupportedError",
    "MissingValueError",
    "MuxException",
    "MuxVersionError",
    "NoDeviceConnectedError",
    "NotConnectedError",
    "NotEnoughDiskSpaceError",
    "NotMountedError",
    "NotPairedError",
    "NotTrustedError",
    "NotificationTimeoutError",
    "OSNotSupportedError",
    "PairingDialogResponsePendingError",
    "PairingError",
    "PasscodeRequiredError",
    "PasswordRequiredError",
    "ProcessInspectionError",
    "ProfileError",
    "PskCipherNotSupportedError",
    "PyMobileDevice3Exception",
    "QuicProtocolNotSupportedError",
    "RSDRequiredError",
    "RemoteAutomationNotEnabledError",
    "RemotePairingCompletedError",
    "RemoteXPCHandshakeTimeoutError",
    "ScreencastUnavailableError",
    "SessionActiveError",
    "SetProhibitedError",
    "StartServiceError",
    "SysdiagnoseTimeoutError",
    "TSSError",
    "TraceLagError",
    "TunneldConnectionError",
    "UnrecognizedSelectorError",
    "UnsupportedCommandError",
    "UserDeniedPairingError",
    "UserspaceTunnelUnavailableError",
    "WdaError",
    "WebInspectorNotEnabledError",
    "WirError",
]

import asyncio
import inspect
from typing import Any, ClassVar, Optional, cast

REPORT_ISSUE_URL = "https://github.com/doronz88/pymobiledevice3/issues"


class PyMobileDevice3Exception(Exception):
    """A pymobiledevice3 operation failed."""

    #: The failure means pymobiledevice3 did not understand the other side (a reply or protocol it does
    #: not handle): the message then asks the user to report it.
    WORTH_REPORTING: ClassVar[bool] = False

    def __init__(self, *args: Any) -> None:
        if not args:
            description = self.describe()
            if description is not None:
                args = (description,)
        super().__init__(*args)

    @classmethod
    def describe(cls) -> Optional[str]:
        """What this failure means: the first paragraph of the nearest docstring below this base class."""
        for klass in cls.__mro__:
            if klass is PyMobileDevice3Exception:
                return None
            doc = klass.__dict__.get("__doc__")
            if doc:
                return " ".join(inspect.cleandoc(doc).split("\n\n", 1)[0].split())
        return None

    @property
    def worth_reporting(self) -> bool:
        """Whether the user should report this failure: ``WORTH_REPORTING``, or a bare `PyMobileDevice3Exception`
        (raised where no specific error type exists yet, so nothing tells the user what to do about it)."""
        return self.WORTH_REPORTING or type(self) is PyMobileDevice3Exception

    def __str__(self) -> str:
        message = super().__str__()
        if not self.worth_reporting:
            return message
        return (
            f"{message.rstrip('.') or 'pymobiledevice3 ran into an unexpected error'}.\nPlease report it at {REPORT_ISSUE_URL}, with the output of the same command "
            "run with -v (`pymobiledevice3 -v ...`), so support for it can be added."
        )


class DeviceVersionNotSupportedError(PyMobileDevice3Exception):
    """The device's iOS version does not support this operation."""


class IncorrectModeError(PyMobileDevice3Exception):
    """The device is not in normal mode: lockdownd did not answer as com.apple.mobile.lockdown."""


class NotTrustedError(PyMobileDevice3Exception):
    """The device does not trust this computer."""


class PairingError(PyMobileDevice3Exception):
    """Pairing with the device failed."""


class NotPairedError(PyMobileDevice3Exception):
    """Device is not paired."""


class CannotStopSessionError(PyMobileDevice3Exception):
    """lockdownd did not stop the session."""


class PasswordRequiredError(PairingError):
    """Device is password protected. Please unlock and retry."""


class BackupFilterPasswordRequiredError(PyMobileDevice3Exception):
    """The backup is encrypted, so filtering it needs the backup password."""


class StartServiceError(PyMobileDevice3Exception):
    """The device refused to start the service."""

    def __init__(self, service_name: str, message: str) -> None:
        if message == "ServiceProhibited" and service_name == "com.apple.pcapd.shim.remote":
            description = (
                f"The {service_name} service is USB only (at least for some iOS versions).\n"
                "Full discussion is available in: https://github.com/doronz88/pymobiledevice3/issues/1515"
            )
        else:
            description = f"Failed to start: {service_name} with. Received error: {message}."
        super().__init__(description)
        self.service_name = service_name
        self.message = message


class FatalPairingError(PyMobileDevice3Exception):
    """The device no longer accepts this computer's pairing record. Pair it again."""


class NoDeviceConnectedError(PyMobileDevice3Exception):
    """Device is not connected."""


class NotConnectedError(PyMobileDevice3Exception):
    """The service was used before connecting to it (call connect() or use `async with`)."""


class InterfaceIndexNotFoundError(PyMobileDevice3Exception):
    """No network interface has the requested address."""

    def __init__(self, address: str):
        super().__init__(f"No network interface has the address {address}")
        self.address = address


class DeviceNotFoundError(PyMobileDevice3Exception):
    """No device with the requested UDID was found.

    Every raise site passes a message naming the lookup that failed (usbmux, tunneld,
    remotepairingd, ...) — ``str(exc)`` is therefore self-explanatory — while ``udid`` remains a
    dedicated member so callers can act on the target itself.
    """

    def __init__(self, udid: Optional[str], message: Optional[str] = None) -> None:
        super().__init__(message or f"Device not found: {udid}")
        self.udid = udid


class TunneldConnectionError(PyMobileDevice3Exception):
    """Unable to connect to tunneld. Start one with `sudo python3 -m pymobiledevice3 remote tunneld`."""


class MuxException(PyMobileDevice3Exception):
    """Talking to usbmuxd failed."""


class MuxVersionError(MuxException):
    """usbmuxd answered with a protocol version pymobiledevice3 does not speak."""

    WORTH_REPORTING = True


class BadCommandError(MuxException):
    """usbmuxd rejected the command."""


class BadDevError(MuxException):
    """usbmuxd does not know the device."""


class ConnectionFailedError(MuxException):
    """Failed to connect to service port."""


class ConnectionFailedToUsbmuxdError(ConnectionFailedError):
    """Failed to connect to usbmuxd socket. Make sure it's running."""


class ArgumentError(PyMobileDevice3Exception):
    """An argument is not valid for this operation."""


class AfcException(PyMobileDevice3Exception, OSError):
    """An AFC (file transfer) operation failed.

    ``status`` is the device's AfcError code and ``filename`` the path, when known.
    """

    def __init__(self, message: str, status: Optional[int], filename: Optional[str] = None) -> None:
        # status carries the AfcError code (an IntEnum in services/afc.py, not importable here without a cycle)
        OSError.__init__(self, status, message)
        self.status = status
        self.filename = filename

    def __str__(self) -> str:
        # (not OSError's "[Errno <status>] <message>: <filename>": the message already says what failed)
        if self.status is None:
            return str(self.strerror)
        return f"{str(self.strerror).rstrip('.')} (AFC status {getattr(self.status, 'name', self.status)})."


class AfcFileNotFoundError(AfcException):
    """The file does not exist on the device."""


class DvtException(PyMobileDevice3Exception):
    """A developer (Instruments) operation failed."""


class UnrecognizedSelectorError(DvtException):
    """The device's Instruments service does not know the method that was called."""

    WORTH_REPORTING = True


class DvtDirListError(DvtException):
    """The device could not list the directory."""


class ProcessInspectionError(DvtException):
    """The device could not inspect the process.

    On a production device these services only accept debuggable apps (development-signed, with
    ``get-task-allow``); any other process is refused.
    """

    def __init__(self, pid: int, operation: str, reason: Optional[str] = None) -> None:
        super().__init__(
            f"The device could not {operation} pid {pid}: "
            f"{reason or 'the app must be debuggable (development-signed with get-task-allow)'}"
        )
        #: The process the device was asked to inspect.
        self.pid = pid
        #: The device's own explanation, when it gave one.
        self.reason = reason


class NotMountedError(PyMobileDevice3Exception):
    """The image is not mounted."""


class AlreadyMountedError(PyMobileDevice3Exception):
    """The image is already mounted."""


class MissingManifestError(PyMobileDevice3Exception):
    """The device did not return the mounted image's signature."""


class UnsupportedCommandError(PyMobileDevice3Exception):
    """The device's image mounter does not know this command on this iOS version."""


class TraceLagError(PyMobileDevice3Exception):
    """The live trace fell further behind the device than allowed."""

    def __init__(self, lag: float, max_lag: float) -> None:
        super().__init__(lag, max_lag)
        self.lag = lag
        self.max_lag = max_lag

    def __str__(self) -> str:
        return (
            f"Fell {self.lag:.2f}s behind, more than the max lag ({self.max_lag:g}s). To skip ahead to recent events "
            "instead, pass --skip-behind (or allow more lag with --max-lag, or narrow the trace)"
        )


class ExtractingStackshotError(PyMobileDevice3Exception):
    """The device did not send a complete stackshot."""


class ChannelClosedError(PyMobileDevice3Exception):
    """The channel is closed."""


class ConnectionTerminatedError(PyMobileDevice3Exception):
    """Connection was terminated abruptly."""


class StreamClosedError(ConnectionTerminatedError):
    """The device closed the stream."""


class WebInspectorNotEnabledError(PyMobileDevice3Exception):
    """Web Inspector is disabled. Enable it in Settings > Apps > Safari > Advanced > Web Inspector."""


class ScreencastUnavailableError(PyMobileDevice3Exception):
    """This target cannot be screencast: it has no page to capture."""


class RemoteAutomationNotEnabledError(PyMobileDevice3Exception):
    """Remote Automation is disabled. Enable it in Settings > Apps > Safari > Advanced > Remote Automation."""


class WirError(PyMobileDevice3Exception):
    """A Web Inspector automation command failed."""


class InternalError(PyMobileDevice3Exception):
    """The device reported an internal error.

    ``args[0]`` is the device's reply; its ``DetailedError`` (e.g. "Failed to unload launchd jobs" on
    unmount) becomes the message.
    """

    def __str__(self) -> str:
        # surface the device's DetailedError (e.g. "Failed to unload launchd jobs" on unmount)
        response = cast(dict[str, Any], self.args[0]) if self.args and isinstance(self.args[0], dict) else {}
        detail = str(response.get("DetailedError", ""))
        return f"Internal Error: {detail}" if detail else "Internal Error"


class ArbitrationError(PyMobileDevice3Exception):
    """The device arbitration service refused the request."""


class DeviceAlreadyInUseError(ArbitrationError):
    """Another computer has the device checked out."""

    @property
    def message(self):
        return self.args[0].get("message")

    @property
    def owner(self):
        return self.args[0].get("owner")

    @property
    def result(self):
        return self.args[0].get("result")


class DeveloperModeIsNotEnabledError(PyMobileDevice3Exception):
    """Developer Mode is disabled. You can try to enable it using: python3 -m pymobiledevice3 amfi
    enable-developer-mode
    """


class DeveloperDiskImageNotFoundError(PyMobileDevice3Exception):
    """Could not find a DeveloperDiskImage for this device's iOS version."""


class DeveloperModeError(PyMobileDevice3Exception):
    """Failed to enable Developer Mode."""


class LockdownError(PyMobileDevice3Exception):
    """lockdownd rejected the request.

    ``error`` is lockdownd's error code (e.g. ``SessionInactive``) when raised for one of its replies.
    """

    def __init__(
        self, message: str, identifier: Optional[str], product_version: str, error: Optional[str] = None
    ) -> None:
        super().__init__(message or self.describe())
        #: lockdownd's error code (e.g. ``"SessionInactive"``), when raised for one of its replies
        self.error = error
        # identifier is Optional only to match the base LockdownClient contract (its constructor
        # permits an unknown identifier); every factory-built client (usbmux/TCP/RemoteXPC)
        # populates it. product_version is always set (the lockdown/RSD property never returns None).
        self.identifier = identifier
        self.product_version = product_version


class GetProhibitedError(LockdownError):
    """lockdownd does not allow reading this value."""


class SetProhibitedError(LockdownError):
    """lockdownd does not allow changing this value."""


class PairingDialogResponsePendingError(PairingError):
    """Waiting for the user to answer the Trust dialog on the device."""


class UserDeniedPairingError(PairingError):
    """The user refused to trust this computer."""


class InvalidHostIDError(PairingError):
    """The device does not recognize this computer's pairing record. Pair it again."""


class MissingValueError(LockdownError):
    """No such value."""


class InvalidConnectionError(LockdownError):
    """lockdownd considers the connection no longer valid."""


class PasscodeRequiredError(LockdownError):
    """Unlock the device with its passcode and retry."""


class MCProtectedError(LockdownError):
    """A configuration profile on the device prohibits this action."""


class SessionActiveError(LockdownError):
    """A lockdown session is already active."""


class AmfiError(PyMobileDevice3Exception):
    """AMFI (the device's code-signing service) refused the request."""


class DeviceHasPasscodeSetError(AmfiError):
    """Cannot enable Developer Mode while the device has a passcode set."""


class NotificationTimeoutError(PyMobileDevice3Exception, TimeoutError):
    """Timed out waiting for a notification from the device."""


class RemoteXPCHandshakeTimeoutError(PyMobileDevice3Exception, asyncio.TimeoutError):
    """The service accepted the connection but never answered the handshake.

    Either the service refuses this host (it lacks the entitlement or device state the service
    wants), or its daemon is stuck.
    """

    def __str__(self) -> str:
        what = super().__str__().rstrip(".")
        return (
            f"{what[:1].upper()}{what[1:]}. The service either refuses this host or its daemon is stuck; "
            "restarting the device clears a stuck daemon."
        )


class ProfileError(PyMobileDevice3Exception):
    """The configuration profile request failed."""


class CloudConfigurationAlreadyPresentError(ProfileError):
    """A cloud configuration is already present on the device. Erase the device before installing a new one:
    `pymobiledevice3 profile erase-device`.
    """


class IRecvError(PyMobileDevice3Exception):
    """Talking to the device in Recovery/DFU mode failed."""


class IRecvNoDeviceConnectedError(IRecvError):
    """No device in Recovery or DFU mode is connected."""


class MessageNotSupportedError(PyMobileDevice3Exception):
    """The device replied with a message pymobiledevice3 does not handle.

    ``request`` and ``reply`` are what was sent and what came back, when known.
    """

    WORTH_REPORTING = True

    def __init__(self, request: Optional[str] = None, reply: Any = None) -> None:
        self.request = request
        self.reply = reply
        message = "The device replied with a message pymobiledevice3 does not handle"
        if request is not None:
            message = f"The device replied to {request} with a message pymobiledevice3 does not handle"
        if reply is not None:
            message += f": {reply!r}"
        super().__init__(message)


class InvalidServiceError(LockdownError):
    """The device does not offer the requested service."""


class DeviceFeatureNotSupportedError(LockdownError):
    """The device does not support a feature this operation needs."""

    def __init__(self, service_name: str, feature: str, identifier: Optional[str], product_version: str) -> None:
        super().__init__(
            f"device does not support feature {feature!r} (service {service_name!r}) (iOS {product_version})",
            identifier,
            product_version,
        )
        self.service_name = service_name
        self.feature = feature


class InspectorEvaluateError(PyMobileDevice3Exception):
    """JavaScript evaluated through Web Inspector threw an error."""

    def __init__(
        self,
        class_name: str,
        message: str,
        line: Optional[int] = None,
        column: Optional[int] = None,
        stack: Optional[list[str]] = None,
    ):
        super().__init__()
        self.class_name = class_name
        self.message = message
        self.line = line
        self.column = column
        self.stack = stack

    def __str__(self) -> str:
        stack_trace = "\n".join([f"\t - {frame}" for frame in self.stack or []])
        return f"{self.class_name}: {self.message}.\nLine: {self.line} Column: {self.column}\nStack: {stack_trace}"


class LaunchingApplicationError(PyMobileDevice3Exception):
    """The application did not appear in Web Inspector in time."""


class AppInstallError(PyMobileDevice3Exception):
    """Installing, upgrading or removing the app failed."""


class AppNotInstalledError(PyMobileDevice3Exception):
    """The app is not installed."""


class CoreDeviceError(PyMobileDevice3Exception):
    """The device failed the CoreDevice request.

    ``code`` and ``user_info`` carry the device's structured ``CoreDevice.error``
    when it was present, so callers can branch on a specific failure (e.g. the
    camera/microphone-in-use rejection) instead of matching on the message text.
    """

    def __init__(
        self,
        message: object = "",
        *,
        code: Optional[int] = None,
        user_info: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(*((message,) if message else ()))
        self.code = code
        self.user_info = user_info or {}


class CryptexdError(PyMobileDevice3Exception):
    """cryptexd rejected the request."""

    def __str__(self) -> str:
        detail = super().__str__()
        return detail if detail == self.describe() else f"cryptexd rejected the request: {detail}"


class InstallCoordinationError(PyMobileDevice3Exception):
    """The install coordination request failed."""

    def __str__(self) -> str:
        detail = super().__str__()
        return detail if detail == self.describe() else f"install coordination request failed: {detail}"


class AccessDeniedError(PyMobileDevice3Exception):
    """This command needs more privileges."""

    def __init__(self, *args: Any) -> None:
        if not args:
            from pymobiledevice3.osu.os_utils import get_os_utils  # (os_utils imports this module)

            args = (get_os_utils().access_denied_error,)
        super().__init__(*args)


class NoSuchBuildIdentityError(PyMobileDevice3Exception):
    """The firmware has no build identity for this device."""


class MobileActivationException(PyMobileDevice3Exception):
    """Activating the device failed."""


class NotEnoughDiskSpaceError(PyMobileDevice3Exception):
    """This computer does not have enough disk space for the operation."""


class DeprecationError(PyMobileDevice3Exception):
    """Failed to query MobileGestalt: it is deprecated on iOS 17.4 and later."""


class RSDRequiredError(PyMobileDevice3Exception):
    """This command needs an RSD (iOS 17+ tunnel) connection to the device."""

    def __init__(self, identifier: Optional[str], product_version: str) -> None:
        self.identifier = identifier
        self.product_version = product_version
        super().__init__()


class RoutableTunnelRequiredError(PyMobileDevice3Exception):
    """This command needs a kernel-routable tunnel, not the in-process userspace one."""


class UserspaceTunnelUnavailableError(PyMobileDevice3Exception):
    """The no-root userspace tunnel cannot serve this device."""


class SysdiagnoseTimeoutError(PyMobileDevice3Exception, TimeoutError):
    """Timed out collecting the sysdiagnose archive."""


class SupportError(PyMobileDevice3Exception):
    """This is not supported on this computer's operating system."""

    def __init__(self, os_name: Optional[str]) -> None:
        self.os_name = os_name
        super().__init__(
            f"Unsupported OS - {os_name}. To add support, consider contributing at "
            f"https://github.com/doronz88/pymobiledevice3."
        )


class OSNotSupportedError(SupportError):
    """This computer's operating system is not supported."""


class FeatureNotSupportedError(SupportError):
    """This feature is not implemented for this computer's operating system."""

    def __init__(self, os_name: Optional[str], feature: str) -> None:
        self.os_name = os_name
        self.feature = feature
        PyMobileDevice3Exception.__init__(
            self,
            f"Missing implementation of `{feature}` on `{os_name}`. To add support, consider contributing at "
            f"https://github.com/doronz88/pymobiledevice3.",
        )


class QuicProtocolNotSupportedError(PyMobileDevice3Exception):
    """QUIC tunnels are not supported (iOS 18.2 removed them); use a TCP tunnel."""


class PskCipherNotSupportedError(PyMobileDevice3Exception):
    """This Python's SSL library cannot select the PSK ciphers the TCP tunnel needs."""


class RemotePairingCompletedError(PyMobileDevice3Exception):
    """Pairing completed; the device closed the connection, so connect again.

    remotepairingdeviced closes connection after pairing, so client must re-establish it after pairing is
    completed.
    """


class DisableMemoryLimitError(PyMobileDevice3Exception):
    """The device refused to disable the process' memory limit."""


class ProtocolError(PyMobileDevice3Exception):
    """The device sent a message that does not fit the protocol."""

    WORTH_REPORTING = True


class DevicePathError(PyMobileDevice3Exception):
    """Refusing a path supplied by the device."""

    def __str__(self) -> str:
        detail = super().__str__()
        return detail if detail == self.describe() else f"Refusing a path supplied by the device: {detail}"


class TSSError(PyMobileDevice3Exception):
    """Apple's signing server (TSS) refused the request."""


class WdaError(PyMobileDevice3Exception):
    """The WebDriverAgent request failed."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
