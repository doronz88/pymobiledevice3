__all__ = [
    'PyMobileDevice3Exception', 'DeviceVersionNotSupportedError', 'IncorrectModeError', 'DeviceVersionFormatError',
    'ConnectionFailedError', 'NotTrustedError', 'PairingError', 'NotPairedError', 'CannotStopSessionError',
    'PasswordRequiredError', 'StartServiceError', 'FatalPairingError', 'NoDeviceConnectedError', 'MuxException',
    'MuxVersionError', 'ArgumentError', 'AfcException', 'AfcFileNotFoundError', 'DvtException', 'DvtDirListError',
    'NotMountedError', 'AlreadyMountedError', 'UnsupportedCommandError', 'ExtractingStackshotError',
    'ConnectionTerminatedError', 'WirError', 'WebInspectorNotEnabled', 'RemoteAutomationNotEnabled',
]


class PyMobileDevice3Exception(Exception):
    pass


class DeviceVersionNotSupportedError(PyMobileDevice3Exception):
    pass


class IncorrectModeError(PyMobileDevice3Exception):
    pass


class DeviceVersionFormatError(PyMobileDevice3Exception):
    pass


class ConnectionFailedError(PyMobileDevice3Exception):
    pass


class NotTrustedError(PyMobileDevice3Exception):
    pass


class PairingError(PyMobileDevice3Exception):
    pass


class NotPairedError(PyMobileDevice3Exception):
    pass


class CannotStopSessionError(PyMobileDevice3Exception):
    pass


class PasswordRequiredError(PyMobileDevice3Exception):
    pass


class StartServiceError(PyMobileDevice3Exception):
    pass


class FatalPairingError(PyMobileDevice3Exception):
    pass


class NoDeviceConnectedError(PyMobileDevice3Exception):
    pass


class MuxException(PyMobileDevice3Exception):
    pass


class MuxVersionError(MuxException):
    pass


class ArgumentError(PyMobileDevice3Exception):
    pass


class AfcException(PyMobileDevice3Exception, OSError):
    def __init__(self, message, status):
        OSError.__init__(self, status, message)
        self.status = status


class AfcFileNotFoundError(AfcException):
    pass


class DvtException(PyMobileDevice3Exception):
    """ Domain exception for DVT operations. """
    pass


class DvtDirListError(DvtException):
    """ Raise when directory listing fails. """
    pass


class NotMountedError(PyMobileDevice3Exception):
    """ Given image for umount wasn't mounted in the first place """
    pass


class AlreadyMountedError(PyMobileDevice3Exception):
    """ Given image for mount has already been mounted in the first place """
    pass


class UnsupportedCommandError(PyMobileDevice3Exception):
    """ Given command isn't supported for this iOS version """
    pass


class ExtractingStackshotError(PyMobileDevice3Exception):
    """ Raise when stackshot is not received in the core profile session. """
    pass


class ConnectionTerminatedError(PyMobileDevice3Exception):
    """ Raise when a connection is terminated abruptly. """
    pass


class WebInspectorNotEnabled(PyMobileDevice3Exception):
    """ Raise when Web Inspector is not enabled. """
    pass


class RemoteAutomationNotEnabled(PyMobileDevice3Exception):
    """ Raise when Web Inspector remote automation is not enabled. """
    pass


class WirError(PyMobileDevice3Exception):
    """ Raise when Webinspector WIR command fails. """
    pass


class InternalError(PyMobileDevice3Exception):
    """ Some internal Apple error """
    pass
