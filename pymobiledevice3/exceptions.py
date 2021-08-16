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


class DeviceNonConnectedError(PyMobileDevice3Exception):
    pass


class MuxException(PyMobileDevice3Exception):
    pass


class MuxVersionError(MuxException):
    pass


class ArgumentError(PyMobileDevice3Exception):
    pass


class AfcException(PyMobileDevice3Exception):
    def __init__(self, message, status):
        super(AfcException, self).__init__(message)
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


class UnsupportedCommandError(PyMobileDevice3Exception):
    """ Given command isn't supported for this iOS version """
    pass
