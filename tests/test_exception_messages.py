import inspect

import pymobiledevice3.exceptions as exceptions
from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    MessageNotSupportedError,
    NoDeviceConnectedError,
    PyMobileDevice3Exception,
    StreamClosedError,
)

_CLASSES = [
    cls
    for cls in vars(exceptions).values()
    if inspect.isclass(cls) and issubclass(cls, PyMobileDevice3Exception) and cls.__module__ == exceptions.__name__
]


def test_every_exception_documents_what_it_means() -> None:
    # the docstring's first paragraph is the message of a bare raise, so each class needs its own
    undocumented = [cls.__name__ for cls in _CLASSES if not cls.__dict__.get("__doc__")]
    assert undocumented == []


def test_a_bare_raise_reads_as_its_docstring() -> None:
    assert str(NoDeviceConnectedError()) == "Device is not connected."
    # a subclass without a docstring of its own would describe itself with its parent's
    assert str(StreamClosedError()) == StreamClosedError.describe()
    assert str(ConnectionTerminatedError()) == "Connection was terminated abruptly."


def test_a_raise_with_a_message_keeps_it() -> None:
    assert str(ConnectionTerminatedError("Connection lost while sending")) == "Connection lost while sending"


def test_the_base_class_is_never_the_description() -> None:
    assert PyMobileDevice3Exception.describe() is None
    # raised where no specific error type exists yet: it asks to be reported, so it should read as a sentence
    assert str(PyMobileDevice3Exception()).startswith("pymobiledevice3 ran into an unexpected error.\nPlease report")


def test_unhandled_replies_ask_to_be_reported() -> None:
    message = str(MessageNotSupportedError("QueryNonce", {"Status": "Weird"}))
    assert message.startswith("The device replied to QueryNonce with a message pymobiledevice3 does not handle")
    assert "{'Status': 'Weird'}" in message
    assert "Please report it at" in message
    assert "-v" in message
