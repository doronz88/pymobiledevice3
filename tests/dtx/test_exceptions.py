from __future__ import annotations

from pymobiledevice3.dtx.exceptions import get_root_exception
from pymobiledevice3.exceptions import InvalidServiceError


def test_get_root_exception_stops_before_invalid_service_cause() -> None:
    wrapper = RuntimeError("wrapper")
    wrapper.__cause__ = InvalidServiceError("InvalidService")

    assert get_root_exception(wrapper) is wrapper


def test_get_root_exception_stops_before_invalid_service_context() -> None:
    wrapper = RuntimeError("wrapper")
    wrapper.__context__ = InvalidServiceError("InvalidService")

    assert get_root_exception(wrapper) is wrapper
