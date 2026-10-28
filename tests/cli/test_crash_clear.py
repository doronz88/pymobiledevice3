from typing import Optional, cast

import pytest

from pymobiledevice3.cli import crash as crash_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())


def _fake_manager(calls: list[tuple[str, Optional[str]]]):
    class _Manager:
        def __init__(self, service_provider):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def clear(self, path: str = "/", match: Optional[str] = None) -> None:
            calls.append((path, match))

    return _Manager


def test_crash_clear_match_forwards_pattern(monkeypatch):
    calls: list[tuple[str, Optional[str]]] = []
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager(calls))

    crash_module.crash_clear(_FAKE_SERVICE_PROVIDER, remote_file="/a", match=r"^drop")

    assert calls == [("/a", r"^drop")]


def test_crash_clear_without_match_clears_everything(monkeypatch):
    calls: list[tuple[str, Optional[str]]] = []
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager(calls))

    crash_module.crash_clear(_FAKE_SERVICE_PROVIDER)

    assert calls == [("/", None)]
