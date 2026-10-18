import asyncio
import inspect
from typing import Any, cast

import pytest
from pykdebugparser.trace_codes import syscall_eventids
from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli.developer.dvt import core_profile_session
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


@pytest.mark.parametrize("command", ["parse_live_profile_session", "callstacks_live_profile_session"])
def test_live_commands_stream_endlessly_by_default(command: str) -> None:
    # The count is passed to itertools.islice, which rejects -1 as "no limit".
    count = inspect.signature(getattr(core_profile_session, command)).parameters["count"]
    assert count.default is None


LOCKDOWN = cast(LockdownServiceProvider, object())


def test_parse_live_rejects_an_unknown_syscall_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_device(_service_provider: object) -> None:
        raise AssertionError("connected to the device")

    monkeypatch.setattr(core_profile_session, "DvtProvider", no_device)
    monkeypatch.delenv("PYMOBILEDEVICE3_UDID", raising=False)

    result = CliRunner().invoke(
        __main__.app, ["developer", "dvt", "core-profile-session", "parse-live", "-s", "open", "--syscall", "nosuch"]
    )

    assert result.exit_code == 2
    assert "unknown syscalls: nosuch" in result.output
    assert "core-profile-session syscalls" in result.output


def test_syscall_names_are_what_parse_live_accepts() -> None:
    names = core_profile_session.syscall_names()
    assert {"open", "openat", "read"} <= set(names)
    assert "open_nocancel" not in names  # covered by `open`
    assert not [name for name in names if "#" in name]
    assert syscall_eventids(names)


def test_parse_live_syscall_filters_on_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: dict[str, Any] = {}
    parsers: list[Any] = []

    class FakeDvtProvider:
        def __init__(self, _service_provider: object) -> None:
            pass

        async def __aenter__(self) -> "FakeDvtProvider":
            return self

        async def __aexit__(self, *exc_info: object) -> None:
            return None

    class FakeCoreProfileSessionTap(FakeDvtProvider):
        def __init__(self, dvt: object, time_config: object, filters: object, sample_callstacks: bool) -> None:
            requested["filters"] = filters

        @staticmethod
        async def get_time_config(dvt: object) -> dict[str, object]:
            return {"numer": 1, "denom": 1, "mach_absolute_time": 0, "usecs_since_epoch": 0, "timezone": None}

        def get_kdbuf_stream(self, chunk_queue: object, **kwargs: object) -> object:
            return object()

        async def pump_kdbuf_chunks(self, chunk_queue: object) -> None:
            await asyncio.Event().wait()

    class FakeParser:
        def __init__(self) -> None:
            parsers.append(self)

        def formatted_traces(self, stream: object) -> list[str]:
            return []

    monkeypatch.setattr(core_profile_session, "DvtProvider", FakeDvtProvider)
    monkeypatch.setattr(core_profile_session, "CoreProfileSessionTap", FakeCoreProfileSessionTap)
    monkeypatch.setattr(core_profile_session, "PyKdebugParser", FakeParser)

    core_profile_session.parse_live_profile_session(
        service_provider=LOCKDOWN, class_filters=[], subclass_filters=[], syscalls=["open"]
    )

    # The device can only filter subclasses: it sends every syscall, with the VFS lookups that hold the paths.
    assert requested["filters"] == core_profile_session.parse_filters([core_profile_session.BSC_SUBCLASS], [])
    (parser,) = parsers
    assert parser.filter_subclass == []
    assert parser.filter_eventid == syscall_eventids(["open"])
