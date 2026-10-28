from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pymobiledevice3.cli.developer import debugserver
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

BUNDLE_ID = "com.example.app"


class _AsyncContext:
    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None


@pytest.mark.parametrize("running_pid", [0, 42], ids=["not-running", "already-running"])
def test_debugserver_lldb_launch_continues_the_attached_app(monkeypatch: pytest.MonkeyPatch, running_pid: int) -> None:
    class FakeInstallationProxyService(_AsyncContext):
        def __init__(self, lockdown: object) -> None:
            pass

        async def get_apps(self, bundle_identifiers: list[str]) -> dict[str, Any]:
            return {BUNDLE_ID: {"Path": "/private/var/containers/Bundle/Application/X/App.app"}}

    class FakeProcessControl(_AsyncContext):
        def __init__(self, dvt: object) -> None:
            pass

        async def process_identifier_for_bundle_identifier(self, bundle_identifier: str) -> int:
            return running_pid

        async def launch(self, **_kwargs: object) -> int:
            return 43

    @asynccontextmanager
    async def forward_debugproxy(service_provider: object) -> AsyncGenerator[int, None]:
        yield 1234

    lldb_commands: list[str] = []

    async def run_lldb(lldb_command: str, commands: list[str]) -> None:
        lldb_commands.extend(commands)

    monkeypatch.setattr(debugserver, "InstallationProxyService", FakeInstallationProxyService)
    monkeypatch.setattr(debugserver, "DvtProvider", lambda service_provider: _AsyncContext())
    monkeypatch.setattr(debugserver, "ProcessControl", FakeProcessControl)
    monkeypatch.setattr(debugserver, "_forward_debugproxy", forward_debugproxy)
    monkeypatch.setattr(debugserver, "_run_lldb", run_lldb)

    service_provider = cast(RemoteServiceDiscoveryService, SimpleNamespace(product_version="17.4"))
    debugserver.debugserver_lldb(service_provider=service_provider, project_or_ipa_or_bundle_id=BUNDLE_ID, launch=True)

    attached_pid = running_pid or 43
    assert lldb_commands[-2:] == [f"process attach --pid {attached_pid}", "process continue"]
