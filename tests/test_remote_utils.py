from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.remote import utils


@pytest.mark.asyncio
async def test_get_rsds_skips_terminated_endpoint(monkeypatch):
    class TerminatedRsd:
        def __init__(self, address):
            pass

        async def connect(self):
            raise ConnectionTerminatedError

    async def browse_remoted(timeout):
        return [SimpleNamespace(addresses=[SimpleNamespace(full_ip="fd00::1")])]

    monkeypatch.setattr(utils, "RemoteServiceDiscoveryService", TerminatedRsd)
    monkeypatch.setattr(utils, "browse_remoted", browse_remoted)
    monkeypatch.setattr(utils, "stop_remoted", nullcontext)

    assert await utils.get_rsds() == []
