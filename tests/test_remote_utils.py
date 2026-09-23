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

    def iter_browse_remoted(timeout):
        async def _iter():
            yield SimpleNamespace(addresses=[SimpleNamespace(full_ip="fd00::1")])

        return _iter()

    monkeypatch.setattr(utils, "RemoteServiceDiscoveryService", TerminatedRsd)
    monkeypatch.setattr(utils, "iter_browse_remoted", iter_browse_remoted)
    monkeypatch.setattr(utils, "stop_remoted", nullcontext)

    assert await utils.get_rsds() == []


def test_handshake_uuid_is_resolved_before_remoted_is_suspended(monkeypatch):
    # `remotectl` gets the UUID from remoted itself: asked after the SIGSTOP it hangs until its
    # timeout inside every RSD handshake, and get_rsds ends up skipping the device.
    events = []
    remoted = SimpleNamespace(status=lambda: "running", suspend=lambda: events.append("suspend"))

    monkeypatch.setattr(utils.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(utils, "get_remoted_process", lambda: remoted)
    monkeypatch.setattr(utils, "default_handshake_uuid", lambda: events.append("resolve uuid"))

    utils.stop_remoted_if_required()

    assert events == ["resolve uuid", "suspend"]
