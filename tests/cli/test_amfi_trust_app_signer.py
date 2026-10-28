from typing import Optional, cast

import pytest

from pymobiledevice3.cli import amfi as amfi_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())
_PROFILE_UUID = "11111111-2222-3333-4444-555555555555"


def test_trust_app_signer_forwards_uuid_and_prints_status(monkeypatch, capsys):
    calls: list[str] = []

    class _Service:
        def __init__(self, service_provider):
            pass

        async def trust_app_signer(self, profile_uuid: str) -> Optional[bool]:
            calls.append(profile_uuid)
            return True

    monkeypatch.setattr(amfi_module, "AmfiService", _Service)

    amfi_module.trust_app_signer(_FAKE_SERVICE_PROVIDER, _PROFILE_UUID)

    assert calls == [_PROFILE_UUID]
    assert capsys.readouterr().out.strip() == "true"
