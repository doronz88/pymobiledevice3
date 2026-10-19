import plistlib
from types import SimpleNamespace
from typing import Any

import pytest

from pymobiledevice3.restore.restore import Restore

COMPONENT = bytes(range(256)) * 80  # 20 KiB: three FileData chunks


class _RecordingService:
    def __init__(self) -> None:
        self.sent: list[tuple[dict[str, Any], Any]] = []

    async def send_plist(self, d: dict[str, Any], endianity: str = ">", fmt: Any = plistlib.FMT_XML) -> None:
        self.sent.append((d, fmt))


def _restore(service: _RecordingService, monkeypatch: pytest.MonkeyPatch) -> Restore:
    # Bypass __init__ (needs an IPSW and a device); only the data-request plumbing is stubbed.
    restore = Restore.__new__(Restore)

    async def get_service(message: dict[str, Any]) -> _RecordingService:
        return service

    async def get_personalized_data(component_name: str, **kwargs: Any) -> bytes:
        return COMPONENT

    async def get_build_identity_from_request(message: dict[str, Any]) -> Any:
        return SimpleNamespace(get_component=lambda name, tss=None: SimpleNamespace(data=COMPONENT))

    monkeypatch.setattr(restore, "_get_service_for_data_request", get_service, raising=False)
    monkeypatch.setattr(restore, "get_personalized_data", get_personalized_data, raising=False)
    monkeypatch.setattr(restore, "get_build_identity_from_request", get_build_identity_from_request, raising=False)
    monkeypatch.setattr(restore, "recovery", SimpleNamespace(require_tss=lambda: None, tss=None), raising=False)
    return restore


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["send_personalized_boot_object_v3", "send_source_boot_object_v4"])
async def test_component_data_is_sent_as_binary_plists(handler: str, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _RecordingService()
    await getattr(_restore(service, monkeypatch), handler)({"Arguments": {"ImageName": "iBEC"}})

    chunks = [(d, fmt) for d, fmt in service.sent if "FileData" in d]
    assert b"".join(d["FileData"] for d, _ in chunks) == COMPONENT
    assert {fmt for _, fmt in chunks} == {plistlib.FMT_BINARY}
    assert service.sent[-1][0] == {"FileDataDone": True}
