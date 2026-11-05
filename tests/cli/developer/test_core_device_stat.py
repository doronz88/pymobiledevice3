import json
from typing import Any, cast

import pytest

from pymobiledevice3.cli.developer import core_device
from pymobiledevice3.remote.core_device.file_service import DomainName
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


def test_stat_prints_timestamps_as_iso8601(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    attributes = {
        "fileType": "regular",
        "size": 5,
        "creationTime": 0,
        "modificationTime": 820454400.5,
        "accessTime": 820454400,
    }

    class FakeFileService:
        def __init__(self, *args: object) -> None:
            pass

        async def __aenter__(self) -> "FakeFileService":
            return self

        async def __aexit__(self, *exc_info: object) -> None:
            return None

        async def get_attributes(self, path: str, follow_symlinks: bool = True) -> dict[str, Any]:
            return attributes

    monkeypatch.setattr(core_device, "FileServiceService", FakeFileService)

    core_device.core_device_stat(
        service_provider=cast(RemoteServiceDiscoveryService, object()), domain=DomainName.TEMPORARY, path="file"
    )

    assert json.loads(capsys.readouterr().out) == {
        "fileType": "regular",
        "size": 5,
        "creationTime": "2001-01-01T00:00:00+00:00",
        "modificationTime": "2027-01-01T00:00:00.500000+00:00",
        "accessTime": "2027-01-01T00:00:00+00:00",
    }
    # The service keeps reporting raw seconds, so they round-trip through set_attributes.
    assert attributes["creationTime"] == 0
