import inspect
from unittest.mock import AsyncMock, Mock

import pytest

from pymobiledevice3.cli import provision
from pymobiledevice3.exceptions import DevicePathError


@pytest.mark.asyncio
@pytest.mark.parametrize("identifier", ["../victim", "/victim", r"C:\victim", r"..\victim", "nested/file"])
async def test_dump_rejects_profile_path(monkeypatch, tmp_path, identifier):
    fake = Mock(copy_all=AsyncMock(return_value=[Mock(plist={"UUID": identifier}, buf=b"data")]))
    monkeypatch.setattr(provision, "MisagentService", lambda **kwargs: fake)
    with pytest.raises(DevicePathError):
        await inspect.unwrap(provision.provision_dump)(None, tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_dump_valid_profile(monkeypatch, tmp_path):
    fake = Mock(copy_all=AsyncMock(return_value=[Mock(plist={"UUID": "ABC-123"}, buf=b"data")]))
    monkeypatch.setattr(provision, "MisagentService", lambda **kwargs: fake)
    await inspect.unwrap(provision.provision_dump)(None, tmp_path)
    assert (tmp_path / "ABC-123.mobileprovision").read_bytes() == b"data"
