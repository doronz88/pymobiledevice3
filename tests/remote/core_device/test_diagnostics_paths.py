from unittest.mock import AsyncMock, Mock

import pytest

from pymobiledevice3.exceptions import DevicePathError
from pymobiledevice3.remote.core_device.diagnostics_service import DiagnosticsServiceService


@pytest.mark.asyncio
@pytest.mark.parametrize("filename", ["../file", "/file", r"C:\file", r"..\file", "dir/file", "x\0y"])
async def test_sysdiagnose_rejects_device_filename(filename):
    service = object.__new__(DiagnosticsServiceService)
    service.invoke = AsyncMock(return_value={"preferredFilename": filename, "fileTransfer": {"expectedLength": 4}})
    with pytest.raises(DevicePathError):
        await service.capture_sysdiagnose(False)


@pytest.mark.asyncio
async def test_sysdiagnose_preserves_valid_response():
    async def chunks(size):
        yield b"data"

    service = object.__new__(DiagnosticsServiceService)
    service._service = Mock(iter_file_chunks=chunks)
    service.invoke = AsyncMock(
        return_value={"preferredFilename": "sysdiagnose.tar.gz", "fileTransfer": {"expectedLength": 4}}
    )
    response = await service.capture_sysdiagnose(False)
    assert response.preferred_filename == "sysdiagnose.tar.gz"
    assert b"".join([chunk async for chunk in response.generator]) == b"data"
