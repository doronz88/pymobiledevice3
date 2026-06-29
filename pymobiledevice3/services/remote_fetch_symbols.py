import asyncio
import dataclasses
import uuid
from pathlib import Path

from tqdm import tqdm

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

MAX_CONCURRENT_DOWNLOADS = 4


@dataclasses.dataclass
class DSCFile:
    """A dyld shared cache file advertised by the device, with its on-device path and byte size."""

    file_path: str
    file_size: int


class RemoteFetchSymbolsService(RemoteService):
    """
    Client for the `com.apple.dt.remoteFetchSymbols` RemoteXPC service (RSD/CoreDevice).

    Lists the device's dyld shared cache (DSC) files and downloads them to the host,
    preserving their on-device directory layout. Downloads run concurrently across up to
    `MAX_CONCURRENT_DOWNLOADS` workers.

    Inherits async context manager support from `RemoteService`; use within an
    ``async with`` block to manage the underlying connection.
    """

    SERVICE_NAME = "com.apple.dt.remoteFetchSymbols"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get_dsc_file_list(self) -> list[DSCFile]:
        """
        Query the device for the list of available DSC files.

        :returns: One `DSCFile` per advertised file, each carrying its on-device path and
            expected byte length.
        """
        files: list[DSCFile] = []
        response = await self.service.send_receive_request({
            "XPCDictionary_sideChannel": uuid.uuid4(),
            "DSCFilePaths": [],
        })
        file_count = response["DSCFilePaths"]
        for _i in range(file_count):
            response = await self.service.receive_response()
            response = response["DSCFilePaths"]
            file_transfer = response["fileTransfer"]
            expected_length = file_transfer["expectedLength"]
            file_path = response["filePath"]
            files.append(DSCFile(file_path=file_path, file_size=expected_length))
        return files

    async def download(self, out: Path) -> None:
        """
        Download all DSC files into a local directory, reproducing their device paths.

        Each file is written under `out` at its device-relative path (the leading "/" is
        stripped), and progress is shown via a tqdm bar.

        :param out: Destination directory; intermediate parent directories are created as needed.
        """
        files = await self.get_dsc_file_list()
        file_indexes: asyncio.Queue[int] = asyncio.Queue()
        for i in range(len(files)):
            file_indexes.put_nowait(i)

        with tqdm(
            total=sum(file.file_size for file in files),
            unit="B",
            unit_scale=True,
            dynamic_ncols=True,
            desc="Downloading DSC",
        ) as pb:
            workers = [self._download_files(files, file_indexes, out, pb) for _ in files[:MAX_CONCURRENT_DOWNLOADS]]
            await asyncio.gather(*workers)

    async def _download_files(
        self, files: list[DSCFile], file_indexes: asyncio.Queue[int], out: Path, pb: tqdm
    ) -> None:
        while True:
            try:
                i = file_indexes.get_nowait()
            except asyncio.QueueEmpty:
                return

            file = files[i]
            out_file = out / file.file_path[1:]  # trim the "/" prefix
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "wb") as f:
                async for chunk in self.service.iter_file_chunks(file.file_size, file_idx=i):
                    f.write(chunk)
                    pb.update(len(chunk))
