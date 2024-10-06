import dataclasses
import uuid
from pathlib import Path

from tqdm import tqdm

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


@dataclasses.dataclass
class DSCFile:
    file_path: str
    file_size: int


class RemoteFetchSymbolsService(RemoteService):
    SERVICE_NAME = 'com.apple.dt.remoteFetchSymbols'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get_dsc_file_list(self) -> list[DSCFile]:
        files: list[DSCFile] = []
        response = await self.service.send_receive_request({'XPCDictionary_sideChannel': uuid.uuid4(), 'DSCFilePaths': []})
        file_count = response['DSCFilePaths']
        for i in range(file_count):
            response = await self.service.receive_response()
            response = response['DSCFilePaths']
            file_transfer = response['fileTransfer']
            expected_length = file_transfer['expectedLength']
            file_path = response['filePath']
            files.append(DSCFile(file_path=file_path, file_size=expected_length))
        return files

    async def download(self, out: Path) -> None:
        files = await self.get_dsc_file_list()
        for i, file in enumerate(files):
            self.logger.info(f'Downloading {file}')
            out_file = out / file.file_path[1:]  # trim the "/" prefix
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, 'wb') as f:
                with tqdm(total=files[i].file_size, dynamic_ncols=True) as pb:
                    async for chunk in self.service.iter_file_chunks(files[i].file_size, file_idx=i):
                        f.write(chunk)
                        pb.update(len(chunk))
