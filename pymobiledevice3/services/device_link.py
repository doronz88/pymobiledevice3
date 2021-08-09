import datetime
import ctypes
import shutil
import os
import struct
from pathlib import Path

from pymobiledevice3.exceptions import PyMobileDevice3Exception

SIZE_FORMAT = '>I'
CODE_FORMAT = '>B'
CODE_FILE_DATA = 0xc
CODE_ERROR_LOCAL = 0x6
CODE_SUCCESS = 0
FILE_TRANSFER_TERMINATOR = b'\x00\x00\x00\x00'
BULK_OPERATION_ERROR = -13
APPLE_EPOCH = 978307200
ERRNO_TO_DEVICE_ERROR = {
    2: -6,
    17: -7,
    20: -8,
    21: -9,
    62: -10,
    5: -11,
    28: -15,
}


class DeviceLink:
    def __init__(self, service, root_path: Path):
        self.service = service
        self.root_path = root_path
        self._dl_handlers = {
            'DLMessageCreateDirectory': self.create_directory,
            'DLMessageUploadFiles': self.upload_files,
            'DLMessageGetFreeDiskSpace': self.get_free_disk_space,
            'DLMessageMoveItems': self.move_items,
            'DLMessageRemoveItems': self.remove_items,
            'DLMessageDownloadFiles': self.download_files,
            'DLContentsOfDirectory': self.contents_of_directory,
            'DLMessageCopyItem': self.copy_item,
        }

    def dl_loop(self, progress_callback=lambda x: None):
        while True:
            message = self.receive_message()
            command = message[0]

            if command in ('DLMessageDownloadFiles', 'DLMessageMoveFiles', 'DLMessageMoveItems', 'DLMessageRemoveFiles',
                           'DLMessageRemoveItems'):
                progress_callback(message[3])
            elif command == 'DLMessageUploadFiles':
                progress_callback(message[2])

            if command == 'DLMessageProcessMessage':
                if not message[1]['ErrorCode']:
                    return message[1].get('Content')
                else:
                    raise PyMobileDevice3Exception(f'Device link error: {message[1]}')
            self._dl_handlers[command](message)

    def version_exchange(self):
        dl_message_version_exchange = self.receive_message()
        version_major = dl_message_version_exchange[1]
        self.service.send_plist(['DLMessageVersionExchange', 'DLVersionsOk', version_major])
        dl_message_device_ready = self.receive_message()
        if dl_message_device_ready[0] != 'DLMessageDeviceReady':
            raise PyMobileDevice3Exception('Device link didn\'t return ready state')

    def send_process_message(self, message):
        self.service.send_plist(['DLMessageProcessMessage', message])

    def download_files(self, message):
        status = {}
        for file in message[1]:
            self.service.sendall(struct.pack(SIZE_FORMAT, len(file)))
            self.service.sendall(file.encode())
            try:
                data = (self.root_path / file).read_bytes()
            except IOError as e:
                status[file] = {
                    'DLFileErrorString': e.strerror,
                    'DLFileErrorCode': ctypes.c_uint64(ERRNO_TO_DEVICE_ERROR[e.errno]).value
                }
                self.service.sendall(struct.pack(SIZE_FORMAT, len(e.strerror) + struct.calcsize(CODE_FORMAT)))
                self.service.sendall(struct.pack(CODE_FORMAT, CODE_ERROR_LOCAL) + e.strerror.encode())
            else:
                self.service.sendall(struct.pack(SIZE_FORMAT, len(data) + struct.calcsize(CODE_FORMAT)))
                self.service.sendall(struct.pack(CODE_FORMAT, CODE_FILE_DATA) + data)
                buffer = struct.pack(SIZE_FORMAT, struct.calcsize(CODE_FORMAT)) + struct.pack(CODE_FORMAT, CODE_SUCCESS)
                self.service.sendall(buffer)
        self.service.sendall(FILE_TRANSFER_TERMINATOR)
        if status:
            self.status_response(BULK_OPERATION_ERROR, 'Multi status', status)
        else:
            self.status_response(0)

    def contents_of_directory(self, message):
        data = {}
        path = self.root_path / message[1]
        for file in path.iterdir():
            ftype = 'DLFileTypeUnknown'
            if file.is_dir():
                ftype = 'DLFileTypeDirectory'
            if file.is_file():
                ftype = 'DLFileTypeRegular'
            data[file.name] = {
                'DLFileType': ftype,
                'DLFileSize': file.stat().st_size,
                'DLFileModificationDate': datetime.datetime.utcfromtimestamp(file.stat().st_mtime - APPLE_EPOCH)
            }
        self.status_response(0, status_dict=data)

    def upload_files(self, message):
        real_size = 0
        while True:
            device_name = self._prefixed_recv()
            if not device_name:
                break
            file_name = self._prefixed_recv()
            size, = struct.unpack(SIZE_FORMAT, self.service.recvall(struct.calcsize(SIZE_FORMAT)))
            code, = struct.unpack(CODE_FORMAT, self.service.recvall(struct.calcsize(CODE_FORMAT)))
            size -= struct.calcsize(CODE_FORMAT)
            data = b''
            while size and code == CODE_FILE_DATA:
                real_size += size
                data += self.service.recvall(size)
                size, = struct.unpack(SIZE_FORMAT, self.service.recvall(struct.calcsize(SIZE_FORMAT)))
                code, = struct.unpack(CODE_FORMAT, self.service.recvall(struct.calcsize(CODE_FORMAT)))
                size -= struct.calcsize(CODE_FORMAT)
            assert code == CODE_SUCCESS
            (self.root_path / file_name).write_bytes(data)
        self.status_response(0)

    def get_free_disk_space(self, message):
        vfs = os.statvfs(self.root_path)
        freespace = vfs.f_bavail * vfs.f_bsize
        self.status_response(0, status_dict=freespace)

    def move_items(self, message):
        for src, dst in message[1].items():
            dest = self.root_path / dst
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(self.root_path / src, dest)
        self.status_response(0)

    def copy_item(self, message):
        src = self.root_path / message[1]
        dest = self.root_path / message[2]
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dest)
        else:
            shutil.copy(src, dest)
        self.status_response(0)

    def remove_items(self, message):
        for path in message[1]:
            rm_path = self.root_path / path
            if rm_path.is_dir():
                shutil.rmtree(rm_path)
            else:
                rm_path.unlink(missing_ok=True)
        self.status_response(0)

    def create_directory(self, message):
        path = message[1]
        (self.root_path / path).mkdir(parents=True, exist_ok=True)
        self.status_response(0)

    def status_response(self, status_code, status_str='', status_dict=None):
        self.service.send_plist([
            'DLMessageStatusResponse', ctypes.c_uint64(status_code).value,
            status_str if status_str else '___EmptyParameterString___',
            status_dict if status_dict is not None else {},
        ])

    def receive_message(self):
        return self.service.recv_plist()

    def disconnect(self):
        self.service.send_plist(['DLMessageDisconnect', '___EmptyParameterString___'])

    def _prefixed_recv(self):
        size, = struct.unpack(SIZE_FORMAT, self.service.recvall(struct.calcsize(SIZE_FORMAT)))
        return self.service.recvall(size).decode()
