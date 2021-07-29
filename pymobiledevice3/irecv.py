import time

from tqdm import trange
from usb.core import find, Device, USBError

USB_TIMEOUT = 10000

IRECV_K_RECOVERY_MODE_1 = 0x1280
IRECV_K_RECOVERY_MODE_2 = 0x1281
IRECV_K_RECOVERY_MODE_3 = 0x1282
IRECV_K_RECOVERY_MODE_4 = 0x1283
IRECV_K_WTF_MODE = 0x1222
IRECV_K_DFU_MODE = 0x122

APPLE_VENDOR_ID = 0x05AC


class IRecv:
    def __init__(self, ecid=None, timeout=0xffffffff):
        self._device = None  # type: Device
        self.device_info = {}
        self._find(ecid=ecid, timeout=timeout)
        self._populate_device_info()

    def ctrl_transfer(self, bmRequestType, bRequest):
        self._device.ctrl_transfer(bmRequestType, bRequest)

    def send_buffer(self, buf: bytes):
        packet_size = 0x8000

        # initiate transfer
        self.ctrl_transfer(0x41, 0)

        for i in trange(0, len(buf), packet_size):
            # Use bulk transfer for recovery mode and control transfer for DFU and WTF mode
            chunk = buf[i:i + packet_size]
            n = self._device.write(0x04, chunk, timeout=USB_TIMEOUT)
            if n != len(chunk):
                raise IOError('failed to upload data')

    def send_command(self, cmd: str, timeout=USB_TIMEOUT):
        self._device.ctrl_transfer(0x40, 0, 0, 0, cmd.encode() + b'\0', timeout=timeout)

    def getenv(self, name):
        try:
            self.send_command(f'getenv {name}')
        except USBError:
            return None
        return bytearray(self._device.ctrl_transfer(0xc0, 0, 0, 0, 255))

    def set_autoboot(self, enable: bool):
        self.send_command(f'setenv auto-boot {str(enable).lower()}')
        self.send_command('saveenv')

    def reboot(self):
        try:
            self.send_command('reboot')
        except USBError:
            pass

    def _find(self, ecid=None, timeout=0xffffffff):
        start = time.time()
        end = start + timeout
        while (self._device is None) and (time.time() < end):
            for device in find(find_all=True):
                try:
                    if not device.manufacturer.startswith('Apple'):
                        continue
                    if 'Recovery Mode' not in device.product:
                        continue
                    if self._device is not None:
                        raise Exception('More then one connected device was found connected in recovery mode')
                    self._device = device
                    self._populate_device_info()

                    if ecid is not None:
                        found_ecid = int(self.device_info['ECID'], 16)
                        if found_ecid != ecid:
                            # wrong device - move on
                            self._device = None
                            continue
                except ValueError:
                    continue

    def _populate_device_info(self):
        for component in self._device.serial_number.split(' '):
            k, v = component.split(':')
            if k == 'SRNM' and '[' in v:
                # trim the `[]`
                v = v[1:-1]
            self.device_info[k] = v

    def __str__(self):
        return str(self.device_info)


def main():
    print(IRecv())


if __name__ == '__main__':
    main()
