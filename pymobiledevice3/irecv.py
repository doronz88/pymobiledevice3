import binascii
import logging
import math
import struct
import time
from enum import Enum
from typing import Optional

from tqdm import trange
from usb.core import find, Device, USBError
from usb.util import get_string

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.irecv_devices import IRECV_DEVICES, IRecvDevice

USB_TIMEOUT = 10000
IRECV_TRANSFER_SIZE_RECOVERY = 0x2000
IRECV_TRANSFER_SIZE_DFU = 0x800


class Mode(Enum):
    RECOVERY_MODE_1 = 0x1280
    RECOVERY_MODE_2 = 0x1281
    RECOVERY_MODE_3 = 0x1282
    RECOVERY_MODE_4 = 0x1283
    WTF_MODE = 0x1222
    DFU_MODE = 0x1227

    @classmethod
    def has_value(cls, value):
        for m in cls:
            if value == m.value:
                return True
        return False

    @classmethod
    def get_mode_from_value(cls, value):
        """
        :rtype: Mode
        """
        for m in cls:
            if value == m.value:
                return m
        return None

    @property
    def is_recovery(self):
        return self not in (self.WTF_MODE, self.DFU_MODE)


CPFM_FLAG_SECURITY_MODE = 1 << 0
CPFM_FLAG_PRODUCTION_MODE = 1 << 1

IBOOT_FLAG_IMAGE4_AWARE = 1 << 2
IBOOT_FLAG_EFFECTIVE_SECURITY_MODE = 1 << 3
IBOOT_FLAG_EFFECTIVE_PRODUCTION_MODE = 1 << 4

APPLE_VENDOR_ID = 0x05AC

logger = logging.getLogger(__name__)


class IRecv:
    def __init__(self, ecid=None, timeout=0xffffffff, is_recovery=None):
        self.mode = None  # type: Optional[Mode]
        self._device_info = {}
        self._device = None  # type: Optional[Device]
        self._reinit(ecid=ecid, timeout=timeout, is_recovery=is_recovery)

    @property
    def ecid(self):
        return int(self._device_info['ECID'], 16)

    @property
    def ibfl(self):
        return int(self._device_info['IBFL'], 16)

    @property
    def chip_id(self):
        return int(self._device_info['CPID'], 16)

    @property
    def board_id(self):
        return int(self._device_info['BDID'], 16)

    @property
    def is_image4_supported(self):
        return self.ibfl & IBOOT_FLAG_IMAGE4_AWARE

    @property
    def _irecv_device(self) -> IRecvDevice:
        for device in IRECV_DEVICES:
            if device.board_id == self.board_id and device.chip_id == self.chip_id:
                return device
        raise KeyError(f'failed to find device of: board_id: {self.board_id} chip_id: {self.chip_id}')

    @property
    def product_type(self):
        return self._irecv_device.product_type

    @property
    def hardware_model(self):
        return self._irecv_device.hardware_model

    @property
    def display_name(self):
        return self._irecv_device.display_name

    @property
    def status(self):
        return self.ctrl_transfer(0xa1, 3, data_or_wLength=b'\x00' * 6)[4]

    def set_interface_altsetting(self, interface=None, alternate_setting=None):
        logger.debug(f'set_interface_altsetting: {interface} {alternate_setting}')
        if interface == 1:
            self._device.set_interface_altsetting(interface=interface, alternate_setting=alternate_setting)

    def set_configuration(self, configuration=None):
        logger.debug(f'set_configuration: {configuration}')
        if self._device.get_active_configuration().bConfigurationValue != configuration:
            self._device.set_configuration(configuration=configuration)

    def ctrl_transfer(self, bmRequestType, bRequest, **kwargs):
        return self._device.ctrl_transfer(bmRequestType, bRequest, **kwargs)

    def send_buffer(self, buf: bytes):
        packet_size = IRECV_TRANSFER_SIZE_RECOVERY if self.mode.is_recovery else IRECV_TRANSFER_SIZE_DFU

        # initiate transfer
        if self.mode.is_recovery:
            self.ctrl_transfer(0x41, 0)
        else:
            response = self.ctrl_transfer(0xa1, 5, data_or_wLength=1)
            state = response[0]
            logger.debug(f'irecv state: {state}')
            if state == 2:
                # DFU IDLE
                pass
            elif state == 10:
                self.ctrl_transfer(0x21, 4)
                raise PyMobileDevice3Exception('DFU ERROR, issuing CLRSTATUS')
            else:
                self.ctrl_transfer(0x21, 6)
                raise PyMobileDevice3Exception(f'Unexpected state {state}, issuing ABORT')

        crc = -1

        num_packets = math.ceil(len(buf) / packet_size)

        for offset in trange(0, len(buf), packet_size, dynamic_ncols=True):
            # Use bulk transfer for recovery mode and control transfer for DFU and WTF mode
            chunk = buf[offset:offset + packet_size]
            packet_index = offset // packet_size

            if self.mode.is_recovery:
                n = self._device.write(0x04, chunk, timeout=USB_TIMEOUT)
                if n != len(chunk):
                    raise IOError('failed to upload data')
            else:
                if offset + packet_size >= len(buf):
                    # last packet

                    # calculate crc of all sent data
                    crc = binascii.crc32(buf, crc)

                    # add crc of dfu_xbuf (salted value)
                    dfu_xbuf = bytearray([0xff, 0xff, 0xff, 0xff, 0xac, 0x05, 0x00, 0x01, 0x55, 0x46, 0x44, 0x10])
                    crc = binascii.crc32(dfu_xbuf, crc)

                    crc_chunk = dfu_xbuf + struct.pack('<I', crc)

                    if len(chunk) + 16 > packet_size:
                        # crc exceeds the max allowed packet size
                        self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=chunk)
                        self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=crc_chunk)
                    else:
                        self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=chunk + crc_chunk)
                else:
                    self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=chunk)

        if not self.mode.is_recovery:
            logger.debug('waiting for status == 5')
            while self.status != 5:
                time.sleep(1)

            self.ctrl_transfer(0x21, 1, wValue=num_packets, wIndex=0)

            for offset in range(2):
                # i know it's not used but idevicerestore does that also
                _ = self.status

            self.reset()

    def reset(self):
        try:
            logger.debug('resetting usb device')
            self._device.reset()
        except USBError:
            pass

        self._reinit(ecid=self.ecid)

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

    def _reinit(self, ecid=None, timeout=0xffffffff, is_recovery=None):
        self._device = None
        self._device_info = {}
        self.mode = None
        self._find(ecid=ecid, timeout=timeout, is_recovery=is_recovery)
        self._populate_device_info()

        self.ap_nonce = self._copy_nonce_with_tag('NONC')
        self.sep_nonce = self._copy_nonce_with_tag('SNON')

        self.set_configuration(1)

        if self.mode.is_recovery:
            self.set_interface_altsetting(0, 0)
            if self.mode.value > Mode.RECOVERY_MODE_2.value:
                self.set_interface_altsetting(1, 1)
        else:
            self.set_interface_altsetting(0, 0)

    def _copy_nonce_with_tag(self, tag):
        return binascii.unhexlify(get_string(self._device, 1).split(f'{tag}:')[1].split(' ')[0])

    def _find(self, ecid=None, timeout=0xffffffff, is_recovery=None):
        start = time.time()
        end = start + timeout
        while (self._device is None) and (time.time() < end):
            for device in find(find_all=True):
                try:
                    if device.manufacturer is None:
                        continue
                    if not device.manufacturer.startswith('Apple'):
                        continue

                    mode = Mode.get_mode_from_value(device.idProduct)
                    if mode is None:
                        # not one of Apple's special modes
                        continue

                    if is_recovery is not None and mode.is_recovery != is_recovery:
                        continue

                    if self._device is not None:
                        raise Exception('More then one connected device was found connected in recovery mode')
                    self._device = device
                    self.mode = mode
                    self._populate_device_info()

                    if ecid is not None:
                        found_ecid = int(self._device_info['ECID'], 16)
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
            self._device_info[k] = v

    def __str__(self):
        return str(self._device_info)


def main():
    print(IRecv())


if __name__ == '__main__':
    main()
