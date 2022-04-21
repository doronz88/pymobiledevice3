import logging
import time
import typing
from io import BytesIO

from usb import USBError

from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.ipsw.ipsw import IPSW
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse


class Recovery:
    def __init__(self, ipsw: BytesIO, device: Device, tss: typing.Mapping = None,
                 behavior='Update'):
        self.logger = logging.getLogger(__name__)
        self.ipsw = IPSW(ipsw)
        self.device = device
        self.tss = TSSResponse(tss) if tss is not None else None

        if not self.device.is_image4_supported:
            raise NotImplementedError('is_image4_supported is False')

        self.logger.info(f'connected device: <ecid: {self.device.ecid} hardware_model: {self.device.hardware_model} '
                         f'image4-support: {self.device.is_image4_supported}>')

        self.logger.debug('scanning BuildManifest.plist for the correct BuildIdentity')
        self.build_identity = self.ipsw.build_manifest.get_build_identity(self.device.hardware_model, behavior)
        self.restore_boot_args = None

    def reconnect_irecv(self, is_recovery=None):
        self.logger.debug('waiting for device to reconnect...')
        self.device.irecv = IRecv(ecid=self.device.ecid, is_recovery=is_recovery)
        self.logger.debug(f'connected mode: {self.device.irecv.mode}')

    def get_preboard_manifest(self):
        overrides = {
            '@APTicket': True,
            'ApProductionMode': 0,
            'ApSecurityDomain': 0,
        }

        parameters = {
            'ApProductionMode': False,
            'ApSecurityMode': False,
            'ApSupportsImg4': True,
        }

        self.build_identity.populate_tss_request_parameters(parameters)

        tss = TSSRequest()
        tss.add_common_tags(parameters, overrides)

        parameters['_OnlyFWComponents'] = True

        tss.add_ap_tags(parameters)

        return tss.img4_create_local_manifest(build_identity=self.build_identity)

    def get_tss_response(self):
        # populate parameters
        parameters = dict()

        parameters['ApECID'] = self.device.ecid
        if self.device.ap_nonce is not None:
            parameters['ApNonce'] = self.device.ap_nonce

        if self.device.sep_nonce is not None:
            parameters['ApSepNonce'] = self.device.sep_nonce

        parameters['ApProductionMode'] = True

        if self.device.is_image4_supported:
            parameters['ApSecurityMode'] = True
            parameters['ApSupportsImg4'] = True
        else:
            parameters['ApSupportsImg4'] = False

        self.build_identity.populate_tss_request_parameters(parameters)

        tss = TSSRequest()
        tss.add_common_tags(parameters)
        tss.add_ap_tags(parameters)

        # add personalized parameters
        if self.device.is_image4_supported:
            tss.add_ap_img4_tags(parameters)
        else:
            tss.add_ap_img3_tags(parameters)

        # normal mode; request baseband ticket as well
        if self.device.lockdown is not None:
            pinfo = self.device.lockdown.preflight_info
            if pinfo:
                self.logger.debug('adding preflight info')

                node = pinfo.get('Nonce')
                if node is not None:
                    parameters['BbNonce'] = node

                node = pinfo.get('ChipID')
                if node is not None:
                    parameters['BbChipID'] = node

                node = pinfo.get('CertID')
                if node is not None:
                    parameters['BbGoldCertId'] = node

                node = pinfo.get('ChipSerialNo')
                if node is not None:
                    parameters['BbSNUM'] = node

                tss.add_baseband_tags(parameters)

                euiccchipid = pinfo.get('EUICCChipID')
                if euiccchipid:
                    self.logger.debug('adding EUICCChipID info')
                    parameters['eUICC,ChipID'] = euiccchipid

                    if euiccchipid >= 5:
                        node = pinfo.get('EUICCCSN')
                        if node is not None:
                            parameters['eUICC,EID'] = node

                        node = pinfo.get('EUICCCertIdentifier')
                        if node is not None:
                            parameters['eUICC,RootKeyIdentifier'] = node

                        node = pinfo.get('EUICCGoldNonce')
                        if node is not None:
                            parameters['EUICCGoldNonce'] = node

                        node = pinfo.get('EUICCMainNonce')
                        if node is not None:
                            parameters['EUICCMainNonce'] = node

                        tss.add_vinyl_tags(parameters)

        # send request and grab response
        return tss.send_receive()

    def fetch_tss_record(self):
        if self.ipsw.build_manifest.build_major > 8:
            if self.device.ap_nonce is None:
                # the first nonce request with older firmware releases can fail and it's OK
                self.logger.info('NOTE: Unable to get nonce from device')

        self.tss = self.get_tss_response()

        if self.ipsw.build_manifest.build_major >= 20:
            raise NotImplementedError('not yet supported')

        return self.tss

    def send_component(self, name):
        self.device.irecv.send_buffer(self.build_identity.get_component(name, tss=self.tss).personalized_data)

    def send_component_and_command(self, name, command):
        self.send_component(name)
        self.device.irecv.send_command(command)

    def send_ibec(self):
        component = 'iBEC'
        self.send_component(component)
        self.device.irecv.send_command('go')
        self.device.irecv.ctrl_transfer(0x21, 1)

    def send_applelogo(self):
        component = 'RestoreLogo'

        if not self.build_identity.has_component(component):
            return

        self.send_component(component)
        self.device.irecv.send_command('setpicture 4')
        self.device.irecv.send_command('bgcolor 0 0 0')

    def send_loaded_by_iboot(self):
        manifest = self.build_identity['Manifest']
        for key, node in manifest.items():
            iboot = node['Info'].get('IsLoadedByiBoot', False)
            iboot_stg1 = node['Info'].get('IsLoadedByiBootStage1', False)

            assert isinstance(iboot, bool)
            assert isinstance(iboot_stg1, bool)

            if iboot and not iboot_stg1:
                self.logger.debug(f'{key} is loaded by iBoot')
                self.send_component_and_command(key, 'firmware')

    def send_ramdisk(self):
        component = 'RestoreRamDisk'
        ramdisk_size = self.device.irecv.getenv('ramdisk-size')
        self.logger.info(f'ramdisk-size: {ramdisk_size}')

        self.send_component(component)
        ramdisk_delay = self.device.irecv.getenv('ramdisk-delay')
        self.logger.info(f'ramdisk-delay: {ramdisk_delay}')

        self.device.irecv.send_command('ramdisk')

        time.sleep(2)

    def send_kernelcache(self):
        component = 'RestoreKernelCache'

        self.send_component(component)
        try:
            self.device.irecv.ctrl_transfer(0x21, 1)
        except USBError:
            pass

        if self.restore_boot_args:
            self.device.irecv.send_command(f'setenv boot-args {self.restore_boot_args}')

        try:
            self.device.irecv.send_command('bootx')
        except USBError:
            pass

    def set_autoboot(self, enable: bool):
        self.device.irecv.set_autoboot(enable)

    def enter_restore(self):
        if self.ipsw.build_manifest.build_major >= 8:
            self.restore_boot_args = 'rd=md0 nand-enable-reformat=1 -progress'
        elif self.ipsw.build_manifest.build_major >= 20:
            self.restore_boot_args = 'rd=md0 nand-enable-reformat=1 -progress -restore'

        # upload data to make device boot restore mode

        # Recovery Mode Environment:
        build_version = self.device.irecv.getenv('build-version')
        self.logger.info(f'iBoot build-version={build_version}')

        build_style = self.device.irecv.getenv('build-style')
        self.logger.info(f'iBoot build-style={build_style}')

        radio_error = self.device.irecv.getenv('radio-error')
        if radio_error:
            radio_error = int(radio_error)
            self.logger.info(f'radio-error: {radio_error}')
            radio_error_string = self.device.irecv.getenv('radio-error-string')
            if radio_error_string:
                self.logger.info(f'radio-error-string: {radio_error_string}')

        self.set_autoboot(False)

        # send logo and show it
        self.send_applelogo()

        # send components loaded by iBoot
        self.send_loaded_by_iboot()

        # send ramdisk and run it
        self.send_ramdisk()

        # send devicetree and load it
        self.send_component_and_command('RestoreDeviceTree', 'devicetree')

        if 'RestoreSEP' in self.build_identity['Manifest']:
            # send rsepfirmware and load it
            self.send_component_and_command('RestoreSEP', 'rsepfirmware')

        self.send_kernelcache()

    def dfu_enter_recovery(self):
        self.send_component('iBSS')
        self.reconnect_irecv(is_recovery=True)

        if self.build_identity.build_manifest.build_major > 8:
            old_nonce = self.device.irecv.ap_nonce

            # reconnect
            self.reconnect_irecv()
            nonce = self.device.irecv.ap_nonce

            if old_nonce != nonce:
                # Welcome iOS5. We have to re-request the TSS with our nonce.
                self.tss = self.get_tss_response()

        self.device.irecv.set_configuration(1)

    def boot_ramdisk(self):
        if self.tss is None:
            self.logger.info('fetching TSS record')
            self.fetch_tss_record()

        if self.device.irecv and self.device.irecv.mode == Mode.DFU_MODE:
            # device is currently in DFU mode, place it into recovery mode
            self.dfu_enter_recovery()

            # Now, before sending iBEC, we must send necessary firmwares on new versions.
            if self.build_identity.build_manifest.build_major >= 20:
                # Without this empty policy file & its special signature, iBEC won't start.
                raise NotImplementedError()

        if self.device.lockdown:
            # normal mode
            self.logger.info('going into Recovery')

            # in case lockdown has disconnected while waiting for a ticket
            self.device.lockdown = LockdownClient(udid=self.device.lockdown.udid)
            self.device.lockdown.enter_recovery()

            self.device.lockdown = None
            self.device.irecv = IRecv(self.device.ecid)

        self.reconnect_irecv()
        ecid = self.device.irecv._device_info['ECID']
        self.logger.debug(f'ECID: {ecid}')

        self.logger.info('device booted into recovery')

        # now we load the iBEC
        try:
            self.send_ibec()
        except USBError:
            pass

        self.reconnect_irecv()

        # now finally do the magic to put the device into restore mode
        self.enter_restore()
