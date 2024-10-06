import hashlib
import logging
import time
from typing import Optional
from zipfile import ZipFile

from usb import USBError

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.restore.base_restore import BaseRestore, Behavior
from pymobiledevice3.restore.consts import lpol_file
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse

RESTORE_VARIANT_ERASE_INSTALL = 'Erase Install (IPSW)'
RESTORE_VARIANT_UPGRADE_INSTALL = 'Upgrade Install (IPSW)'
RESTORE_VARIANT_MACOS_RECOVERY_OS = 'macOS Customer'


class Recovery(BaseRestore):
    def __init__(self, ipsw: ZipFile, device: Device, tss: Optional[dict] = None, behavior: Behavior = Behavior.Update):
        super().__init__(ipsw, device, tss, behavior)
        self.tss_localpolicy = None
        self.tss_recoveryos_root_ticket = None
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

    async def get_tss_response(self) -> TSSResponse:
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
            pinfo = self.device.preflight_info
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
        return await tss.send_receive()

    def get_local_policy_tss_response(self):
        # populate parameters
        parameters = {
            'ApECID': self.device.ecid,
            'Ap,LocalBoot': False,
            'ApProductionMode': True,
        }

        if self.device.ap_nonce:
            parameters['ApNonce'] = self.device.ap_nonce

        sep_nonce = self.device.sep_nonce

        if sep_nonce:
            parameters['ApSepNonce'] = sep_nonce

        if self.device.is_image4_supported:
            parameters['ApSecurityMode'] = True
            parameters['ApSupportsImg4'] = True
        else:
            parameters['ApSupportsImg4'] = False

        self.build_identity.populate_tss_request_parameters(parameters)

        # Add Ap,LocalPolicy
        lpol = {
            'Digest': hashlib.sha384(lpol_file).digest(),
            'Trusted': True,
        }

        parameters['Ap,LocalPolicy'] = lpol

        # Add Ap,NextStageIM4MHash
        # Get previous TSS ticket
        ticket = self.tss.ap_img4_ticket
        # Hash it and add it as Ap,NextStageIM4MHash
        parameters['Ap,NextStageIM4MHash'] = hashlib.sha384(ticket).digest()

        # create basic request
        request = TSSRequest()

        # add common tags from manifest
        request.add_local_policy_tags(parameters)

        return request.send_receive()

    def get_recoveryos_root_ticket_tss_response(self):
        # populate parameters
        parameters = {
            'ApECID': self.device.ecid,
            'Ap,LocalBoot': False,
            'ApProductionMode': True,
        }

        if self.device.ap_nonce:
            parameters['ApNonce'] = self.device.ap_nonce

        sep_nonce = self.device.sep_nonce

        if sep_nonce:
            parameters['ApSepNonce'] = sep_nonce

        if self.device.is_image4_supported:
            parameters['ApSecurityMode'] = True
            parameters['ApSupportsImg4'] = True
        else:
            parameters['ApSupportsImg4'] = False

        self.build_identity.populate_tss_request_parameters(parameters)

        # create basic request
        # Adds @HostPlatformInfo, @VersionInfo, @UUID
        request = TSSRequest()

        # add common tags from manifest
        # Adds Ap,OSLongVersion, AppNonce, @ApImg4Ticket
        request.add_ap_img4_tags(parameters)

        # add AP tags from manifest
        request.add_common_tags(parameters)

        # add AP tags from manifest
        # Fills digests & co
        request.add_ap_recovery_tags(parameters)

        return request.send_receive()

    async def fetch_tss_record(self) -> TSSResponse:
        if self.ipsw.build_manifest.build_major > 8:
            if self.device.ap_nonce is None:
                # the first nonce request with older firmware releases can fail, and it's OK
                self.logger.info('NOTE: Unable to get nonce from device')

        self.tss = await self.get_tss_response()

        if self.macos_variant:
            self.tss_localpolicy = self.get_local_policy_tss_response()
            self.tss_recoveryos_root_ticket = self.get_recoveryos_root_ticket_tss_response()

        return self.tss

    def send_component(self, name: str):
        # Use a specific TSS ticket for the Ap,LocalPolicy component
        data = None
        tss = self.tss
        if name == 'Ap,LocalPolicy':
            tss = self.tss_localpolicy
            # If Ap,LocalPolicy => Inject an empty policy
            data = lpol_file

        data = self.build_identity.get_component(name, tss=tss, data=data).personalized_data
        self.logger.info(f'Sending {name} ({len(data)} bytes)...')
        self.device.irecv.send_buffer(data)

    def send_component_and_command(self, name, command):
        self.send_component(name)
        self.device.irecv.send_command(command)

    def send_ibec(self):
        component = 'iBEC'
        self.send_component(component)
        self.device.irecv.send_command('go', b_request=1)
        self.device.irecv.ctrl_transfer(0x21, 1)

    def send_applelogo(self, allow_missing=True):
        component = 'RestoreLogo'

        if not self.build_identity.has_component(component):
            if allow_missing:
                logging.warning(f'build_identity has no {component}')
                return
            else:
                raise PyMobileDevice3Exception(f'missing component: {component}')

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

    def send_iboot_stage1_components(self):
        manifest = self.build_identity['Manifest']
        for key, node in manifest.items():
            iboot = node['Info'].get('IsLoadedByiBoot', False)
            iboot_stg1 = node['Info'].get('IsLoadedByiBootStage1', False)

            assert isinstance(iboot, bool)
            assert isinstance(iboot_stg1, bool)

            if iboot and iboot_stg1:
                self.logger.debug(f'{key} is loaded by iBoot Stage 1')
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
            self.device.irecv.send_command('bootx', b_request=1)
        except USBError:
            pass

    def set_autoboot(self, enable: bool):
        self.device.irecv.set_autoboot(enable)

    def enter_restore(self):
        if self.ipsw.build_manifest.build_major >= 8:
            self.restore_boot_args = 'rd=md0 nand-enable-reformat=1 -progress'
        elif self.macos_variant:
            self.restore_boot_args = 'rd=md0 nand-enable-reformat=1 -progress -restore'

        # upload data to make device boot restore mode

        # Recovery Mode Environment:
        build_version = None
        while not build_version:
            self.logger.debug('build-version not yet supported. reconnecting...')
            time.sleep(1)

            # sometimes we manage to connect before iBEC actually started running
            build_version = self.device.irecv.getenv('build-version')
            self.reconnect_irecv()

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

        if self.build_identity.has_component('RestoreSEP'):
            # attempt to send rsepfirmware and load it, otherwise continue
            try:
                self.send_component_and_command('RestoreSEP', 'rsepfirmware')
            except USBError:
                pass

        self.send_kernelcache()

    async def dfu_enter_recovery(self) -> None:
        self.send_component('iBSS')
        self.reconnect_irecv()

        if 'SRTG' in self.device.irecv._device_info:
            raise PyMobileDevice3Exception('Device failed to enter recovery')

        if self.build_identity.build_manifest.build_major > 8:
            old_nonce = self.device.irecv.ap_nonce

            # reconnect
            self.reconnect_irecv()
            nonce = self.device.irecv.ap_nonce

            if old_nonce != nonce:
                # Welcome iOS5. We have to re-request the TSS with our nonce.
                self.tss = await self.get_tss_response()

            self.device.irecv.set_configuration(1)

            # Now, before sending iBEC, we must send necessary firmwares on new versions.
            if self.macos_variant:
                # Without this empty policy file & its special signature, iBEC won't start.
                self.send_component_and_command('Ap,LocalPolicy', 'lpolrestore')
                self.send_iboot_stage1_components()
                self.device.irecv.set_autoboot(False)
                self.device.irecv.send_command('setenvnp boot-args rd=md0 nand-enable-reformat=1 -progress -restore')
                self.send_applelogo(allow_missing=False)

            mode = self.device.irecv.mode
            # send iBEC
            self.send_component('iBEC')

            if self.device.irecv and mode.is_recovery:
                time.sleep(1)
                self.device.irecv.send_command('go', b_request=1)

                if self.build_identity.build_manifest.build_major < 20:
                    try:
                        self.device.irecv.ctrl_transfer(0x21, 1, timeout=5000)
                    except USBError:
                        pass

                self.logger.debug('Waiting for device to disconnect...')
                time.sleep(10)

        self.logger.debug('Waiting for device to reconnect in recovery mode...')
        self.reconnect_irecv(is_recovery=True)

    async def boot_ramdisk(self) -> None:
        if self.tss is None:
            self.logger.info('fetching TSS record')
            await self.fetch_tss_record()

        if self.device.lockdown:
            # normal mode
            self.logger.info('going into Recovery')

            # in case lockdown has disconnected while waiting for a ticket
            self.device.lockdown = create_using_usbmux(serial=self.device.lockdown.udid, connection_type='USB')
            self.device.lockdown.enter_recovery()

            self.device.lockdown = None
            self.device.irecv = IRecv(self.device.ecid)
            self.reconnect_irecv()

        if self.device.irecv.mode == Mode.DFU_MODE:
            # device is currently in DFU mode, place it into recovery mode
            await self.dfu_enter_recovery()

        elif self.device.irecv.mode.is_recovery:
            # now we load the iBEC
            try:
                self.send_ibec()
            except USBError:
                pass

            self.reconnect_irecv(is_recovery=True)

        self.logger.info('device booted into recovery')

        # now finally do the magic to put the device into restore mode
        self.enter_restore()
