import logging
import plistlib
import time
import zipfile
from io import BytesIO

from cached_property import cached_property
from usb import USBError

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.img4 import stitch_component
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse


class Recovery:
    def __init__(self, ipsw: BytesIO, lockdown: LockdownClient = None, irecv: IRecv = None, tss: dict = None,
                 offline=False, behavior='Update'):
        self.ipsw = zipfile.ZipFile(ipsw)
        self.irecv = irecv  # type: IRecv
        self.lockdown = lockdown  # type: LockdownClient
        self.offline = offline

        if tss is not None:
            self.tss = TSSResponse(tss)
        else:
            self.tss = None

        if not self.is_image4_supported:
            raise NotImplementedError('is_image4_supported is False')

        logging.info(f'connected device: <ecid: {self.ecid} hardware_model: {self.hardware_model} '
                     f'image4-support: {self.is_image4_supported}>')

        self.build_identity = None

        logging.debug('scanning BuildManifest.plist for the correct BuildIdentity')
        self.build_manifest = plistlib.loads(self.ipsw.read('BuildManifest.plist'))
        for build_identity in self.build_manifest['BuildIdentities']:
            device_class = build_identity['Info']['DeviceClass'].lower()
            restore_behavior = build_identity['Info'].get('RestoreBehavior')
            logging.debug(f'iterating: class: {device_class} behavior: {restore_behavior}')
            if (device_class == self.hardware_model) and (restore_behavior == behavior):
                self.build_identity = build_identity
                break

        if self.build_identity is None:
            raise PyMobileDevice3Exception('failed to find the correct BuildIdentity from the BuildManifest.plist')

        self.build_major = int(self.build_manifest['ProductBuildVersion'][:2])

    @cached_property
    def ecid(self):
        if self.lockdown:
            return self.lockdown.ecid
        return self.irecv.ecid

    @cached_property
    def hardware_model(self):
        if self.lockdown:
            return self.lockdown.all_values['HardwareModel'].lower()
        return self.irecv.hardware_model

    @cached_property
    def is_image4_supported(self):
        if self.lockdown:
            return self.lockdown.get_value(key='Image4Supported')
        return self.irecv.is_image4_supported

    @cached_property
    def ap_nonce(self):
        if self.lockdown:
            return self.lockdown.get_value(key='ApNonce')
        return self.irecv.ap_nonce

    @cached_property
    def sep_nonce(self):
        if self.lockdown:
            return self.lockdown.get_value(key='SEPNonce')
        return self.irecv.sep_nonce

    def reconnect_irecv(self):
        logging.debug('waiting for device to reconnect in Recovery mode...')
        self.irecv = IRecv(ecid=self.ecid)

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

        self.tss_parameters_add_from_manifest(parameters)

        tss = TSSRequest(offline=self.offline)
        tss.add_common_tags(parameters, overrides)

        parameters['_OnlyFWComponents'] = True

        tss.add_ap_tags(parameters)

        return tss.img4_create_local_manifest()

    def tss_parameters_add_from_manifest(self, parameters):
        keys_to_copy = ('UniqueBuildID', 'Ap,OSLongVersion', 'ApChipID', 'ApBoardID', 'ApSecurityDomain',
                        'BMU,BoardID', 'BMU,ChipID', 'BbChipID', 'BbProvisioningManifestKeyHash',
                        'BbActivationManifestKeyHash', 'BbCalibrationManifestKeyHash',
                        'BbFactoryActivationManifestKeyHash', 'BbFDRSecurityKeyHash', 'BbSkeyId', 'SE,ChipID',
                        'Savage,ChipID', 'Savage,PatchEpoch', 'Yonkers,BoardID', 'Yonkers,ChipID',
                        'Yonkers,PatchEpoch', 'Rap,BoardID', 'Rap,ChipID', 'Rap,SecurityDomain', 'eUICC,ChipID',
                        'PearlCertificationRootPub', 'Manifest')

        for k in keys_to_copy:
            try:
                v = self.build_identity[k]
                if isinstance(v, str) and v.startswith('0x'):
                    v = int(v, 16)
                parameters[k] = v
            except KeyError:
                pass

    def get_tss_response(self):
        # populate parameters
        parameters = dict()

        parameters['ApECID'] = self.ecid
        if self.ap_nonce is not None:
            parameters['ApNonce'] = self.ap_nonce

        if self.sep_nonce is not None:
            parameters['ApSepNonce'] = self.sep_nonce

        parameters['ApProductionMode'] = True

        if self.is_image4_supported:
            parameters['ApSecurityMode'] = True
            parameters['ApSupportsImg4'] = True
        else:
            parameters['ApSupportsImg4'] = False

        self.tss_parameters_add_from_manifest(parameters)

        tss = TSSRequest(offline=self.offline)
        tss.add_common_tags(parameters)
        tss.add_ap_tags(parameters)

        # add personalized parameters
        if self.is_image4_supported:
            tss.add_ap_img4_tags(parameters)
        else:
            tss.add_ap_img3_tags(parameters)

        # normal mode; request baseband ticket aswell
        if self.lockdown is not None:
            pinfo = self.lockdown.get_value(key='FirmwarePreflightInfo')
            if pinfo:
                logging.debug('adding preflight info')

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
                    logging.debug('adding EUICCChipID info')
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
        if self.build_major > 8:
            if self.ap_nonce is None:
                # the first nonce request with older firmware releases can fail and it's OK
                logging.info('NOTE: Unable to get nonce from device')

        self.tss = self.get_tss_response()

        if self.build_major >= 20:
            raise NotImplementedError('not yet supported')

        return self.tss

    def build_identity_has_component(self, component):
        return component in self.build_identity['Manifest']

    def build_identity_get_component_path(self, component):
        return self.build_identity['Manifest'][component]['Info']['Path']

    def personalize_component(self, name, data, tss):
        # stitch ApImg4Ticket into IMG4 file
        blob = tss.ap_img4_ticket
        return stitch_component(name, data, blob)

    def get_component_path(self, name):
        path = None
        if self.tss:
            path = self.tss.get_path_by_entry(name)

        if path is None:
            logging.debug(f'NOTE: No path for component {name} in TSS, will fetch from build_identity')

        path = self.build_identity_get_component_path(name)

        if path is None:
            raise PyMobileDevice3Exception(f'Failed to find component path for {name}')

        return path

    def send_component(self, name):
        logging.info(f'sending {name}...')
        path = self.get_component_path(name)
        logging.debug(f'sending a patched version of: {path}')

        data = self.ipsw.read(path)
        signed_data = self.personalize_component(name, data, self.tss)

        self.irecv.send_buffer(signed_data)

    def send_component_and_command(self, name, command):
        self.send_component(name)
        self.irecv.send_command(command)

    def send_ibec(self):
        component = 'iBEC'
        self.send_component(component)
        self.irecv.send_command('go')
        self.irecv.ctrl_transfer(0x21, 1)

    def send_applelogo(self):
        component = 'RestoreLogo'
        self.send_component(component)
        self.irecv.send_command('setpicture 4')
        self.irecv.send_command('bgcolor 0 0 0')

    def send_loaded_by_iboot(self):
        manifest = self.build_identity['Manifest']
        for key, node in manifest.items():
            iboot = node['Info'].get('IsLoadedByiBoot', False)
            iboot_stg1 = node['Info'].get('IsLoadedByiBootStage1', False)

            assert isinstance(iboot, bool)
            assert isinstance(iboot_stg1, bool)

            if iboot and not iboot_stg1:
                logging.debug(f'{key} is loaded by iBoot')
                self.send_component_and_command(key, 'firmware')

    def send_ramdisk(self):
        component = 'RestoreRamDisk'
        ramdisk_size = self.irecv.getenv('ramdisk-size')
        logging.info(f'ramdisk-size: {ramdisk_size}')

        self.send_component(component)
        ramdisk_delay = self.irecv.getenv('ramdisk-delay')
        logging.info(f'ramdisk-delay: {ramdisk_delay}')

        self.irecv.send_command('ramdisk')

        time.sleep(2)

    def send_kernelcache(self):
        component = 'RestoreKernelCache'

        self.send_component(component)
        try:
            self.irecv.ctrl_transfer(0x21, 1)
        except USBError:
            pass

        if self.restore_boot_args:
            self.irecv.send_command(f'setenv boot-args {self.restore_boot_args}')

        try:
            self.irecv.send_command('bootx')
        except USBError:
            pass

    def set_autoboot(self, enable: bool):
        self.irecv.set_autoboot(enable)

    def enter_restore(self):
        if self.build_major >= 8:
            self.restore_boot_args = 'rd=md0 nand-enable-reformat=1 -progress'
        elif self.build_major >= 20:
            self.restore_boot_args = 'rd=md0 nand-enable-reformat=1 -progress -restore'

        # upload data to make device boot restore mode

        # Recovery Mode Environment:
        build_version = self.irecv.getenv('build-version')
        logging.info(f'iBoot build-version={build_version}')

        build_style = self.irecv.getenv('build-style')
        logging.info(f'iBoot build-style={build_style}')

        radio_error = self.irecv.getenv('radio-error')
        if radio_error:
            radio_error = int(radio_error)
            logging.info(f'radio-error: {radio_error}')
            radio_error_string = self.irecv.getenv('radio-error-string')
            if radio_error_string:
                logging.info(f'radio-error-string: {radio_error_string}')

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

    def boot_ramdisk(self):
        if self.tss is None:
            logging.info('fetching TSS record')
            self.fetch_tss_record()

        if self.lockdown:
            # normal mode
            logging.info('going into Recovery')
            self.lockdown.enter_recovery()

            self.lockdown = None
            self.irecv = IRecv(self.ecid)

        self.reconnect_irecv()
        ecid = self.irecv.device_info['ECID']
        logging.debug(f'ECID: {ecid}')

        logging.info('device booted into recovery')

        # now we load the iBEC
        try:
            self.send_ibec()
        except USBError:
            pass

        self.reconnect_irecv()

        # now finally do the magic to put the device into restore mode
        self.enter_restore()
