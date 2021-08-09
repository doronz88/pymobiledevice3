import logging
import plistlib
import time
import zipfile
from io import BytesIO

import asn1
from usb import USBError

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.tss import TSSRequest
from pymobiledevice3.services.preboard import PreboardService


class RestoreService:
    def __init__(self, lockdown: LockdownClient, ipsw: BytesIO, tss=None):
        self.ipsw = zipfile.ZipFile(ipsw)
        self.tss = tss

        self._lockdown = lockdown
        self.hardware_model = self._lockdown.all_values['HardwareModel'].lower()
        self.ecid = self._lockdown.all_values['UniqueChipID']
        self.build_version = self._lockdown.all_values['BuildVersion']
        self.build_major = int(self.build_version[:2])
        self.is_image4_supported = self._lockdown.get_value(key='Image4Supported')

        if not self.is_image4_supported:
            raise NotImplementedError('is_image4_supported is False')

        logging.info(f'connected device: <ecid: {self.ecid} chipset: {self.hardware_model} build: {self.build_version} '
                     f'image4-support: {self.is_image4_supported}>')

        self.build_identity = None

        logging.debug('scanning BuildManifest.plist for the correct BuildIdentity')
        self.build_manifest = plistlib.loads(self.ipsw.read('BuildManifest.plist'))
        for build_identity in self.build_manifest['BuildIdentities']:
            device_class = build_identity['Info']['DeviceClass'].lower()
            restore_behavior = build_identity['Info']['RestoreBehavior']
            logging.debug(f'iterating: class: {device_class} behavior: {restore_behavior}')
            if (device_class == self.hardware_model) and (restore_behavior == 'Update'):
                self.build_identity = build_identity
                break

        if self.build_identity is None:
            raise PyMobileDevice3Exception('failed to find the correct BuildIdentity from the BuildManifest.plist')

        self.irecv = None  # type: IRecv

    def reconnect(self):
        logging.debug('Waiting for device to reconnect in Recovery mode...')
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

        keys_to_copy = ('UniqueBuildID', 'ApChipID', 'ApBoardID', 'ApSecurityDomain', 'Ap,OSLongVersion', 'BMU,BoardID',
                        'BMU,ChipID', 'BbChipID', 'BbProvisioningManifestKeyHash', 'BbActivationManifestKeyHash',
                        'BbCalibrationManifestKeyHash', 'BbFactoryActivationManifestKeyHash', 'BbFDRSecurityKeyHash',
                        'BbSkeyId', 'SE,ChipID', 'Savage,ChipID', 'Savage,PatchEpoch', 'Yonkers,BoardID',
                        'Yonkers,ChipID', 'Yonkers,PatchEpoch', 'Rap,BoardID', 'Rap,ChipID', 'Rap,SecurityDomain',
                        'eUICC,ChipID', 'PearlCertificationRootPub', 'Manifest',)
        for k in keys_to_copy:
            try:
                v = self.build_identity[k]
                if isinstance(v, str) and v.startswith('0x'):
                    v = int(v, 16)
                parameters[k] = v
            except KeyError:
                pass

        tss = TSSRequest()
        tss.add_common_flags(parameters, overrides)

        parameters['_OnlyFWComponents'] = True

        tss.add_ap_tags(parameters)

        return tss.img4_create_local_manifest()

    def normal_handle_create_stashbag(self, manifest):
        preboard = PreboardService(self._lockdown)
        return preboard.create_stashbag(manifest)

    def get_ap_nonce(self):
        return self._lockdown.get_value(key='ApNonce')

    def get_sep_nonce(self):
        return self._lockdown.get_value(key='SEPNonce')

    def tss_parameters_add_from_manifest(self, parameters):
        keys_to_copy = (
            'UniqueBuildID', 'Ap,OSLongVersion', 'ApChipID', 'ApBoardID', 'ApSecurityDomain',
            'BMU,BoardID', 'BMU,ChipID', 'BbChipID', 'BbProvisioningManifestKeyHash', 'BbActivationManifestKeyHash',
            'BbCalibrationManifestKeyHash', 'BbFactoryActivationManifestKeyHash', 'BbFDRSecurityKeyHash', 'BbSkeyId',
            'SE,ChipID', 'Savage,ChipID', 'Savage,PatchEpoch', 'Yonkers,BoardID', 'Yonkers,ChipID',
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

    def get_preflight_info(self):
        return self._lockdown.get_value(key='FirmwarePreflightInfo')

    def get_tss_response(self):
        # populate parameters
        parameters = dict()

        parameters['ApECID'] = self.ecid
        if self.ap_nonce is not None:
            parameters['ApNonce'] = self.ap_nonce

        sep_nonce = self.get_sep_nonce()
        if sep_nonce is not None:
            parameters['ApSepNonce'] = sep_nonce

        parameters['ApProductionMode'] = True

        if self.is_image4_supported:
            parameters['ApSecurityMode'] = True
            parameters['ApSupportsImg4'] = True
        else:
            parameters['ApSupportsImg4'] = False

        self.tss_parameters_add_from_manifest(parameters)

        tss = TSSRequest()
        tss.add_common_flags(parameters)
        tss.add_ap_tags(parameters)

        # add personalized parameters
        if self.is_image4_supported:
            tss.add_ap_img4_tags(parameters)
        else:
            tss.add_ap_img3_tags(parameters)

        # normal mode; request baseband ticket aswell
        pinfo = self.get_preflight_info()
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
        return tss.request_send()

    def fetch_tss_record(self):
        stashbag_commit_required = False
        if self._lockdown.all_values['HasSiDP']:
            logging.info('Checking if device requires stashbag...')
            manifest = self.get_preboard_manifest()

            logging.debug('creating stashbag...')
            response = self.normal_handle_create_stashbag(manifest)

            if not response.get('Skip', False):
                raise NotImplementedError('requiring stashbag not yet supported')

        if self.build_major > 8:
            self.ap_nonce = self.get_ap_nonce()
            if self.ap_nonce is None:
                # the first nonce request with older firmware releases can fail and it's OK
                logging.info('NOTE: Unable to get nonce from device')

        self.tss = self.get_tss_response()

        if self.build_major >= 20:
            raise NotImplementedError('not yet supported')

        if stashbag_commit_required:
            raise NotImplementedError('requiring stashbag not yet supported')

        return self.tss

    def tss_response_get_path_by_entry(self, component):
        node = self.tss.get(component)
        if node is not None:
            return node.get('Path')

        return None

    def build_identity_get_component_path(self, component):
        return self.build_identity['Manifest'][component]['Info']['Path']

    def tss_response_get_ap_img4_ticket(self):
        return self.tss.get('ApImg4Ticket')

    def img4_stitch_component(self, name, data, blob):
        logging.info(f'Personalizing IMG4 component {name}...')

        # first we need check if we have to change the tag for the given component
        decoder = asn1.Decoder()
        decoder.start(data)
        decoder.enter()

        decoder.read()
        tag, value = decoder.read()

        component_name_tag = {
            'RestoreKernelCache': b'rkrn',
            'RestoreDeviceTree': b'rdtr',
            'RestoreSEP': b'rsep',
            'RestoreLogo': b'rlgo',
            'RestoreTrustCache': b'rtsc',
            'RestoreDCP': b'rdcp',
            'Ap,RestoreTMU': b'rtmu',
            'Ap,RestoreCIO': b'rcio',
            'Ap,DCP2': b'dcp2',
        }

        logging.debug(f'tag: {tag} {value}')
        if name in component_name_tag:
            logging.debug('Tag found')
            data = data.replace(value.encode(), component_name_tag[name], 1)

        # create element header for the "IMG4" magic
        encoder = asn1.Encoder()
        encoder.start()

        encoder.enter(asn1.Numbers.Sequence)

        # create element header for the "IMG4" magic
        encoder.write(b'IMG4', asn1.Numbers.IA5String)

        decoder = asn1.Decoder()
        decoder.start(data)
        encoder.write(decoder.read()[1], nr=asn1.Numbers.Sequence, typ=asn1.Types.Constructed)

        encoder.enter(0, cls=asn1.Classes.Context)

        decoder = asn1.Decoder()
        decoder.start(blob)
        encoder.write(decoder.read()[1], nr=asn1.Numbers.Sequence, typ=asn1.Types.Constructed)

        encoder.leave()

        encoder.leave()

        return encoder.output()

    def personalize_component(self, name, data):
        blob = self.tss_response_get_ap_img4_ticket()

        # stitch ApImg4Ticket into IMG4 file
        return self.img4_stitch_component(name, data, blob)

    def recovery_send_component(self, name):
        logging.info(f'Sending {name}...')
        path = None
        if self.tss:
            path = self.tss_response_get_path_by_entry(name)

        if path is None:
            logging.debug(f'NOTE: No path for component {name} in TSS, will fetch from build_identity')

        path = self.build_identity_get_component_path(name)
        logging.debug(f'Sending a patched version of: {path}')

        data = self.ipsw.read(path)
        signed_data = self.personalize_component(name, data)

        self.irecv.send_buffer(signed_data)

    def recovery_send_component_and_command(self, name, command):
        self.recovery_send_component(name)
        self.irecv.send_command(command)

    def recovery_send_ibec(self):
        component = 'iBEC'
        self.recovery_send_component(component)
        self.irecv.send_command('go')
        self.irecv.ctrl_transfer(0x21, 1)

    def recovery_send_applelogo(self):
        component = 'RestoreLogo'
        self.recovery_send_component(component)
        self.irecv.send_command('setpicture 4')
        self.irecv.send_command('bgcolor 0 0 0')

    def recovery_send_loaded_by_iboot(self):
        manifest = self.build_identity['Manifest']
        for key, node in manifest.items():
            iboot = node['Info'].get('IsLoadedByiBoot', False)
            iboot_stg1 = node['Info'].get('IsLoadedByiBootStage1', False)

            assert isinstance(iboot, bool)
            assert isinstance(iboot_stg1, bool)

            if iboot and not iboot_stg1:
                logging.debug(f'{key} is loaded by iBoot')
                self.recovery_send_component_and_command(key, 'firmware')

    def recovery_send_ramdisk(self):
        component = 'RestoreRamDisk'
        ramdisk_size = self.irecv.getenv('ramdisk-size')
        logging.info(f'ramdisk-size: {ramdisk_size}')

        self.recovery_send_component(component)
        ramdisk_delay = self.irecv.getenv('ramdisk-delay')
        logging.info(f'ramdisk-delay: {ramdisk_delay}')

        self.irecv.send_command('ramdisk')

        time.sleep(2)

    def recovery_send_kernelcache(self):
        component = 'RestoreKernelCache'

        self.recovery_send_component(component)
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

    def recovery_set_autoboot(self, enable: bool):
        self.irecv.set_autoboot(enable)

    def recovery_enter_restore(self):
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

        self.recovery_set_autoboot(False)

        # send logo and show it
        self.recovery_send_applelogo()

        # send components loaded by iBoot
        self.recovery_send_loaded_by_iboot()

        # send ramdisk and run it
        self.recovery_send_ramdisk()

        # send devicetree and load it
        self.recovery_send_component_and_command('RestoreDeviceTree', 'devicetree')

        if 'RestoreSEP' in self.build_identity['Manifest']:
            # send rsepfirmware and load it
            self.recovery_send_component_and_command('RestoreSEP', 'rsepfirmware')

        self.recovery_send_kernelcache()

    def boot_ramdisk(self):
        if self.tss is None:
            logging.info('fetching TSS record')
            self.fetch_tss_record()

        logging.info('going into Recovery')
        self._lockdown.enter_recovery()
        self.reconnect()
        ecid = self.irecv.device_info['ECID']
        logging.debug(f'ECID: {ecid}')

        logging.info('device booted into recovery')

        # now we load the iBEC
        try:
            self.recovery_send_ibec()
        except USBError:
            pass

        self.reconnect()

        # now finally do the magic to put the device into restore mode
        self.recovery_enter_restore()

    def restore_device(self):
        # TODO: implement
        raise NotImplementedError('restore_device not yet implemented')

    def upgrade(self):
        self.boot_ramdisk()

        # device is finally in restore mode, let's do this
        self.restore_device()
