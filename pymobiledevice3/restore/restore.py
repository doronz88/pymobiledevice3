import binascii
import hashlib
import logging
import os
import plistlib
import struct
import tempfile
import uuid
import zipfile
from io import BytesIO
from typing import Optional

import tqdm
from pymobiledevice3.exceptions import PyMobileDevice3Exception, NoDeviceConnectedError
from pymobiledevice3.restore.asr import ASRClient
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.fdr import start_fdr_thread, fdr_type
from pymobiledevice3.restore.ftab import Ftab
from pymobiledevice3.restore.ipsw.ipsw import IPSW
from pymobiledevice3.restore.recovery import Recovery
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse
from pymobiledevice3.utils import plist_access_path

lpol_file = bytearray([0x30, 0x14, 0x16, 0x04, 0x49, 0x4d, 0x34, 0x50,
                       0x16, 0x04, 0x6c, 0x70, 0x6f, 0x6c, 0x16, 0x03,
                       0x31, 0x2e, 0x30, 0x04, 0x01, 0x00])

PROGRESS_BAR_OPERATIONS = {
    11: 'CREATE_PARTITION_MAP',
    12: 'CREATE_FILESYSTEM',
    13: 'RESTORE_IMAGE',
    14: 'VERIFY_RESTORE',
    15: 'CHECK_FILESYSTEMS',
    16: 'MOUNT_FILESYSTEMS',
    17: 'FIXUP_VAR',
    18: 'FLASH_FIRMWARE',
    19: 'UPDATE_BASEBAND',
    20: 'SET_BOOT_STAGE',
    21: 'REBOOT_DEVICE',
    22: 'SHUTDOWN_DEVICE',
    23: 'TURN_ON_ACCESSORY_POWER',
    24: 'CLEAR_BOOTARGS',
    25: 'MODIFY_BOOTARGS',
    26: 'INSTALL_ROOT',
    27: 'INSTALL_KERNELCACHE',
    28: 'WAIT_FOR_NAND',
    29: 'UNMOUNT_FILESYSTEMS',
    30: 'SET_DATETIME',
    31: 'EXEC_IBOOT',
    32: 'FINALIZE_NAND_EPOCH_UPDATE',
    33: 'CHECK_INAPPR_BOOT_PARTITIONS',
    34: 'CREATE_FACTORY_RESTORE_MARKER',
    35: 'LOAD_FIRMWARE',
    36: 'REQUESTING_FUD_DATA',
    37: 'REMOVING_ACTIVATION_RECORD',
    38: 'CHECK_BATTERY_VOLTAGE',
    39: 'WAIT_BATTERY_CHARGE',
    40: 'CLOSE_MODEM_TICKETS',
    41: 'MIGRATE_DATA',
    42: 'WIPE_STORAGE_DEVICE',
    43: 'SEND_APPLE_LOGO',
    44: 'CHECK_LOGS',
    46: 'CLEAR_NVRAM',
    47: 'UPDATE_GAS_GAUGE',
    48: 'PREPARE_BASEBAND_UPDATE',
    49: 'BOOT_BASEBAND',
    50: 'CREATE_SYSTEM_KEYBAG',
    51: 'UPDATE_IR_MCU_FIRMWARE',
    52: 'RESIZE_SYSTEM_PARTITION',
    53: 'COLLECTING_UPDATER_OUTPUT',
    54: 'PAIR_STOCKHOLM',
    55: 'UPDATE_STOCKHOLM',
    56: 'UPDATE_SWDHID',
    57: 'CERTIFY_SEP',
    58: 'UPDATE_NAND_FIRMWARE',
    59: 'UPDATE_SE_FIRMWARE',
    60: 'UPDATE_SAVAGE',
    61: 'INSTALLING_DEVICETREE',
    62: 'CERTIFY_SAVAGE',
    63: 'SUBMITTING_PROVINFO',
    64: 'CERTIFY_YONKERS',
    65: 'UPDATE_ROSE',
    66: 'UPDATE_VERIDIAN',
    67: 'CREATING_PROTECTED_VOLUME',
    68: 'RESIZING_MAIN_FS_PARTITION',
    69: 'CREATING_RECOVERY_OS_VOLUME',
    70: 'INSTALLING_RECOVERY_OS_FILES',
    71: 'INSTALLING_RECOVERY_OS_IMAGE',
    74: 'REQUESTING_EAN_DATA',
    77: 'SEALING_SYSTEM_VOLUME',
}

# extracted from ac2
SUPPORTED_DATA_TYPES = {
    'BasebandBootData': False,
    'BasebandData': False,
    'BasebandStackData': False,
    'BasebandUpdaterOutputData': False,
    'BuildIdentityDict': False,
    'BuildIdentityDictV2': False,
    'DataType': False,
    'DiagData': False,
    'EANData': False,
    'FDRMemoryCommit': False,
    'FDRTrustData': False,
    'FUDData': False,
    'FileData': False,
    'FileDataDone': False,
    'FirmwareUpdaterData': False,
    'GrapeFWData': False,
    'HPMFWData': False,
    'HostSystemTime': True,
    'KernelCache': False,
    'NORData': False,
    'NitrogenFWData': True,
    'OpalFWData': False,
    'OverlayRootDataCount': False,
    'OverlayRootDataForKey': True,
    'PeppyFWData': True,
    'PersonalizedBootObjectV3': False,
    'PersonalizedData': True,
    'ProvisioningData': False,
    'RamdiskFWData': True,
    'RecoveryOSASRImage': True,
    'RecoveryOSAppleLogo': True,
    'RecoveryOSDeviceTree': True,
    'RecoveryOSFileAssetImage': True,
    'RecoveryOSIBEC': True,
    'RecoveryOSIBootFWFilesImages': True,
    'RecoveryOSImage': True,
    'RecoveryOSKernelCache': True,
    'RecoveryOSLocalPolicy': True,
    'RecoveryOSOverlayRootDataCount': False,
    'RecoveryOSRootTicketData': True,
    'RecoveryOSStaticTrustCache': True,
    'RecoveryOSVersionData': True,
    'RootData': False,
    'RootTicket': False,
    'S3EOverride': False,
    'SourceBootObjectV3': False,
    'SourceBootObjectV4': False,
    'SsoServiceTicket': False,
    'StockholmPostflight': False,
    'SystemImageCanonicalMetadata': False,
    'SystemImageData': False,
    'SystemImageRootHash': False,
    'USBCFWData': False,
    'USBCOverride': False,
}

# extracted from ac2
SUPPORTED_MESSAGE_TYPES = {
    'BBUpdateStatusMsg': False,
    'CheckpointMsg': True,
    'DataRequestMsg': False,
    'FDRSubmit': True,
    'MsgType': False,
    'PreviousRestoreLogMsg': False,
    'ProgressMsg': False,
    'ProvisioningAck': False,
    'ProvisioningInfo': False,
    'ProvisioningStatusMsg': False,
    'ReceivedFinalStatusMsg': False,
    'RestoredCrash': True,
    'StatusMsg': False,
}


class Restore:
    def __init__(self, ipsw: BytesIO, device: Device, tss=None, offline=False,
                 behavior='Update'):

        self.ipsw = IPSW(ipsw)
        self.device = device
        self.build_identity = self.ipsw.build_manifest.get_build_identity(self.device.hardware_model, behavior)

        self.recovery = Recovery(ipsw, device, tss=tss, offline=offline, behavior=behavior)
        self.offline = offline
        self.bbtss = None  # type: Optional[TSSResponse]
        self.tss_recoveryos_root_ticket = None  # type: Optional[TSSResponse]
        self._restored = None  # type: Optional[RestoredClient]
        self._restore_finished = False

        # query preflight info while device may still be in normal mode
        self._preflight_info = self.device.preflight_info

        # prepare progress bar for OS component verify
        self._pb_verify_restore = None
        self._pb_verify_restore_old_value = None

    def send_filesystem(self, message: dict):
        logging.info('about to send filesystem...')

        asr = ASRClient()

        logging.info('connected to ASR')

        # this step sends requested chunks of data from various offsets to asr so
        # it can validate the filesystem before installing it
        logging.info('validating the filesystem')
        with self.ipsw.open_path(self.build_identity.get_component_path('OS')) as filesystem:
            asr.perform_validation(filesystem)
            logging.info('filesystem validated')

            # once the target filesystem has been validated, ASR then requests the
            # entire filesystem to be sent.
            logging.info('sending filesystem now...')
            asr.send_payload(filesystem)

    def get_build_identity_from_request(self, msg):
        # TODO: extract build identity from msg
        return self.build_identity

    def send_buildidentity(self, message: dict):
        logging.info('About to send BuildIdentity Dict...')
        req = {'BuildIdentityDict': dict(self.get_build_identity_from_request(message))}
        arguments = message['Arguments']
        variant = arguments.get('Variant')

        if variant:
            req['Variant'] = variant
        else:
            req['Variant'] = 'Erase'

        logging.info('Sending BuildIdentityDict now...')
        self._restored.send(req)

    def extract_global_manifest(self):
        build_info = self.build_identity.get('Info')
        if build_info is None:
            raise PyMobileDevice3Exception('build identity does not contain an "Info" element')

        device_class = build_info.get('DeviceClass')
        if device_class is None:
            raise PyMobileDevice3Exception('build identity does not contain an "DeviceClass" element')

        macos_variant = build_info.get('MacOSVariant')
        if macos_variant is None:
            raise PyMobileDevice3Exception('build identity does not contain an "MacOSVariant" element')

        # The path of the global manifest is hardcoded. There's no pointer to in the build manifest.
        return self.ipsw.get_global_manifest(macos_variant, device_class)

    def send_personalized_boot_object(self, message: dict):
        image_name = message['Arguments']['ImageName']
        component_name = image_name
        logging.info(f'About to send {component_name}...')

        if image_name == '__GlobalManifest__':
            data = self.extract_global_manifest()
        elif image_name == '__RestoreVersion__':
            data = self.ipsw.restore_version
        elif image_name == '__SystemVersion__':
            data = self.ipsw.system_version
        else:
            data = self.build_identity.get_component(component_name, tss=self.recovery.tss).personalized_data

        logging.info(f'Sending {component_name} now...')
        chunk_size = 8192
        for i in range(0, len(data), chunk_size):
            self._restored.send({'FileData': data[i:i + chunk_size]})

        # Send FileDataDone
        self._restored.send({'FileDataDone': True})

        logging.info(f'Done sending {component_name}')

    def get_recovery_os_local_policy_tss_response(self, args):
        # populate parameters
        parameters = {
            'ApECID': self.device.ecid,
            'Ap,LocalBoot': True,
            'ApProductionMode': True,
            'ApSecurityMode': True,
            'ApSupportsImg4': True,
        }

        self.build_identity.populate_tss_request_parameters(parameters)

        # Add Ap,LocalPolicy
        lpol = {
            'Digest': hashlib.sha384(lpol_file).digest(),
            'Trusted': True,
        }

        parameters['Ap,LocalPolicy'] = lpol

        parameters['Ap,NextStageIM4MHash'] = args['Ap,NextStageIM4MHash']
        parameters['Ap,RecoveryOSPolicyNonceHash'] = args['Ap,RecoveryOSPolicyNonceHash']

        vol_uuid = args['Ap,VolumeUUID']
        vol_uuid = binascii.unhexlify(vol_uuid.replace('-', ''))
        parameters['Ap,VolumeUUID'] = vol_uuid

        # create basic request
        request = TSSRequest(self.offline)

        # add common tags from manifest
        request.add_local_policy_tags(parameters)

        logging.info('Requesting SHSH blobs...')
        return request.send_receive()

    def send_restore_local_policy(self, message: dict):
        component = 'Ap,LocalPolicy'

        # The Update mode does not have a specific build identity for the recovery os.
        tss_localpolicy = self.get_recovery_os_local_policy_tss_response(message['Arguments'])

        self._restored.send({'Ap,LocalPolicy': self.build_identity.get_component(component, tss=tss_localpolicy,
                                                                                 data=lpol_file).personalized_data})

    def send_recovery_os_root_ticket(self, message: dict):
        logging.info('About to send RecoveryOSRootTicket...')

        if self.tss_recoveryos_root_ticket is None:
            raise PyMobileDevice3Exception('Cannot send RootTicket without TSS')

        logging.info('Sending RecoveryOSRootTicket now...')
        self._restored.send({'RootTicketData': self.tss_recoveryos_root_ticket.ap_img4_ticket})

    def send_root_ticket(self, message: dict):
        logging.info('About to send RootTicket...')

        if self.recovery.tss is None:
            raise PyMobileDevice3Exception('Cannot send RootTicket without TSS')

        logging.info('Sending RootTicket now...')
        self._restored.send({'RootTicketData': self.recovery.tss.ap_img4_ticket})

    def send_nor(self, message: dict):
        logging.info('About to send NORData...')
        llb_path = self.build_identity.get_component('LLB', tss=self.recovery.tss).path
        llb_filename_offset = llb_path.find('LLB')

        if llb_filename_offset == -1:
            raise PyMobileDevice3Exception('Unable to extract firmware path from LLB filename')

        firmware_path = llb_path[:llb_filename_offset - 1]
        logging.info(f'Found firmware path: {firmware_path}')

        firmware_files = dict()
        try:
            firmware = self.ipsw.get_firmware(firmware_path)
            firmware_files = firmware.get_files()
        except KeyError:
            logging.info('Getting firmware manifest from build identity')
            build_id_manifest = self.build_identity['Manifest']
            for component, manifest_entry in build_id_manifest.items():
                if isinstance(manifest_entry, dict):
                    is_fw = plist_access_path(manifest_entry, ('Info', 'IsFirmwarePayload'), bool)
                    loaded_by_iboot = plist_access_path(manifest_entry, ('Info', 'IsLoadedByiBoot'), bool)
                    is_secondary_fw = plist_access_path(manifest_entry, ('Info', 'IsSecondaryFirmwarePayload'), bool)

                    if is_fw or (is_secondary_fw and loaded_by_iboot):
                        firmware_files[component] = plist_access_path(manifest_entry, ('Info', 'Path'))

        component = 'LLB'
        llb_data = self.build_identity.get_component(component, tss=self.recovery.tss,
                                                     path=llb_path).personalized_data
        req = {'LlbImageData': llb_data}

        if self.ipsw.build_manifest.build_major >= 20:
            # Starting with M1 macs, it seems that NorImageData is now a dict.
            # Sending an array like previous versions results in restore success but the machine will SOS after
            # rebooting.
            norimage = dict()
        else:
            norimage = []

        for component, comppath in firmware_files.items():
            if component in ('LLB', 'RestoreSEP'):
                # skip LLB, it's already passed in LlbImageData
                # skip RestoreSEP, it's passed in RestoreSEPImageData
                continue

            nor_data = self.build_identity.get_component(component, tss=self.recovery.tss,
                                                         path=comppath).personalized_data

            if self.ipsw.build_manifest.build_major >= 20:
                norimage[component] = nor_data
            else:
                # make sure iBoot is the first entry in the array
                if 'iBoot' == component:
                    norimage = [nor_data] + norimage
                else:
                    norimage.append(nor_data)

        req['NorImageData'] = norimage

        for component in ('RestoreSEP', 'SEP'):
            comp = self.build_identity.get_component(component, tss=self.recovery.tss)
            if comp.path:
                req[f'{component}ImageData'] = comp.personalized_data

        logging.info('Sending NORData now...')
        self._restored.send(req)

    @staticmethod
    def get_bbfw_fn_for_element(elem):
        bbfw_fn_elem = {
            # ICE3 firmware files
            'RamPSI': 'psi_ram.fls',
            'FlashPSI': 'psi_flash.fls',
            # Trek firmware files
            'eDBL': 'dbl.mbn',
            'RestoreDBL': 'restoredbl.mbn',
            # Phoenix/Mav4 firmware files
            'DBL': 'dbl.mbn',
            'ENANDPRG': 'ENPRG.mbn',
            # Mav5 firmware files
            'RestoreSBL1': 'restoresbl1.mbn',
            'SBL1': 'sbl1.mbn',
            # ICE16 firmware files
            'RestorePSI': 'restorepsi.bin',
            'PSI': 'psi_ram.bin',
            # ICE19 firmware files
            'RestorePSI2': 'restorepsi2.bin',
            'PSI2': 'psi_ram2.bin',
            # Mav20 Firmware file
            'Misc': 'multi_image.mbn',
        }
        return bbfw_fn_elem.get(elem)

    def fls_parse(self, buffer):
        raise NotImplementedError()

    def fls_update_sig_blob(self, buffer, blob):
        raise NotImplementedError()

    def fls_insert_ticket(self, fls, bbticket):
        raise NotImplementedError()

    def sign_bbfw(self, bbfw_orig, bbtss, bb_nonce):
        # check for BBTicket in result
        bbticket = bbtss.bb_ticket
        bbfw_dict = bbtss.get('BasebandFirmware')
        is_fls = False
        signed_file = []

        with tempfile.NamedTemporaryFile() as tmp_zip_read:
            with tempfile.NamedTemporaryFile() as tmp_zip_write:
                bbfw_patched = zipfile.ZipFile(tmp_zip_write, 'w')

                tmp_zip_read.write(bbfw_orig)
                bbfw_orig = zipfile.ZipFile(tmp_zip_read.name, 'r')

                for key, blob in bbfw_dict.items():
                    if key.endswith('-Blob') and isinstance(blob, bytes):
                        key = key.split('-', 1)[0]
                        signfn = self.get_bbfw_fn_for_element(key)

                        if signfn is None:
                            raise PyMobileDevice3Exception(
                                f'can\'t match element name \'{key}\' to baseband firmware file name.')

                        if signfn.endswith('.fls'):
                            is_fls = True

                        buffer = bbfw_orig.read(signfn)

                        if is_fls:
                            fls = self.fls_parse(buffer)
                            data = self.fls_update_sig_blob(fls, blob)
                        else:
                            parsed_sig_offset = len(buffer) - len(blob)
                            data = buffer[:parsed_sig_offset] + blob

                        bbfw_patched.writestr(bbfw_orig.getinfo(signfn), data)

                        if is_fls and (bb_nonce is None):
                            if key == 'RamPSI':
                                signed_file.append(signfn)
                        else:
                            signed_file.append(signfn)

                # remove everything but required files
                for entry in bbfw_orig.filelist:
                    keep = False
                    filename = entry.filename

                    if filename in signed_file:
                        keep = True

                    # check for anything but .mbn and .fls if bb_nonce is set
                    if bb_nonce and not keep:
                        ext = os.path.splitext(filename)[1]
                        keep |= ext in ('.fls', '.mbn', '.elf', '.bin')

                    if keep and (filename not in signed_file):
                        bbfw_patched.writestr(bbfw_orig.getinfo(filename), bbfw_orig.read(filename))

                if bb_nonce:
                    if is_fls:
                        # add BBTicket to file ebl.fls
                        buffer = bbfw_orig.read('ebl.fls')
                        fls = self.fls_parse(buffer)
                        data = self.fls_insert_ticket(fls, bbticket)
                        bbfw_patched.writestr('ebl.fls', data)
                    else:
                        # add BBTicket as bbticket.der
                        zname = zipfile.ZipInfo('bbticket.der')
                        zname.filename = 'bbticket.der'
                        ZIP_EXT_ATTR_FILE = 0o100000
                        zname.external_attr = (0o644 | ZIP_EXT_ATTR_FILE) << 16
                        bbfw_patched.writestr(zname, bbticket)

                bbfw_patched.close()
                tmp_zip_write.seek(0)
                return tmp_zip_write.read()

    def send_baseband_data(self, message: dict):
        logging.info(f'About to send BasebandData: {message}')

        # NOTE: this function is called 2 or 3 times!

        # setup request data
        arguments = message['Arguments']
        bb_chip_id = arguments.get('ChipID')
        bb_cert_id = arguments.get('CertID')
        bb_snum = arguments.get('ChipSerialNo')
        bb_nonce = arguments.get('Nonce')
        bbtss = self.bbtss

        if (bb_nonce is None) or (self.bbtss is None):
            # populate parameters
            parameters = {'ApECID': self.device.ecid}
            if bb_nonce:
                parameters['BbNonce'] = bb_nonce
            parameters['BbChipID'] = bb_chip_id
            parameters['BbGoldCertId'] = bb_cert_id
            parameters['BbSNUM'] = bb_snum

            self.build_identity.populate_tss_request_parameters(parameters)

            # create baseband request
            request = TSSRequest(self.offline)

            # add baseband parameters
            request.add_common_tags(parameters)
            request.add_baseband_tags(parameters)

            fdr_support = self.build_identity['Info'].get('FDRSupport', False)
            if fdr_support:
                request.update({'ApProductionMode': True, 'ApSecurityMode': True})

            logging.info('Sending Baseband TSS request...')
            bbtss = request.send_receive()

            if bb_nonce:
                # keep the response for later requests
                self.bbtss = bbtss

        # get baseband firmware file path from build identity
        bbfwpath = self.build_identity['Manifest']['BasebandFirmware']['Info']['Path']

        # extract baseband firmware to temp file
        bbfw = self.ipsw.read(bbfwpath)

        buffer = self.sign_bbfw(bbfw, bbtss, bb_nonce)

        logging.info('Sending BasebandData now...')
        self._restored.send({'BasebandData': buffer})

    def send_fdr_trust_data(self, message):
        logging.info('About to send FDR Trust data...')

        # TODO: FIXME: What should we send here?
        # Sending an empty dict makes it continue with FDR
        # and this is what iTunes seems to be doing too
        logging.info('Sending FDR Trust data now...')
        self._restored.send({})

    def send_image_data(self, message, image_list_k, image_type_k, image_data_k):
        logging.debug(f'send_image_data: {message}')
        arguments = message['Arguments']
        want_image_list = arguments.get(image_list_k)
        image_name = arguments.get('ImageName')

        if image_type_k is None:
            image_type_k = arguments['ImageType']

        if image_type_k is None:
            raise PyMobileDevice3Exception('missing ImageType')

        if want_image_list is None and image_name is None:
            logging.info(f'About to send {image_data_k}...')

        matched_images = []
        data_dict = dict()

        build_id_manifest = self.build_identity['Manifest']

        for component, manifest_entry in build_id_manifest.items():
            if not isinstance(manifest_entry, dict):
                continue

            is_image_type = manifest_entry['Info'].get(image_type_k)
            if is_image_type:
                if want_image_list:
                    logging.info(f'found {component} component')
                    matched_images.append(component)
                elif image_name is None or image_name == component:
                    if image_name is None:
                        logging.info(f'found {image_type_k} component \'{component}\'')

                    data_dict[component] = self.build_identity.get_component(component,
                                                                             tss=self.recovery.tss).personalized_data

        req = dict()
        if want_image_list:
            req[image_list_k] = matched_images
            logging.info(f'Sending {image_type_k} image list')
        else:
            if image_name:
                if image_name in data_dict:
                    req[image_data_k] = data_dict[image_name]
                req['ImageName'] = image_name
                logging.info(f'Sending {image_type_k} for {image_name}...')
            else:
                req[image_data_k] = data_dict
                logging.info(f'Sending {image_type_k} now...')

        self._restored.send(req)

    def get_se_firmware_data(self, info: dict):
        chip_id = info.get('SE,ChipID')
        if chip_id is None:
            chip_id = info.get('SEChipID')
            if chip_id is None:
                chip_id = self.build_identity['Manifest']['SEChipID']

        if chip_id == 0x20211:
            comp_name = 'SE,Firmware'
        elif chip_id in (0x73, 0x64, 0xC8, 0xD2):
            comp_name = 'SE,UpdatePayload'
        else:
            logging.warning(f'Unknown SE,ChipID {chip_id} detected. Restore might fail.')

            if self.build_identity.has_component('SE,UpdatePayload'):
                comp_name = 'SE,UpdatePayload'
            elif self.build_identity.has_component('SE,Firmware'):
                comp_name = 'SE,Firmware'
            else:
                raise NotImplementedError('Neither \'SE,Firmware\' nor \'SE,UpdatePayload\' found in build identity.')

        component_data = self.build_identity.get_component(comp_name).data

        # create SE request
        request = TSSRequest(self.offline)
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add SE,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for SE TSS request
        request.add_se_tags(parameters, None)

        logging.info('Sending SE TSS request...')
        response = request.send_receive()

        if 'SE,Ticket' in response:
            logging.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception('No \'SE,Ticket\' in TSS response, this might not work')

        response['FirmwareData'] = component_data

        return response

    def get_yonkers_firmware_data(self, info: dict):
        # create Yonkers request
        request = TSSRequest(self.offline)
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add Yonkers,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Yonkers TSS request
        comp_name = request.add_yonkers_tags(parameters, None)

        if comp_name is None:
            raise PyMobileDevice3Exception('Could not determine Yonkers firmware component')

        logging.debug(f'restore_get_yonkers_firmware_data: using {comp_name}')

        logging.info('Sending SE Yonkers request...')
        response = request.send_receive()

        if 'Yonkers,Ticket' in response:
            logging.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception('No \'Yonkers,Ticket\' in TSS response, this might not work')

        # now get actual component data
        component_data = self.build_identity.get_component(comp_name).data

        firmware_data = {
            'YonkersFirmware': component_data,
        }

        response['FirmwareData'] = firmware_data

        return response

    def get_savage_firmware_data(self, info: dict):
        # create Savage request
        request = TSSRequest(self.offline)
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add Savage,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Savage TSS request
        comp_name = request.add_savage_tags(parameters, None)

        if comp_name is None:
            raise PyMobileDevice3Exception('Could not determine Savage firmware component')

        logging.debug(f'restore_get_savage_firmware_data: using {comp_name}')

        logging.info('Sending SE Savage request...')
        response = request.send_receive()

        if 'Savage,Ticket' in response:
            logging.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception('No \'Savage,Ticket\' in TSS response, this might not work')

        # now get actual component data
        component_data = self.build_identity.get_component(comp_name).data
        component_data = struct.pack('<L', len(component_data)) + b'\x00' * 12

        response['FirmwareData'] = component_data

        return response

    def get_rose_firmware_data(self, info: dict):
        logging.info(f'get_rose_firmware_data: {info}')

        # create Rose request
        request = TSSRequest(self.offline)
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        parameters['ApProductionMode'] = True

        if self.device.is_image4_supported:
            parameters['ApSecurityMode'] = True
            parameters['ApSupportsImg4'] = True
        else:
            parameters['ApSupportsImg4'] = False

        # add Rap,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Rose TSS request
        request.add_rose_tags(parameters, None)

        logging.info('Sending Rose TSS request...')
        response = request.send_receive()

        rose_ticket = response.get('Rap,Ticket')
        if rose_ticket is None:
            logging.error('No "Rap,Ticket" in TSS response, this might not work')

        comp_name = 'Rap,RTKitOS'
        component_data = self.build_identity.get_component(comp_name).data

        ftab = Ftab(component_data)

        comp_name = 'Rap,RestoreRTKitOS'
        if self.build_identity.has_component(comp_name):
            rftab = Ftab(self.build_identity.get_component(comp_name).data)

            component_data = rftab.get_entry_data(b'rrko')
            if component_data is None:
                logging.error('Could not find "rrko" entry in ftab. This will probably break things')
            else:
                ftab.add_entry(b'rrko', component_data)

        response['FirmwareData'] = ftab.data

        return response

    def get_veridian_firmware_data(self, info: dict):
        logging.info(f'get_veridian_firmware_data: {info}')
        comp_name = 'BMU,FirmwareMap'

        # create Veridian request
        request = TSSRequest(self.offline)
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add BMU,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Veridian TSS request
        request.add_veridian_tags(parameters, None)

        logging.info('Sending Veridian TSS request...')
        response = request.send_receive()

        ticket = response.get('BMU,Ticket')
        if ticket is None:
            logging.warning('No "BMU,Ticket" in TSS response, this might not work')

        component_data = self.build_identity.get_component(comp_name).data
        fw_map = plistlib.loads(component_data)
        fw_map['fw_map_digest'] = self.build_identity['Manifest'][comp_name]['Digest']

        bin_plist = plistlib.dumps(fw_map, fmt=plistlib.PlistFormat.FMT_BINARY)
        response['FirmwareData'] = bin_plist

        return response

    def send_firmware_updater_data(self, message: dict):
        logging.debug(f'got FirmwareUpdaterData request: {message}')
        arguments = message['Arguments']
        s_type = arguments['MessageArgType']
        updater_name = arguments['MessageArgUpdaterName']

        if s_type not in ('FirmwareResponseData',):
            raise PyMobileDevice3Exception(f'MessageArgType has unexpected value \'{s_type}\'')

        info = arguments['MessageArgInfo']

        if updater_name == 'SE':
            fwdict = self.get_se_firmware_data(info)
            if fwdict is None:
                raise PyMobileDevice3Exception('Couldn\'t get SE firmware data')

        elif updater_name == 'Savage':
            fwtype = 'Savage'
            info2 = info.get('YonkersDeviceInfo')
            if info2:
                fwtype = 'Yonkers'
                fwdict = self.get_yonkers_firmware_data(info2)
            else:
                fwdict = self.get_savage_firmware_data(info)
            if fwdict is None:
                raise PyMobileDevice3Exception(f'Couldn\'t get {fwtype} firmware data')

        elif updater_name == 'Rose':
            fwdict = self.get_rose_firmware_data(info)
            if fwdict is None:
                raise PyMobileDevice3Exception(f'Couldn\'t get Rose firmware data')

        elif updater_name == 'T200':
            fwdict = self.get_veridian_firmware_data(info)
            if fwdict is None:
                raise PyMobileDevice3Exception(f'Couldn\'t get Veridian firmware data')

        else:
            raise PyMobileDevice3Exception(f'Got unknown updater name: {updater_name}')

        logging.info('Sending FirmwareResponse data now...')
        self._restored.send({'FirmwareResponseData': fwdict})

    def send_firmware_updater_preflight(self, message: dict):
        logging.warning(f'send_firmware_updater_preflight: {message}')
        self._restored.send({})

    def send_component(self, component, component_name=None):
        if component_name is None:
            component_name = component

        logging.info(f'Sending now {component_name}...')
        self._restored.send(
            {f'{component_name}File': self.build_identity.get_component(component,
                                                                        tss=self.recovery.tss).personalized_data})

    def handle_data_request_msg(self, message: dict):
        # checks and see what kind of data restored is requests and pass the request to its own handler
        data_type = message.get('DataType')

        if not isinstance(data_type, str):
            return

        handlers = {
            # this request is sent when restored is ready to receive the filesystem
            'SystemImageData': self.send_filesystem,

            'BuildIdentityDict': self.send_buildidentity,
            'PersonalizedBootObjectV3': self.send_personalized_boot_object,
            'SourceBootObjectV4': self.send_personalized_boot_object,
            'RecoveryOSLocalPolicy': self.send_restore_local_policy,

            # this request is sent when restored is ready to receive the filesystem
            'RecoveryOSASRImage': self.send_filesystem,

            # Send RecoveryOS RTD
            'RecoveryOSRootTicketData': self.send_recovery_os_root_ticket,

            # send RootTicket (== APTicket from the TSS request)
            'RootTicket': self.send_root_ticket,

            'NORData': self.send_nor,
            'BasebandData': self.send_baseband_data,
            'FDRTrustData': self.send_fdr_trust_data,
            'FirmwareUpdaterData': self.send_firmware_updater_data,

            # TODO: verify
            'FirmwareUpdaterPreflight': self.send_firmware_updater_preflight,
        }

        components = {
            'KernelCache': self.send_component,
            'DeviceTree': self.send_component,
        }

        if data_type in handlers:
            handlers[data_type](message)
        elif data_type in components:
            components[data_type](data_type)
        elif data_type == 'SystemImageRootHash':
            self.send_component('SystemVolume', data_type)
        elif data_type == 'SystemImageCanonicalMetadata':
            self.send_component('Ap,SystemVolumeCanonicalMetadata', data_type)
        elif data_type == 'FUDData':
            self.send_image_data(message, 'FUDImageList', 'IsFUDFirmware', 'FUDImageData')
        elif data_type == 'PersonalizedData':
            self.send_image_data(message, 'ImageList', None, 'ImageData')
        elif data_type == 'EANData':
            self.send_image_data(message, 'EANImageList', 'IsEarlyAccessFirmware', 'EANData')
        else:
            logging.error(f'unknown data request: {message}')

    def handle_previous_restore_log_msg(self, message: dict):
        restorelog = message['PreviousRestoreLog']
        logging.info(f'PreviousRestoreLog: {restorelog}')

    def handle_progress_msg(self, message: dict):
        operation = message['Operation']
        if operation in PROGRESS_BAR_OPERATIONS:
            message['Operation'] = PROGRESS_BAR_OPERATIONS[operation]

        if message['Operation'] == 'VERIFY_RESTORE':
            progress = message['Progress']

            if self._pb_verify_restore is None:
                self._pb_verify_restore = tqdm.tqdm(total=100, desc='verify-restore')
                self._pb_verify_restore_old_value = 0

            self._pb_verify_restore.update(progress - self._pb_verify_restore_old_value)
            self._pb_verify_restore_old_value = progress

            if progress == 100:
                self._pb_verify_restore.close()
                self._pb_verify_restore = None

            return

        logging.info(f'progress-bar: {message}')

    def handle_status_msg(self, message: dict):
        logging.info(f'status message: {message}')
        status = message['Status']
        if status == 0:
            self._restore_finished = True
            self._restored.send({'MsgType': 'ReceivedFinalStatusMsg'})
        else:
            known_errors = {
                0xFFFFFFFFFFFFFFFF: 'verification error',
                6: 'disk failure',
                14: 'fail',
                27: 'failed to mount filesystems',
                51: 'failed to load SEP firmware',
                53: 'failed to recover FDR data',
                1015: 'X-Gold Baseband Update Failed. Defective Unit?',
            }

            if status in known_errors:
                logging.error(known_errors[status])
            else:
                logging.error('unknown error')

    def handle_checkpoint_msg(self, message: dict):
        logging.info(f'checkpoint: {message}')

    def handle_bb_update_status_msg(self, message: dict):
        logging.info(f'bb_update_status_msg: {message}')
        if not message['Accepted']:
            raise PyMobileDevice3Exception(str(message))

    def handle_baseband_updater_output_data(self, message: dict):
        # TODO: implement (can be copied from idevicerestore)
        logging.warning(f'restore_handle_baseband_updater_output_data: {message}')

    def restore_device(self):
        logging.debug('waiting for device to connect for restored service')
        while True:
            try:
                self._restored = RestoredClient()
                break
            except NoDeviceConnectedError:
                pass
        logging.info('connected to restored service')

        hardware_info = self._restored.query_value('HardwareInfo')['HardwareInfo']

        logging.info(f'hardware info: {hardware_info}')
        logging.info(f'version: {self._restored.version}')

        if self.recovery.tss.bb_ticket is not None:
            # initial TSS response contains a baseband ticket
            self.bbtss = self.recovery.tss

        logging.info('Starting FDR listener thread')
        start_fdr_thread(fdr_type.FDR_CTRL)

        opts = dict()
        opts['AutoBootDelay'] = 0

        if self._preflight_info:
            bbus = dict(self._preflight_info)
            bbus.pop('FusingStatus')
            bbus.pop('PkHash')
            opts['BBUpdaterState'] = bbus

            nonce = self._preflight_info.get('Nonce')
            if nonce is not None:
                opts['BasebandNonce'] = nonce

        opts['SupportedDataTypes'] = SUPPORTED_DATA_TYPES
        opts['SupportedMessageTypes'] = SUPPORTED_MESSAGE_TYPES

        if self.ipsw.build_manifest.build_major >= 20:
            raise NotImplementedError()
        else:
            opts['BootImageType'] = 'UserOrInternal'
            opts['DFUFileType'] = 'RELEASE'
            opts['DataImage'] = False
            opts['FirmwareDirectory'] = '.'
            opts['FlashNOR'] = True
            opts['KernelCacheType'] = 'Release'
            opts['NORImageType'] = 'production'
            opts['RestoreBundlePath'] = '/tmp/Per2.tmp'
            opts['SystemImageType'] = 'User'
            opts['UpdateBaseband'] = False

            sep = self.build_identity['Manifest']['SEP'].get('Info')
            if sep:
                required_capacity = sep.get('RequiredCapacity')
                if required_capacity:
                    logging.debug(f'TZ0RequiredCapacity: {required_capacity}')
                    opts['TZ0RequiredCapacity'] = required_capacity
            opts['PersonalizedDuringPreflight'] = True

        opts['RootToInstall'] = False
        guid = str(uuid.uuid4())
        opts['UUID'] = guid
        opts['CreateFilesystemPartitions'] = True
        opts['SystemImage'] = True

        if self.recovery.restore_boot_args:
            opts['RestoreBootArgs'] = self.recovery.restore_boot_args

        spp = self.build_identity['Info'].get('SystemPartitionPadding')
        if spp:
            spp = dict(spp)
        else:
            spp = {'128': 1280, '16': 160, '32': 320, '64': 640, '8': 80}
        opts['SystemPartitionPadding'] = spp

        # start the restore process
        self._restored.start_restore(opts)

        handlers = {
            # data request messages are sent by restored whenever it requires
            # files sent to the server by the client. these data requests include
            # SystemImageData, RootTicket, KernelCache, NORData and BasebandData requests
            'DataRequestMsg': self.handle_data_request_msg,

            # restore logs are available if a previous restore failed
            'PreviousRestoreLogMsg': self.handle_previous_restore_log_msg,

            # progress notification messages sent by the restored inform the client
            # of it's current operation and sometimes percent of progress is complete
            'ProgressMsg': self.handle_progress_msg,

            # status messages usually indicate the current state of the restored
            # process or often to signal an error has been encountered
            'StatusMsg': self.handle_status_msg,

            # checkpoint notifications
            'CheckpointMsg': self.handle_checkpoint_msg,

            # baseband update message
            'BBUpdateStatusMsg': self.handle_bb_update_status_msg,

            # baseband updater output data request
            'BasebandUpdaterOutputData': self.handle_baseband_updater_output_data,
        }

        # this is the restore process loop, it reads each message in from
        # restored and passes that data on to it's specific handler
        while not self._restore_finished:
            # finally, if any of these message handlers returned -1 then we encountered
            # an unrecoverable error, so we need to bail.
            message = self._restored.recv()

            # discover what kind of message has been received
            message_type = message.get('MsgType')

            if message_type in handlers:
                handlers[message_type](message)
            else:
                # there might be some other message types i'm not aware of, but I think
                # at least the "previous error logs" messages usually end up here
                logging.debug(f'unhandled message type received: {message}')

    def update(self):
        self.recovery.boot_ramdisk()

        # device is finally in restore mode, let's do this
        self.restore_device()
