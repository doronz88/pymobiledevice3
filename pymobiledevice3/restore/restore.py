import binascii
import hashlib
import logging
import os
import plistlib
import struct
import tempfile
import zipfile
from io import BytesIO
from typing import Optional, Mapping

import tqdm

from pymobiledevice3.exceptions import PyMobileDevice3Exception, NoDeviceConnectedError
from pymobiledevice3.restore.asr import ASRClient
from pymobiledevice3.restore.consts import lpol_file, PROGRESS_BAR_OPERATIONS
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.fdr import start_fdr_thread, fdr_type
from pymobiledevice3.restore.ftab import Ftab
from pymobiledevice3.restore.ipsw.ipsw import IPSW
from pymobiledevice3.restore.recovery import Recovery
from pymobiledevice3.restore.restore_options import RestoreOptions
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse
from pymobiledevice3.utils import plist_access_path

known_errors = {
    0xFFFFFFFFFFFFFFFF: 'verification error',
    6: 'disk failure',
    14: 'fail',
    27: 'failed to mount filesystems',
    51: 'failed to load SEP firmware',
    53: 'failed to recover FDR data',
    1015: 'X-Gold Baseband Update Failed. Defective Unit?',
}


class Restore:
    def __init__(self, ipsw: BytesIO, device: Device, tss=None, behavior='Update'):
        self.logger = logging.getLogger(__name__)
        self.ipsw = IPSW(ipsw)
        self.device = device
        self.build_identity = self.ipsw.build_manifest.get_build_identity(self.device.hardware_model, behavior)

        self.recovery = Recovery(ipsw, device, tss=tss, behavior=behavior)
        self.bbtss = None  # type: Optional[TSSResponse]
        self.tss_recoveryos_root_ticket = None  # type: Optional[TSSResponse]
        self._restored = None  # type: Optional[RestoredClient]
        self._restore_finished = False

        # query preflight info while device may still be in normal mode
        self._preflight_info = self.device.preflight_info

        # prepare progress bar for OS component verify
        self._pb_verify_restore = None
        self._pb_verify_restore_old_value = None

        self._handlers = {
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

        self._data_request_handlers = {
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

        self._data_request_components = {
            'KernelCache': self.send_component,
            'DeviceTree': self.send_component,
        }

    def send_filesystem(self, message: Mapping):
        self.logger.info('about to send filesystem...')

        asr = ASRClient()

        self.logger.info('connected to ASR')

        # this step sends requested chunks of data from various offsets to asr so
        # it can validate the filesystem before installing it
        self.logger.info('validating the filesystem')
        with self.ipsw.open_path(self.build_identity.get_component_path('OS')) as filesystem:
            asr.perform_validation(filesystem)
            self.logger.info('filesystem validated')

            # once the target filesystem has been validated, ASR then requests the
            # entire filesystem to be sent.
            self.logger.info('sending filesystem now...')
            asr.send_payload(filesystem)

    def get_build_identity_from_request(self, msg):
        # TODO: extract build identity from msg
        return self.build_identity

    def send_buildidentity(self, message: Mapping):
        self.logger.info('About to send BuildIdentity Dict...')
        req = {'BuildIdentityDict': dict(self.get_build_identity_from_request(message))}
        arguments = message['Arguments']
        variant = arguments.get('Variant')

        if variant:
            req['Variant'] = variant
        else:
            req['Variant'] = 'Erase'

        self.logger.info('Sending BuildIdentityDict now...')
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

    def send_personalized_boot_object(self, message: Mapping):
        image_name = message['Arguments']['ImageName']
        component_name = image_name
        self.logger.info(f'About to send {component_name}...')

        if image_name == '__GlobalManifest__':
            data = self.extract_global_manifest()
        elif image_name == '__RestoreVersion__':
            data = self.ipsw.restore_version
        elif image_name == '__SystemVersion__':
            data = self.ipsw.system_version
        else:
            data = self.build_identity.get_component(component_name, tss=self.recovery.tss).personalized_data

        self.logger.info(f'Sending {component_name} now...')
        chunk_size = 8192
        for i in range(0, len(data), chunk_size):
            self._restored.send({'FileData': data[i:i + chunk_size]})

        # Send FileDataDone
        self._restored.send({'FileDataDone': True})

        self.logger.info(f'Done sending {component_name}')

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
        request = TSSRequest()

        # add common tags from manifest
        request.add_local_policy_tags(parameters)

        self.logger.info('Requesting SHSH blobs...')
        return request.send_receive()

    def send_restore_local_policy(self, message: Mapping):
        component = 'Ap,LocalPolicy'

        # The Update mode does not have a specific build identity for the recovery os.
        tss_localpolicy = self.get_recovery_os_local_policy_tss_response(message['Arguments'])

        self._restored.send({'Ap,LocalPolicy': self.build_identity.get_component(component, tss=tss_localpolicy,
                                                                                 data=lpol_file).personalized_data})

    def send_recovery_os_root_ticket(self, message: Mapping):
        self.logger.info('About to send RecoveryOSRootTicket...')

        if self.tss_recoveryos_root_ticket is None:
            raise PyMobileDevice3Exception('Cannot send RootTicket without TSS')

        self.logger.info('Sending RecoveryOSRootTicket now...')
        self._restored.send({'RootTicketData': self.tss_recoveryos_root_ticket.ap_img4_ticket})

    def send_root_ticket(self, message: Mapping):
        self.logger.info('About to send RootTicket...')

        if self.recovery.tss is None:
            raise PyMobileDevice3Exception('Cannot send RootTicket without TSS')

        self.logger.info('Sending RootTicket now...')
        self._restored.send({'RootTicketData': self.recovery.tss.ap_img4_ticket})

    def send_nor(self, message: Mapping):
        self.logger.info(f'send_nor: {message}')
        llb_path = self.build_identity.get_component('LLB', tss=self.recovery.tss).path
        llb_filename_offset = llb_path.find('LLB')

        if llb_filename_offset == -1:
            raise PyMobileDevice3Exception('Unable to extract firmware path from LLB filename')

        firmware_path = llb_path[:llb_filename_offset - 1]
        self.logger.info(f'Found firmware path: {firmware_path}')

        firmware_files = dict()
        try:
            firmware = self.ipsw.get_firmware(firmware_path)
            firmware_files = firmware.get_files()
        except KeyError:
            self.logger.info('Getting firmware manifest from build identity')
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

        # Starting at some versions, it seems that NorImageData is now a dict.
        # Sending an array like previous versions results in restore success but the machine will SOS after
        # rebooting.
        norimage_dict = False

        if self.ipsw.build_manifest.supported_product_types_family == 'iBridge' and \
                self.ipsw.build_manifest.build_major >= 18:
            # certain T2 versions
            norimage_dict = True

        if self.ipsw.build_manifest.build_major >= 20:
            # M1
            norimage_dict = True

        self.logger.debug(f'sending nor data as dict: {norimage_dict}')

        if norimage_dict:
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

            if norimage_dict:
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

        self.logger.info('Sending NORData now...')
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

    def send_baseband_data(self, message: Mapping):
        self.logger.info(f'About to send BasebandData: {message}')

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
            request = TSSRequest()

            # add baseband parameters
            request.add_common_tags(parameters)
            request.add_baseband_tags(parameters)

            fdr_support = self.build_identity['Info'].get('FDRSupport', False)
            if fdr_support:
                request.update({'ApProductionMode': True, 'ApSecurityMode': True})

            self.logger.info('Sending Baseband TSS request...')
            bbtss = request.send_receive()

            if bb_nonce:
                # keep the response for later requests
                self.bbtss = bbtss

        # get baseband firmware file path from build identity
        bbfwpath = self.build_identity['Manifest']['BasebandFirmware']['Info']['Path']

        # extract baseband firmware to temp file
        bbfw = self.ipsw.read(bbfwpath)

        buffer = self.sign_bbfw(bbfw, bbtss, bb_nonce)

        self.logger.info('Sending BasebandData now...')
        self._restored.send({'BasebandData': buffer})

    def send_fdr_trust_data(self, message):
        self.logger.info('About to send FDR Trust data...')

        # TODO: FIXME: What should we send here?
        # Sending an empty dict makes it continue with FDR
        # and this is what iTunes seems to be doing too
        self.logger.info('Sending FDR Trust data now...')
        self._restored.send({})

    def send_image_data(self, message, image_list_k, image_type_k, image_data_k):
        self.logger.debug(f'send_image_data: {message}')
        arguments = message['Arguments']
        want_image_list = arguments.get(image_list_k)
        image_name = arguments.get('ImageName')
        build_id_manifest = self.build_identity['Manifest']

        if not want_image_list and image_name is not None:
            if image_name not in build_id_manifest:
                if image_name.startswith('Ap'):
                    image_name = image_name.replace('Ap', 'Ap,')
                    if image_name not in build_id_manifest:
                        raise PyMobileDevice3Exception(f'{image_name} not in build_id_manifest')

        if image_type_k is None:
            image_type_k = arguments['ImageType']

        if image_type_k is None:
            raise PyMobileDevice3Exception('missing ImageType')

        if want_image_list is None and image_name is None:
            self.logger.info(f'About to send {image_data_k}...')

        matched_images = []
        data_dict = dict()

        for component, manifest_entry in build_id_manifest.items():
            if not isinstance(manifest_entry, dict):
                continue

            is_image_type = manifest_entry['Info'].get(image_type_k)
            if is_image_type:
                if want_image_list:
                    self.logger.info(f'found {component} component')
                    matched_images.append(component)
                elif image_name is None or image_name == component:
                    if image_name is None:
                        self.logger.info(f'found {image_type_k} component \'{component}\'')
                    else:
                        self.logger.info(f'found component \'{component}\'')

                    data_dict[component] = self.build_identity.get_component(component,
                                                                             tss=self.recovery.tss).personalized_data

        req = dict()
        if want_image_list:
            req[image_list_k] = matched_images
            self.logger.info(f'Sending {image_type_k} image list')
        else:
            if image_name:
                if image_name in data_dict:
                    req[image_data_k] = data_dict[image_name]
                req['ImageName'] = image_name
                self.logger.info(f'Sending {image_type_k} for {image_name}...')
            else:
                req[image_data_k] = data_dict
                self.logger.info(f'Sending {image_type_k} now...')

        self._restored.send(req)

    def get_se_firmware_data(self, info: Mapping):
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
            self.logger.warning(f'Unknown SE,ChipID {chip_id} detected. Restore might fail.')

            if self.build_identity.has_component('SE,UpdatePayload'):
                comp_name = 'SE,UpdatePayload'
            elif self.build_identity.has_component('SE,Firmware'):
                comp_name = 'SE,Firmware'
            else:
                raise NotImplementedError('Neither \'SE,Firmware\' nor \'SE,UpdatePayload\' found in build identity.')

        component_data = self.build_identity.get_component(comp_name).data

        # create SE request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add SE,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for SE TSS request
        request.add_se_tags(parameters, None)

        self.logger.info('Sending SE TSS request...')
        response = request.send_receive()

        if 'SE,Ticket' in response:
            self.logger.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception('No \'SE,Ticket\' in TSS response, this might not work')

        response['FirmwareData'] = component_data

        return response

    def get_yonkers_firmware_data(self, info: Mapping):
        # create Yonkers request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add Yonkers,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Yonkers TSS request
        comp_name = request.add_yonkers_tags(parameters, None)

        if comp_name is None:
            raise PyMobileDevice3Exception('Could not determine Yonkers firmware component')

        self.logger.debug(f'restore_get_yonkers_firmware_data: using {comp_name}')

        self.logger.info('Sending SE Yonkers request...')
        response = request.send_receive()

        if 'Yonkers,Ticket' in response:
            self.logger.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception('No \'Yonkers,Ticket\' in TSS response, this might not work')

        # now get actual component data
        component_data = self.build_identity.get_component(comp_name).data

        firmware_data = {
            'YonkersFirmware': component_data,
        }

        response['FirmwareData'] = firmware_data

        return response

    def get_savage_firmware_data(self, info: Mapping):
        # create Savage request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add Savage,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Savage TSS request
        comp_name = request.add_savage_tags(parameters, None)

        if comp_name is None:
            raise PyMobileDevice3Exception('Could not determine Savage firmware component')

        self.logger.debug(f'restore_get_savage_firmware_data: using {comp_name}')

        self.logger.info('Sending SE Savage request...')
        response = request.send_receive()

        if 'Savage,Ticket' in response:
            self.logger.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception('No \'Savage,Ticket\' in TSS response, this might not work')

        # now get actual component data
        component_data = self.build_identity.get_component(comp_name).data
        component_data = struct.pack('<L', len(component_data)) + b'\x00' * 12

        response['FirmwareData'] = component_data

        return response

    def get_rose_firmware_data(self, info: Mapping):
        self.logger.info(f'get_rose_firmware_data: {info}')

        # create Rose request
        request = TSSRequest()
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

        self.logger.info('Sending Rose TSS request...')
        response = request.send_receive()

        rose_ticket = response.get('Rap,Ticket')
        if rose_ticket is None:
            self.logger.error('No "Rap,Ticket" in TSS response, this might not work')

        comp_name = 'Rap,RTKitOS'
        component_data = self.build_identity.get_component(comp_name).data

        ftab = Ftab(component_data)

        comp_name = 'Rap,RestoreRTKitOS'
        if self.build_identity.has_component(comp_name):
            rftab = Ftab(self.build_identity.get_component(comp_name).data)

            component_data = rftab.get_entry_data(b'rrko')
            if component_data is None:
                self.logger.error('Could not find "rrko" entry in ftab. This will probably break things')
            else:
                ftab.add_entry(b'rrko', component_data)

        response['FirmwareData'] = ftab.data

        return response

    def get_veridian_firmware_data(self, info: Mapping):
        self.logger.info(f'get_veridian_firmware_data: {info}')
        comp_name = 'BMU,FirmwareMap'

        # create Veridian request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add BMU,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Veridian TSS request
        request.add_veridian_tags(parameters, None)

        self.logger.info('Sending Veridian TSS request...')
        response = request.send_receive()

        ticket = response.get('BMU,Ticket')
        if ticket is None:
            self.logger.warning('No "BMU,Ticket" in TSS response, this might not work')

        component_data = self.build_identity.get_component(comp_name).data
        fw_map = plistlib.loads(component_data)
        fw_map['fw_map_digest'] = self.build_identity['Manifest'][comp_name]['Digest']

        bin_plist = plistlib.dumps(fw_map, fmt=plistlib.PlistFormat.FMT_BINARY)
        response['FirmwareData'] = bin_plist

        return response

    def get_tcon_firmware_data(self, info: Mapping):
        self.logger.info(f'restore_get_tcon_firmware_data: {info}')
        comp_name = 'Baobab,TCON'

        # create Baobab request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

        # add Baobab,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Baobab TSS request
        request.add_tcon_tags(parameters, None)

        self.logger.info('Sending Baobab TSS request...')
        response = request.send_receive()

        ticket = response.get('Baobab,Ticket')
        if ticket is None:
            self.logger.warning('No "Baobab,Ticket" in TSS response, this might not work')

        response['FirmwareData'] = self.build_identity.get_component(comp_name).data

        return response

    def send_firmware_updater_data(self, message: Mapping):
        self.logger.debug(f'got FirmwareUpdaterData request: {message}')
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
                raise PyMobileDevice3Exception('Couldn\'t get Rose firmware data')

        elif updater_name == 'T200':
            fwdict = self.get_veridian_firmware_data(info)
            if fwdict is None:
                raise PyMobileDevice3Exception('Couldn\'t get Veridian firmware data')

        elif updater_name == 'AppleTCON':
            fwdict = self.get_tcon_firmware_data(info)
            if fwdict is None:
                raise PyMobileDevice3Exception('Couldn\'t get TCON firmware data')

        else:
            raise PyMobileDevice3Exception('Got unknown updater name: {updater_name}')

        self.logger.info('Sending FirmwareResponse data now...')
        self._restored.send({'FirmwareResponseData': fwdict})

    def send_firmware_updater_preflight(self, message: Mapping):
        self.logger.warning(f'send_firmware_updater_preflight: {message}')
        self._restored.send({})

    def send_component(self, component, component_name=None):
        if component_name is None:
            component_name = component

        self.logger.info(f'Sending now {component_name}...')
        self._restored.send(
            {f'{component_name}File': self.build_identity.get_component(component,
                                                                        tss=self.recovery.tss).personalized_data})

    def handle_data_request_msg(self, message: Mapping):
        # checks and see what kind of data restored is requests and pass the request to its own handler
        data_type = message.get('DataType')

        if not isinstance(data_type, str):
            return

        if data_type in self._data_request_handlers:
            self._data_request_handlers[data_type](message)
        elif data_type in self._data_request_components:
            self._data_request_components[data_type](data_type)
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
            self.logger.error(f'unknown data request: {message}')

    def handle_previous_restore_log_msg(self, message: Mapping):
        restorelog = message['PreviousRestoreLog']
        self.logger.info(f'PreviousRestoreLog: {restorelog}')

    def handle_progress_msg(self, message: Mapping):
        operation = message['Operation']
        if operation in PROGRESS_BAR_OPERATIONS:
            message['Operation'] = PROGRESS_BAR_OPERATIONS[operation]

        if message['Operation'] == 'VERIFY_RESTORE':
            progress = message['Progress']

            if self._pb_verify_restore is None:
                self._pb_verify_restore = tqdm.tqdm(total=100, desc='verify-restore', dynamic_ncols=True)
                self._pb_verify_restore_old_value = 0

            self._pb_verify_restore.update(progress - self._pb_verify_restore_old_value)
            self._pb_verify_restore_old_value = progress

            if progress == 100:
                self._pb_verify_restore.close()
                self._pb_verify_restore = None

            return

        self.logger.info(f'progress-bar: {message}')

    def handle_status_msg(self, message: Mapping):
        self.logger.info(f'status message: {message}')
        status = message['Status']
        if status == 0:
            self._restore_finished = True
            self._restored.send({'MsgType': 'ReceivedFinalStatusMsg'})
        else:
            if status in known_errors:
                self.logger.error(known_errors[status])
            else:
                self.logger.error('unknown error')

    def handle_checkpoint_msg(self, message: Mapping):
        self.logger.info(f'checkpoint: {message}')

    def handle_bb_update_status_msg(self, message: Mapping):
        self.logger.info(f'bb_update_status_msg: {message}')
        if not message['Accepted']:
            raise PyMobileDevice3Exception(str(message))

    def handle_baseband_updater_output_data(self, message: Mapping):
        # TODO: implement (can be copied from idevicerestore)
        self.logger.warning(f'restore_handle_baseband_updater_output_data: {message}')

    def _connect_to_restored_service(self):
        while True:
            try:
                self._restored = RestoredClient()
                break
            except NoDeviceConnectedError:
                pass

    def restore_device(self):
        if self.ipsw.build_manifest.build_major >= 20:
            raise NotImplementedError()

        self.logger.debug('waiting for device to connect for restored service')
        self._connect_to_restored_service()
        self.logger.info('connected to restored service')

        self.logger.info(f'hardware info: {self._restored.hardware_info}')
        self.logger.info(f'version: {self._restored.version}')

        if self.recovery.tss.bb_ticket is not None:
            # initial TSS response contains a baseband ticket
            self.bbtss = self.recovery.tss

        self.logger.info('Starting FDR listener thread')
        start_fdr_thread(fdr_type.FDR_CTRL)

        sep = self.build_identity['Manifest']['SEP'].get('Info')
        spp = self.build_identity['Info'].get('SystemPartitionPadding')
        opts = RestoreOptions(preflight_info=self._preflight_info, sep=sep,
                              restore_boot_args=self.recovery.restore_boot_args, spp=spp)

        # start the restore process
        self._restored.start_restore(opts)

        # this is the restore process loop, it reads each message in from
        # restored and passes that data on to it's specific handler
        while not self._restore_finished:
            # finally, if any of these message handlers returned -1 then we encountered
            # an unrecoverable error, so we need to bail.
            message = self._restored.recv()

            # discover what kind of message has been received
            message_type = message.get('MsgType')

            if message_type in self._handlers:
                self._handlers[message_type](message)
            else:
                # there might be some other message types i'm not aware of, but I think
                # at least the "previous error logs" messages usually end up here
                self.logger.debug(f'unhandled message type received: {message}')

    def update(self):
        self.recovery.boot_ramdisk()

        # device is finally in restore mode, let's do this
        self.restore_device()
