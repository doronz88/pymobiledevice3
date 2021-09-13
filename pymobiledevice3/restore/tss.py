import logging
import plistlib
import time
import typing
from pathlib import Path
from uuid import uuid4

import asn1
import requests
from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.restore.img4 import img4_get_component_tag
from pymobiledevice3.utils import bytes_to_uint

TSS_CLIENT_VERSION_STRING = 'libauthinstall-776.60.1'
TICKETS_SUBDIR = Path('offline_requests')

OFFLINE_REQUEST_SCRIPT = """#!/bin/sh
curl -d "@{request}" -H 'Cache-Control: no-cache' -H 'Content-type: text/xml; charset="utf-8"' -H 'User-Agent: InetURL/1.0' -H 'Expect: ' 'http://gs.apple.com/TSS/controller?action=2' | tee {response} 
"""


class TSSResponse(dict):
    @property
    def ap_img4_ticket(self):
        ticket = self.get('ApImg4Ticket')

        if ticket is None:
            raise PyMobileDevice3Exception('TSS response doesn\'t contain a ApImg4Ticket')

        return ticket

    @property
    def bb_ticket(self):
        return self.get('BBTicket')

    def get_path_by_entry(self, component: str):
        node = self.get(component)
        if node is not None:
            return node.get('Path')

        return None


class TSSRequest:
    def __init__(self, offline=False):
        self._request = {
            '@BBTicket': True,
            '@HostPlatformInfo': 'mac',
            '@VersionInfo': TSS_CLIENT_VERSION_STRING,
            '@UUID': str(uuid4()).upper(),
        }
        self._offline = offline

    @staticmethod
    def apply_restore_request_rules(tss_entry: typing.Mapping, parameters: typing.Mapping, rules: list):
        for rule in rules:
            conditions_fulfilled = True
            conditions = rule['Conditions']
            for key, value in conditions.items():
                if not conditions_fulfilled:
                    break

                if key == 'ApRawProductionMode':
                    value2 = parameters.get('ApProductionMode')
                elif key == 'ApCurrentProductionMode':
                    value2 = parameters.get('ApProductionMode')
                elif key == 'ApRawSecurityMode':
                    value2 = parameters.get('ApSecurityMode')
                elif key == 'ApRequiresImage4':
                    value2 = parameters.get('ApSupportsImg4')
                elif key == 'ApDemotionPolicyOverride':
                    value2 = parameters.get('DemotionPolicy')
                elif key == 'ApInRomDFU':
                    value2 = parameters.get('ApInRomDFU')
                else:
                    logging.error(f'Unhandled condition {key} while parsing RestoreRequestRules')
                    value2 = None

                if value2:
                    conditions_fulfilled = value == value2
                else:
                    conditions_fulfilled = False

            if not conditions_fulfilled:
                continue

            actions = rule['Actions']
            for key, value in actions.items():
                if value != 255:
                    value2 = tss_entry.get(key)
                    if value2:
                        tss_entry.pop(key)
                    logging.debug(f'Adding {key}={value} to TSS entry')
                    tss_entry[key] = value
        return tss_entry

    def add_common_tags(self, parameters: typing.Mapping, overrides=None):
        keys = ('ApECID', 'UniqueBuildID', 'ApChipID', 'ApBoardID', 'ApSecurityDomain')
        for k in keys:
            if k in parameters:
                self._request[k] = parameters[k]
        if overrides is not None:
            self._request.update(overrides)

    def add_local_policy_tags(self, parameters: typing.Mapping):
        self._request['@ApImg4Ticket'] = True

        keys_to_copy = (
            'Ap,LocalBoot', 'Ap,LocalPolicy', 'Ap,NextStageIM4MHash', 'Ap,NextStageIM4MHash',
            'Ap,RecoveryOSPolicyNonceHash', 'Ap,VolumeUUID', 'ApECID', 'ApChipID', 'ApBoardID', 'ApSecurityDomain'
                                                                                                'ApNonce',
            'ApSecurityMode', 'ApProductionMode')

        for k in keys_to_copy:
            if k in parameters:
                self._request[k] = parameters[k]

    def add_vinyl_tags(self, parameters: typing.Mapping, overrides=None):
        self._request['@BBTicket'] = True
        self._request['@eUICC,Ticket'] = True

        keys = ('eUICC,ChipID', 'eUICC,EID', 'eUICC,RootKeyIdentifier')
        for k in keys:
            if k in parameters:
                self._request[k] = parameters[k]

        # set Nonce for eUICC,Gold component
        node = parameters.get('EUICCGoldNonce')
        if node is not None:
            n = self._request.get('eUICC,Gold')
            if n is not None:
                n['Nonce'] = node

        # set Nonce for eUICC,Main component
        node = parameters.get('EUICCMainNonce')
        if node is not None:
            n = self._request.get('eUICC,Main')
            if n is not None:
                n['Nonce'] = node

        if overrides is not None:
            self._request.update(overrides)

    def add_ap_tags(self, parameters: typing.Mapping, overrides=None):
        """ loop over components from build manifest """

        manifest_node = parameters['Manifest']

        # add components to request
        skipped_keys = ('BasebandFirmware', 'SE,UpdatePayload', 'BaseSystem', 'Diags',)
        for key, manifest_entry in manifest_node.items():
            if key in skipped_keys:
                continue

            info_dict = manifest_entry.get('Info')
            if info_dict is None:
                continue

            if parameters.get('ApSupportsImg4', False) and ('RestoreRequestRules' not in info_dict):
                logging.debug(f'Skipping "{key}" as it doesn\'t have RestoreRequestRules')
                continue

            if parameters.get('_OnlyFWComponents', False):
                if not manifest_node.get('Trusted', False):
                    logging.debug(f'skipping {key} as it is not trusted')
                    continue
                info = manifest_node['Info']
                if not info['IsFirmwarePayload'] and not info['IsSecondaryFirmwarePayload'] and \
                        not info['IsFUDFirmware']:
                    logging.debug(f'skipping {key} as it is neither firmware nor secondary nor FUD firmware payload')
                    continue

            # copy this entry
            tss_entry = dict(manifest_entry)

            # remove obsolete Info node
            tss_entry.pop('Info')

            # handle RestoreRequestRules
            if 'Info' in manifest_entry and 'RestoreRequestRules' in manifest_entry['Info']:
                rules = manifest_entry['Info']['RestoreRequestRules']
                if rules:
                    logging.debug(f'Applying restore request rules for entry {key}')
                    tss_entry = self.apply_restore_request_rules(tss_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            node = manifest_entry.get('Trusted', False)
            if node:
                if manifest_entry.get('Digest') is None:
                    tss_entry['Digest'] = bytes()

            self._request[key] = tss_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_ap_img3_tags(self, parameters: typing.Mapping):
        if 'ApNonce' in parameters:
            self._request['ApNonce'] = parameters['ApNonce']
        self._request['@APTicket'] = True

    def add_ap_img4_tags(self, parameters):
        keys_to_copy = (
            'ApNonce', 'Ap,OSLongVersion', 'ApSecurityMode', 'ApProductionMode', 'ApSepNonce',
            'PearlCertificationRootPub')
        for k in keys_to_copy:
            if k in parameters:
                v = parameters[k]
                if k == 'ApSepNonce':
                    k = 'SepNonce'
                self._request[k] = v

        self._request['@ApImg4Ticket'] = True

    def add_se_tags(self, parameters: typing.Mapping, overrides=None):
        manifest = parameters['Manifest']

        # add tags indicating we want to get the SE,Ticket
        self._request['@BBTicket'] = True
        self._request['@SE,Ticket'] = True

        keys_to_copy = ('SE,ChipID', 'SE,ID', 'SE,Nonce', 'SE,Nonce', 'SE,RootKeyIdentifier',
                        'SEChipID', 'SEID', 'SENonce', 'SENonce', 'SERootKeyIdentifier',)

        for src_key in keys_to_copy:
            if src_key not in parameters:
                continue

            if src_key.startswith('SE'):
                dst_key = src_key
                if not dst_key.startswith('SE,'):
                    # make sure there is a comma (,) after prefix
                    dst_key = 'SE,' + dst_key.split('SE', 1)[1]
                self._request[dst_key] = parameters[src_key]

        # 'IsDev' determines whether we have Production or Development
        is_dev = parameters.get('SE,IsDev')
        if is_dev is None:
            is_dev = parameters.get('SEIsDev', False)

        # add SE,* components from build manifest to request
        for key, manifest_entry in manifest.items():
            if not key.startswith('SE'):
                continue

            # copy this entry
            tss_entry = dict(manifest_entry)

            # remove Info node
            tss_entry.pop('Info')

            # remove Development or Production key/hash node
            if is_dev:
                if 'ProductionCMAC' in tss_entry:
                    tss_entry.pop('ProductionCMAC')
                if 'ProductionUpdatePayloadHash' in tss_entry:
                    tss_entry.pop('ProductionUpdatePayloadHash')
            else:
                if 'DevelopmentCMAC' in tss_entry:
                    tss_entry.pop('DevelopmentCMAC')
                if 'DevelopmentUpdatePayloadHash' in tss_entry:
                    tss_entry.pop('DevelopmentUpdatePayloadHash')

            # add entry to request
            self._request[key] = tss_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_savage_tags(self, parameters: typing.Mapping, overrides=None, component_name=None):
        manifest = parameters['Manifest']

        # add tags indicating we want to get the Savage,Ticket
        self._request['@BBTicket'] = True
        self._request['@Savage,Ticket'] = True

        # add Savage,UID
        self._request['Savage,UID'] = parameters['Savage,UID']

        # add SEP
        self._request['SEP'] = {'Digest': manifest['SEP']['Digest']}

        keys_to_copy = (
            'Savage,PatchEpoch', 'Savage,ChipID', 'Savage,AllowOfflineBoot', 'Savage,ReadFWKey',
            'Savage,ProductionMode', 'Savage,Nonce', 'Savage,Nonce')

        for k in keys_to_copy:
            if k in parameters:
                self._request[k] = parameters[k]

        isprod = parameters['Savage,ProductionMode']

        # get the right component name
        comp_name = 'Savage,B0-Prod-Patch' if isprod else 'Savage,B0-Dev-Patch'
        node = parameters.get('Savage,Revision')

        if isinstance(node, bytes):
            savage_rev = node
            if ((savage_rev[0] | 0x10) & 0xF0) == 0x30:
                comp_name = 'Savage,B2-Prod-Patch' if isprod else 'Savage,B2-Dev-Patch'
            elif (savage_rev[0] & 0xF0) == 0xA0:
                comp_name = 'Savage,BA-Prod-Patch' if isprod else 'Savage,BA-Dev-Patch'

        # add Savage,B?-*-Patch
        d = dict(manifest[comp_name])
        d.pop('Info')
        self._request[comp_name] = d

        if overrides is not None:
            self._request.update(overrides)

        return comp_name

    def add_yonkers_tags(self, parameters: typing.Mapping, overrides=None):
        manifest = parameters['Manifest']

        # add tags indicating we want to get the Yonkers,Ticket
        self._request['@BBTicket'] = True
        self._request['@Yonkers,Ticket'] = True

        # add SEP
        self._request['SEP'] = {'Digest': manifest['SEP']['Digest']}

        keys_to_copy = (
            'Yonkers,AllowOfflineBoot', 'Yonkers,BoardID', 'Yonkers,ChipID', 'Yonkers,ECID', 'Yonkers,Nonce',
            'Yonkers,PatchEpoch', 'Yonkers,ProductionMode', 'Yonkers,ReadECKey', 'Yonkers,ReadFWKey',)

        for k in keys_to_copy:
            if k in parameters:
                self._request[k] = parameters[k]

        isprod = parameters.get('Yonkers,ProductionMode', 1)
        fabrevision = parameters.get('Yonkers,FabRevision', 0xffffffffffffffff)
        comp_node = None
        result_comp_name = None

        for comp_name, node in manifest.items():
            if not comp_name.startswith('Yonkers,'):
                continue

            target_node = 1
            sub_node = node.get('EPRO')
            if sub_node:
                target_node &= sub_node if isprod else not sub_node
            sub_node = node.get('FabRevision')
            if sub_node:
                target_node &= sub_node == fabrevision

            if target_node:
                comp_node = node
                result_comp_name = comp_name
                break

        if comp_node is None:
            raise PyMobileDevice3Exception(f'No Yonkers node for {isprod}/{fabrevision}')

        # add Yonkers,SysTopPatch
        comp_dict = dict(comp_node)
        comp_dict.pop('Info')
        self._request[result_comp_name] = comp_dict

        if overrides is not None:
            self._request.update(overrides)

        return result_comp_name

    def add_baseband_tags(self, parameters: typing.Mapping, overrides=None):
        self._request['@BBTicket'] = True

        keys_to_copy = (
            'BbChipID', 'BbProvisioningManifestKeyHash', 'BbActivationManifestKeyHash', 'BbCalibrationManifestKeyHash',
            'BbFactoryActivationManifestKeyHash', 'BbFDRSecurityKeyHash', 'BbSkeyId', 'BbNonce',
            'BbGoldCertId', 'BbSNUM',)

        for k in keys_to_copy:
            if k in parameters:
                self._request[k] = parameters[k]

        bb_chip_id = parameters['BbChipID']
        bb_cert_id = parameters['BbGoldCertId']

        bbfwdict = dict(parameters['Manifest']['BasebandFirmware'])
        bbfwdict.pop('Info')

        if bb_chip_id == 0x68:
            # depending on the BasebandCertId remove certain nodes
            if bb_cert_id in (0x26F3FACC, 0x5CF2EC4E, 0x8399785A):
                bbfwdict.pop('PSI2-PartialDigest')
                bbfwdict.pop('RestorePSI2-PartialDigest')
            else:
                bbfwdict.pop('PSI-PartialDigest')
                bbfwdict.pop('RestorePSI-PartialDigest')

        self._request['BasebandFirmware'] = bbfwdict

        if overrides:
            self._request.update(overrides)

    def add_rose_tags(self, parameters: typing.Mapping, overrides: typing.Mapping = None):
        manifest = parameters['Manifest']

        # add tags indicating we want to get the Rap,Ticket
        self._request['@BBTicket'] = True
        self._request['@Rap,Ticket'] = True

        keys_to_copy_uint = ('Rap,BoardID', 'Rap,ChipID', 'Rap,ECID', 'Rap,SecurityDomain',)

        for k in keys_to_copy_uint:
            self._request[k] = bytes_to_uint(parameters[k])

        keys_to_copy_bool = ('Rap,ProductionMode', 'Rap,SecurityMode',)

        for k in keys_to_copy_bool:
            self._request[k] = bytes_to_uint(parameters[k]) == 1

        nonce = parameters.get('Rap,Nonce')
        if nonce is not None:
            self._request['Rap,Nonce'] = nonce

        for comp_name, node in manifest.items():
            if not comp_name.startswith('Rap,'):
                continue

            manifest_entry = dict(node)

            # handle RestoreRequestRules
            rules = manifest_entry['Info'].get('RestoreRequestRules')
            if rules is not None:
                self.apply_restore_request_rules(manifest_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            trusted = manifest_entry.get('Trusted', False)

            if trusted:
                digest = manifest_entry.get('Digest')
                if digest is None:
                    logging.debug(f'No Digest data, using empty value for entry {comp_name}')
                    manifest_entry['Digest'] = b''

            manifest_entry.pop('Info')

            # finally add entry to request
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_veridian_tags(self, parameters: typing.Mapping, overrides: typing.Mapping = None):
        manifest = parameters['Manifest']

        # add tags indicating we want to get the Rap,Ticket
        self._request['@BBTicket'] = True
        self._request['@BMU,Ticket'] = True

        self._request['BMU,ChipID'] = parameters['ChipID']
        self._request['BMU,UniqueID'] = parameters['UniqueID']
        self._request['BMU,ProductionMode'] = parameters['ProductionMode']

        nonce = parameters.get('Nonce')
        if nonce is not None:
            self._request['BMU,Nonce'] = nonce

        for comp_name, node in manifest.items():
            if not comp_name.startswith('BMU,'):
                continue

            manifest_entry = dict(node)

            # handle RestoreRequestRules
            rules = manifest_entry['Info'].get('RestoreRequestRules')
            if rules is not None:
                self.apply_restore_request_rules(manifest_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            trusted = manifest_entry.get('Trusted', False)

            if trusted:
                digest = manifest_entry.get('Digest')
                if digest is None:
                    logging.debug(f'No Digest data, using empty value for entry {comp_name}')
                    manifest_entry['Digest'] = b''

            manifest_entry.pop('Info')

            # finally add entry to request
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def img4_create_local_manifest(self, build_identity=None):
        manifest = None
        if build_identity is not None:
            manifest = build_identity['Manifest']

        p = asn1.Encoder()
        p.start()

        p.write(b'MANP', asn1.Numbers.IA5String)
        p.enter(asn1.Numbers.Set)

        p.write(b'BORD', asn1.Numbers.IA5String)
        p.write(self._request['ApBoardID'], asn1.Numbers.Integer)

        p.write(b'CEPO', asn1.Numbers.IA5String)
        p.write(0, asn1.Numbers.Integer)

        p.write(b'CHIP', asn1.Numbers.IA5String)
        p.write(self._request['ApChipID'], asn1.Numbers.Integer)

        p.write(b'CPRO', asn1.Numbers.IA5String)
        p.write(self._request['ApProductionMode'], asn1.Numbers.Integer)

        p.write(b'CSEC', asn1.Numbers.IA5String)
        p.write(0, asn1.Numbers.Integer)

        p.write(b'SDOM', asn1.Numbers.IA5String)
        p.write(self._request['ApSecurityDomain'], asn1.Numbers.Integer)

        p.leave()

        # now write the components
        for k, v in self._request.items():
            if isinstance(v, dict):
                # check if component has Img4PayloadType
                comp = None
                if manifest is not None:
                    comp = manifest[k]['Info'].get('Img4PayloadType')

                if comp is None:
                    comp = img4_get_component_tag(k)

                if comp is None:
                    raise NotImplementedError(f'Unhandled component {k} - can\'t create manifest')

                logging.debug(f'found component {comp} ({k})')

        # write manifest body header
        p.write(b'MANB', asn1.Numbers.IA5String)
        p.enter(asn1.Numbers.Set)
        p.leave()

        # write header values
        p.write(b'IM4M', asn1.Numbers.IA5String)
        p.write(0, asn1.Numbers.Integer)

        return p.output()

    def update(self, options):
        self._request.update(options)

    def send_receive(self) -> TSSResponse:
        headers = {
            'Cache-Control': 'no-cache',
            'Content-type': 'text/xml; charset="utf-8"',
            'User-Agent': 'InetURL/1.0',
            'Expect': '',
        }

        if self._offline:
            unique_identifier = str(time.time())
            request_plist_path = TICKETS_SUBDIR / f'request_data_{unique_identifier}.plist'
            request_script_path = TICKETS_SUBDIR / f'request_script.sh'
            response_path = TICKETS_SUBDIR / f'response_{unique_identifier}.txt'

            TICKETS_SUBDIR.mkdir(parents=True, exist_ok=True)
            for file in TICKETS_SUBDIR.iterdir():
                file.unlink()

            with request_plist_path.open('wb') as f:
                plistlib.dump(self._request, f)

            request_script_path.write_text(
                OFFLINE_REQUEST_SCRIPT.format(request=request_plist_path.name, response=response_path.name))
            request_script_path.chmod(0o755)

            logging.info(f'waiting for {response_path} to be created')
            while not response_path.exists() or b'</plist>' not in response_path.read_bytes():
                time.sleep(1)

            content = response_path.read_bytes()
        else:
            logging.info(f'Sending TSS request...')
            r = requests.post('http://gs.apple.com/TSS/controller?action=2', headers=headers,
                              data=plistlib.dumps(self._request), verify=False)
            content = r.content

        if b'MESSAGE=SUCCESS' in content:
            logging.info('response successfully received')

        message = content.split(b'MESSAGE=', 1)[1].split(b'&', 1)[0].decode()
        if message != 'SUCCESS':
            raise Exception(f'server replied: {message}')

        return TSSResponse(plistlib.loads(content.split(b'REQUEST_STRING=', 1)[1]))
