import logging
import plistlib
from uuid import uuid4

import asn1
import requests

from pymobiledevice3.restore.img4 import img4_get_component_tag

TSS_CLIENT_VERSION_STRING = 'libauthinstall-776.60.1'


class TSSRequest:
    def __init__(self):
        self._request = {
            '@BBTicket': True,
            '@HostPlatformInfo': 'mac',
            '@VersionInfo': TSS_CLIENT_VERSION_STRING,
            '@UUID': str(uuid4()).upper(),
        }

    def add_common_flags(self, parameters, overrides=None):
        keys = ('ApECID', 'UniqueBuildID', 'ApChipID', 'ApBoardID', 'ApSecurityDomain')
        for k in keys:
            if k in parameters:
                self._request[k] = parameters[k]
        if overrides is not None:
            self._request.update(overrides)

    def add_vinyl_tags(self, parameters, overrides=None):
        self._request['@BBTicket'] = True
        self._request['@eUICC,Ticket'] = True

        keys = ('eUICC,ChipID', 'eUICC,EID', 'eUICC,RootKeyIdentifier')
        for k in keys:
            if k in parameters:
                self._request[k] = parameters[k]

        # set Nonce for eUICC,Gold component
        node = parameters.get('EUICCGoldNonce')
        if node is not None:
            n = self._request['eUICC,Gold']
            n['Nonce'] = node

        # set Nonce for eUICC,Main component
        node = parameters.get('EUICCMainNonce')
        if node is not None:
            n = self._request['eUICC,Main']
            n['Nonce'] = node

        if overrides is not None:
            self._request.update(overrides)

    @staticmethod
    def apply_restore_request_rules(tss_entry: dict, parameters: dict, rules: list):
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
                    logging.debug(f'DEBUG: Adding {key}={value} to TSS entry')
                    tss_entry[key] = value
        return tss_entry

    def add_ap_tags(self, parameters, overrides=None):
        """ loop over components from build manifest """

        manifest_node = parameters['Manifest']

        # add components to request
        skipped_keys = ('BasebandFirmware', 'SE,UpdatePayload', 'BaseSystem', 'Diags',)
        for key, manifest_entry in manifest_node.items():
            if key in skipped_keys:
                continue

            if parameters.get('_OnlyFWComponents', False):
                if not manifest_node.get('Trusted', False):
                    logging.debug(f'skipping {key} as it is not trusted')
                    continue
                info = manifest_node['Info']
                if not info['IsFirmwarePayload'] and not info['IsSecondaryFirmwarePayload'] and not info[
                    'IsFUDFirmware']:
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

    def add_ap_img3_tags(self, parameters):
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

    def add_baseband_tags(self, parameters, overrides=None):
        keys_to_copy = (
            'BbChipID', 'BbProvisioningManifestKeyHash', 'BbActivationManifestKeyHash', 'BbCalibrationManifestKeyHash',
            'BbFactoryActivationManifestKeyHash', 'BbFDRSecurityKeyHash', 'BbSkeyId', 'BbNonce', '@BBTicket',
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

    def img4_create_local_manifest(self):
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
                comp = img4_get_component_tag(k)
                if comp is None:
                    raise Exception(f'Unhandled component {k} - can\'t create manifest')
                logging.debug(f'found component {comp} ({k})')

        # write manifest body header
        p.write(b'MANB', asn1.Numbers.IA5String)
        p.enter(asn1.Numbers.Set)
        p.leave()

        # write header values
        p.write(b'IM4M', asn1.Numbers.IA5String)
        p.write(0, asn1.Numbers.Integer)

        return p.output()

    def request_send(self):
        for retry in range(15):
            headers = {
                'Cache-Control': 'no-cache',
                'Content-type': 'text/xml; charset="utf-8"',
                'User-Agent': 'InetURL/1.0',
                'Expect': '',
            }

            logging.info(f'Sending TSS request attempt {retry}')
            r = requests.post('http://gs.apple.com/TSS/controller?action=2', headers=headers,
                              data=plistlib.dumps(self._request), verify=False)

            if b'MESSAGE=SUCCESS' in r.content:
                logging.info('response successfully received')

            message = r.content.split(b'MESSAGE=', 1)[1].split(b'&', 1)[0].decode()
            if message != 'SUCCESS':
                raise Exception(f'server replied: {message}')

            return plistlib.loads(r.content.split(b'REQUEST_STRING=', 1)[1])
