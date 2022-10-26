import asn1
import logging
import struct
from typing import Optional

logger = logging.getLogger(__name__)


def img4_get_component_tag(compname):
    component_tags = {
        'ACIBT': b'acib',
        'ACIBTLPEM': b'lpbt',
        'ACIWIFI': b'aciw',
        'ANE': b'anef',
        'ANS': b'ansf',
        'AOP': b'aopf',
        'AVE': b'avef',
        'Alamo': b'almo',
        'Ap,ANE1': b'ane1',
        'Ap,ANE2': b'ane2',
        'Ap,ANE3': b'ane3',
        'Ap,AudioAccessibilityBootChime': b'auac',
        'Ap,AudioBootChime': b'aubt',
        'Ap,AudioPowerAttachChime': b'aupr',
        'Ap,BootabilityBrainTrustCache': b'trbb',
        'Ap,CIO': b'ciof',
        'Ap,HapticAssets': b'hpas',
        'Ap,LocalBoot': b'lobo',
        'Ap,LocalPolicy': b'lpol',
        'Ap,NextStageIM4MHash': b'nsih',
        'Ap,RecoveryOSPolicyNonceHash': b'ronh',
        'Ap,RestoreANE1': b'ran1',
        'Ap,RestoreANE2': b'ran2',
        'Ap,RestoreANE3': b'ran3',
        'Ap,RestoreCIO': b'rcio',
        'Ap,RestoreTMU': b'rtmu',
        'Ap,Scorpius': b'scpf',
        'Ap,SystemVolumeCanonicalMetadata': b'msys',
        'Ap,TMU': b'tmuf',
        'Ap,VolumeUUID': b'vuid',
        'Ap,rOSLogo1': b'rlg1',
        'Ap,rOSLogo2': b'rlg2',
        'AppleLogo': b'logo',
        'AudioCodecFirmware': b'acfw',
        'BatteryCharging': b'glyC',
        'BatteryCharging0': b'chg0',
        'BatteryCharging1': b'chg1',
        'BatteryFull': b'batF',
        'BatteryLow0': b'bat0',
        'BatteryLow1': b'bat1',
        'BatteryPlugin': b'glyP',
        'CFELoader': b'cfel',
        'CrownFirmware': b'crwn',
        'DCP': b'dcpf',
        'Dali': b'dali',
        'DeviceTree': b'dtre',
        'Diags': b'diag',
        'EngineeringTrustCache': b'dtrs',
        'ExtDCP': b'edcp',
        'GFX': b'gfxf',
        'Hamm': b'hamf',
        'Homer': b'homr',
        'ISP': b'ispf',
        'InputDevice': b'ipdf',
        'KernelCache': b'krnl',
        'LLB': b'illb',
        'LeapHaptics': b'lphp',
        'Liquid': b'liqd',
        'LoadableTrustCache': b'ltrs',
        'LowPowerWallet0': b'lpw0',
        'LowPowerWallet1': b'lpw1',
        'LowPowerWallet2': b'lpw2',
        'MacEFI': b'mefi',
        'MtpFirmware': b'mtpf',
        'Multitouch': b'mtfw',
        'NeedService': b'nsrv',
        'OS': b'OS\0\0',
        'OSRamdisk': b'osrd',
        'PEHammer': b'hmmr',
        'PERTOS': b'pert',
        'PHLEET': b'phlt',
        'PMP': b'pmpf',
        'PersonalizedDMG': b'pdmg',
        'RBM': b'rmbt',
        'RTP': b'rtpf',
        'Rap,SoftwareBinaryDsp1': b'sbd1',
        'Rap,RTKitOS': b'rkos',
        'Rap,RestoreRTKitOS': b'rrko',
        'RecoveryMode': b'recm',
        'RestoreANS': b'rans',
        'RestoreDCP': b'rdcp',
        'RestoreDeviceTree': b'rdtr',
        'RestoreExtDCP': b'recp',
        'RestoreKernelCache': b'rkrn',
        'RestoreLogo': b'rlgo',
        'RestoreRTP': b'rrtp',
        'RestoreRamDisk': b'rdsk',
        'RestoreSEP': b'rsep',
        'RestoreTrustCache': b'rtsc',
        'SCE': b'scef',
        'SCE1Firmware': b'sc1f',
        'SEP': b'sepi',
        'SIO': b'siof',
        'StaticTrustCache': b'trst',
        'SystemLocker': b'lckr',
        'SystemVolume': b'isys',
        'WCHFirmwareUpdater': b'wchf',
        'ftap': b'ftap',
        'ftsp': b'ftsp',
        'iBEC': b'ibec',
        'iBSS': b'ibss',
        'iBoot': b'ibot',
        'iBootData': b'ibdt',
        'iBootDataStage1': b'ibd1',
        'iBootTest': b'itst',
        'rfta': b'rfta',
        'rfts': b'rfts',
    }

    return component_tags.get(compname)


def asn1_find_element(index: int, type_: int, data: bytes) -> Optional[int]:
    el_type = 0

    # verify data integrity
    off = 0
    if data[off] != (asn1.Types.Constructed | asn1.Numbers.Sequence):
        return None
    off += 1

    # check data size
    offsets = {0x84: 4, 0x83: 3, 0x82: 2, 0x81: 1}
    off += 1 + offsets.get(data[off], 0)

    # find the element we are searching
    for i in range(0, index + 1):
        el_type = data[off]
        off += 1
        el_size = data[off]
        off += 1

        if i == index:
            break

        off += el_size

    # check element type
    if el_type != type_:
        return None

    return off


def stitch_component(name: str, data: bytes, tss):
    logger.info(f'Personalizing IMG4 component {name}...')

    blob = tss.ap_img4_ticket

    # first we need check if we have to change the tag for the given component
    tag_off = asn1_find_element(1, asn1.Numbers.IA5String, data)

    if tag_off is not None:
        logger.debug('Tag found')
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
        if name in component_name_tag:
            first_len = len(data)

            data = bytearray(data)
            chunk = component_name_tag[name]
            data[tag_off:tag_off + len(chunk)] = chunk
            data = bytes(data)

            assert len(data) == first_len
    else:
        logging.warning('not asn1 sequence')

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

    # hack if we have a *-TBM entry for the give
    tbm_dict = tss.get(f'{name}-TBM')
    if tbm_dict is not None:
        # now construct IM4R
        encoder.enter(asn1.Numbers.Boolean, cls=asn1.Classes.Context)
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(b'IM4R', asn1.Numbers.IA5String)
        encoder.enter(asn1.Numbers.Set)

        for tbm_component in (b'ucon', b'ucer'):
            # write priv ucon element
            encoder.enter(struct.unpack('>I', tbm_component)[0], cls=asn1.Classes.Private)

            # write ucon IA5STRING and ucon data
            encoder.enter(asn1.Numbers.Sequence)
            encoder.write(tbm_component, asn1.Numbers.IA5String)
            encoder.write(tbm_dict[tbm_component.decode()])
            encoder.leave()

            encoder.leave()

        encoder.leave()
        encoder.leave()
        encoder.leave()

    encoder.leave()

    return encoder.output()
