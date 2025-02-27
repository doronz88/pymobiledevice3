import logging

from ipsw_parser.build_identity import BuildIdentity
from pyimg4 import IM4P, IM4R, IMG4, RestoreProperty

logger = logging.getLogger(__name__)

COMPONENT_FOURCC = {
    'ACIBT': 'acib',
    'ACIBTLPEM': 'lpbt',
    'ACIWIFI': 'aciw',
    'ANE': 'anef',
    'ANS': 'ansf',
    'AOP': 'aopf',
    'AVE': 'avef',
    'Alamo': 'almo',
    'Ap,ANE1': 'ane1',
    'Ap,ANE2': 'ane2',
    'Ap,ANE3': 'ane3',
    'Ap,AudioAccessibilityBootChime': 'auac',
    'Ap,AudioBootChime': 'aubt',
    'Ap,AudioPowerAttachChime': 'aupr',
    'Ap,BootabilityBrainTrustCache': 'trbb',
    'Ap,CIO': 'ciof',
    'Ap,HapticAssets': 'hpas',
    'Ap,LocalBoot': 'lobo',
    'Ap,LocalPolicy': 'lpol',
    'Ap,NextStageIM4MHash': 'nsih',
    'Ap,RecoveryOSPolicyNonceHash': 'ronh',
    'Ap,RestoreANE1': 'ran1',
    'Ap,RestoreANE2': 'ran2',
    'Ap,RestoreANE3': 'ran3',
    'Ap,RestoreCIO': 'rcio',
    'Ap,RestoreTMU': 'rtmu',
    'Ap,Scorpius': 'scpf',
    'Ap,SystemVolumeCanonicalMetadata': 'msys',
    'Ap,TMU': 'tmuf',
    'Ap,VolumeUUID': 'vuid',
    'Ap,rOSLogo1': 'rlg1',
    'Ap,rOSLogo2': 'rlg2',
    'AppleLogo': 'logo',
    'AudioCodecFirmware': 'acfw',
    'BatteryCharging': 'glyC',
    'BatteryCharging0': 'chg0',
    'BatteryCharging1': 'chg1',
    'BatteryFull': 'batF',
    'BatteryLow0': 'bat0',
    'BatteryLow1': 'bat1',
    'BatteryPlugin': 'glyP',
    'CFELoader': 'cfel',
    'CrownFirmware': 'crwn',
    'DCP': 'dcpf',
    'Dali': 'dali',
    'DeviceTree': 'dtre',
    'Diags': 'diag',
    'EngineeringTrustCache': 'dtrs',
    'ExtDCP': 'edcp',
    'GFX': 'gfxf',
    'Hamm': 'hamf',
    'Homer': 'homr',
    'ISP': 'ispf',
    'InputDevice': 'ipdf',
    'KernelCache': 'krnl',
    'LLB': 'illb',
    'LeapHaptics': 'lphp',
    'Liquid': 'liqd',
    'LoadableTrustCache': 'ltrs',
    'LowPowerWallet0': 'lpw0',
    'LowPowerWallet1': 'lpw1',
    'LowPowerWallet2': 'lpw2',
    'MacEFI': 'mefi',
    'MtpFirmware': 'mtpf',
    'Multitouch': 'mtfw',
    'NeedService': 'nsrv',
    'OS': 'OS\0\0',
    'OSRamdisk': 'osrd',
    'PEHammer': 'hmmr',
    'PERTOS': 'pert',
    'PHLEET': 'phlt',
    'PMP': 'pmpf',
    'PersonalizedDMG': 'pdmg',
    'RBM': 'rmbt',
    'RTP': 'rtpf',
    'Rap,SoftwareBinaryDsp1': 'sbd1',
    'Rap,RTKitOS': 'rkos',
    'Rap,RestoreRTKitOS': 'rrko',
    'RecoveryMode': 'recm',
    'RestoreANS': 'rans',
    'RestoreDCP': 'rdcp',
    'RestoreDeviceTree': 'rdtr',
    'RestoreExtDCP': 'recp',
    'RestoreKernelCache': 'rkrn',
    'RestoreLogo': 'rlgo',
    'RestoreRTP': 'rrtp',
    'RestoreRamDisk': 'rdsk',
    'RestoreSEP': 'rsep',
    'RestoreTrustCache': 'rtsc',
    'SCE': 'scef',
    'SCE1Firmware': 'sc1f',
    'SEP': 'sepi',
    'SIO': 'siof',
    'StaticTrustCache': 'trst',
    'SystemLocker': 'lckr',
    'SystemVolume': 'isys',
    'WCHFirmwareUpdater': 'wchf',
    'ftap': 'ftap',
    'ftsp': 'ftsp',
    'iBEC': 'ibec',
    'iBSS': 'ibss',
    'iBoot': 'ibot',
    'iBootData': 'ibdt',
    'iBootDataStage1': 'ibd1',
    'iBootTest': 'itst',
    'rfta': 'rfta',
    'rfts': 'rfts',
    'Ap,DCP2': 'dcp2',
    'Ap,RestoreSecureM3Firmware': 'rsm3',
    'Ap,RestoreSecurePageTableMonitor': 'rspt',
    'Ap,RestoreTrustedExecutionMonitor': 'rtrx',
    'Ap,RestorecL4': 'rxcl',
}


def stitch_component(name: str, im4p_data: bytes, tss: dict, build_identity: BuildIdentity,
                     ap_parameters: dict) -> bytes:
    logger.info(f'Personalizing IMG4 component {name}...')

    im4p = IM4P(data=im4p_data)

    # patch fourcc
    fourcc = COMPONENT_FOURCC.get(name)
    if fourcc is not None:
        im4p.fourcc = fourcc

    # hack if we have a *-TBM entry for the give
    tbm_dict = tss.get(f'{name}-TBM')

    im4r = None
    if tbm_dict is not None:
        im4r = IM4R()
        info = build_identity['Info']
        if info.get('RequiresNonceSlot', False) and name in ('SEP', 'SepStage1', 'LLB'):
            logger.debug(f'{name}: RequiresNonceSlot for {name}')
            if name in ('SEP', 'SepStage1'):
                snid = ap_parameters.get('SepNonceSlotID', info.get('SepNonceSlotID', 2))
                logger.debug(f'snid: {snid}')
                im4r.add_property(
                    RestoreProperty(fourcc='snid', value=snid)
                )
            else:
                anid = ap_parameters.get('ApNonceSlotID', info.get('ApNonceSlotID', 0))
                logger.debug(f'anid: {anid}')
                im4r.add_property(
                    RestoreProperty(fourcc='anid', value=anid)
                )

        for key in tbm_dict.keys():
            logger.debug(f'{name}: Adding property {key}')
            im4r.add_property(RestoreProperty(fourcc=key, value=tbm_dict[key]))

    return IMG4(im4p=im4p, im4m=tss.ap_img4_ticket, im4r=im4r).output()
