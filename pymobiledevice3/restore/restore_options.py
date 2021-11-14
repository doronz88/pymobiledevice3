# extracted from ac2
import logging
import uuid

logger = logging.getLogger(__name__)

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


class RestoreOptions:

    def __init__(self, preflight_info=None, sep=None, restore_boot_args=None, spp=None):
        self.AutoBootDelay = 0
        self.SupportedDataTypes = SUPPORTED_DATA_TYPES
        self.SupportedMessageTypes = SUPPORTED_MESSAGE_TYPES
        self.BootImageType = 'UserOrInternal'
        self.DFUFileType = 'RELEASE'
        self.DataImage = False
        self.FirmwareDirectory = '.'
        self.FlashNOR = True
        self.KernelCacheType = 'Release'
        self.NORImageType = 'production'
        self.RestoreBundlePath = '/tmp/Per2.tmp'
        self.SystemImageType = 'User'
        self.UpdateBaseband = False
        self.PersonalizedDuringPreflight = True
        self.RootToInstall = False
        guid = str(uuid.uuid4())
        self.UUID = guid
        self.CreateFilesystemPartitions = True
        self.SystemImage = True

        if preflight_info is not None:
            bbus = dict(preflight_info)
            bbus.pop('FusingStatus')
            bbus.pop('PkHash')
            self.BBUpdaterState = bbus

            nonce = preflight_info.get('Nonce')
            if nonce is not None:
                self.BasebandNonce = nonce

        if sep is not None:
            required_capacity = sep.get('RequiredCapacity')
            if required_capacity:
                logger.debug(f'TZ0RequiredCapacity: {required_capacity}')
                self.TZ0RequiredCapacity = required_capacity

        if restore_boot_args is not None:
            self.RestoreBootArgs = restore_boot_args

        if spp:
            spp = dict(spp)
        else:
            spp = {'128': 1280, '16': 160, '32': 320, '64': 640, '8': 80}
        self.SystemPartitionPadding = spp

    def to_dict(self):
        return self.__dict__
