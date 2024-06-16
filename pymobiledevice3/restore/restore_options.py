# extracted from ac2
import logging
import uuid

from ipsw_parser.build_identity import BuildIdentity

logger = logging.getLogger(__name__)

SUPPORTED_DATA_TYPES = {
    'BasebandBootData': False,
    'BasebandData': False,
    'BasebandStackData': False,
    'BasebandUpdaterOutputData': False,
    'BootabilityBundle': False,
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
    'FirmwareUpdaterPreflight': True,
    'ReceiptManifest': True,
    'FirmwareUpdaterDataV2': False,
    'RestoreLocalPolicy': True,
    'AuthInstallCACert': True,
    'OverlayRootDataForKeyIndex': True,

    # Added in iOS 18.0 beta1
    'FirmwareUpdaterDataV3': True,
    'MessageUseStreamedImageFile': True,
    'UpdateVolumeOverlayRootDataCount': True,
    'URLAsset': True,
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

    # Added in iOS 18.0 beta1
    'AsyncDataRequestMsg': True,
    'AsyncWait': True,
    'RestoreAttestation': True,
}


class RestoreOptions:

    def __init__(self, preflight_info=None, sep=None, macos_variant=None, build_identity: BuildIdentity = None,
                 restore_boot_args=None, spp=None, restore_behavior: str = None, msp=None):
        self.AutoBootDelay = 0

        if preflight_info is not None:
            bbus = dict(preflight_info)
            bbus.pop('FusingStatus')
            bbus.pop('PkHash')
            self.BBUpdaterState = bbus

            nonce = preflight_info.get('Nonce')
            if nonce is not None:
                self.BasebandNonce = nonce

        self.SupportedDataTypes = SUPPORTED_DATA_TYPES
        self.SupportedMessageTypes = SUPPORTED_MESSAGE_TYPES

        # FIXME: Should be adjusted for update behaviors
        if macos_variant:
            self.AddSystemPartitionPadding = True
            self.AllowUntetheredRestore = False
            self.AuthInstallEnableSso = False

            macos_variant = build_identity.macos_variant
            if macos_variant is not None:
                self.AuthInstallRecoveryOSVariant = macos_variant

            self.AuthInstallRestoreBehavior = restore_behavior
            self.AutoBootDelay = 0
            self.BasebandUpdaterOutputPath = True
            self.DisableUserAuthentication = True
            self.FitSystemPartitionToContent = True
            self.FlashNOR = True
            self.FormatForAPFS = True
            self.FormatForLwVM = False
            self.InstallDiags = False
            self.InstallRecoveryOS = True
            self.MacOSSwapPerformed = True
            self.MacOSVariantPresent = True
            self.MinimumBatteryVoltage = 0  # FIXME: Should be adjusted for M1 macbooks (if needed)
            self.RecoveryOSUnpack = True
            self.ShouldRestoreSystemImage = True
            self.SkipPreflightPersonalization = False
            self.UpdateBaseband = True

            # FIXME: I don't know where this number comes from yet.
            #  It seems like it matches this part of the build identity:
            # 	<key>OSVarContentSize</key>
            # 	<integer>573751296</integer>
            # It did work with multiple macOS versions
            self.recoveryOSPartitionSize = 58201
            if msp:
                self.SystemPartitionSize = msp
        else:
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

            # Added for iOS 18.0 beta1
            self.HostHasFixFor99053849 = True
            self.SystemImageFormat = 'AEAWrappedDiskImage'
            self.WaitForDeviceConnectionToFinishStateMachine = False
            self.SupportedAsyncDataTypes = {
                'BasebandData': False,
                'RecoveryOSASRImage': False,
                'StreamedImageDecryptionKey': False,
                'SystemImageData': False,
                'URLAsset': True
            }

            if sep is not None:
                required_capacity = sep.get('RequiredCapacity')
                if required_capacity:
                    logger.debug(f'TZ0RequiredCapacity: {required_capacity}')
                    self.TZ0RequiredCapacity = required_capacity

            self.PersonalizedDuringPreflight = True

        self.RootToInstall = False
        self.UUID = str(uuid.uuid4()).upper()
        self.CreateFilesystemPartitions = True
        self.SystemImage = True

        if restore_boot_args is not None:
            self.RestoreBootArgs = restore_boot_args

        if spp:
            spp = dict(spp)
        else:
            spp = {'128': 1280, '16': 160, '32': 320, '64': 640, '8': 80}
        self.SystemPartitionPadding = spp

    def to_dict(self):
        return self.__dict__
