# extracted from ac2
import logging
import math
import uuid
from collections.abc import Mapping
from typing import Any, Optional, cast

from ipsw_parser.build_identity import BuildIdentity

logger = logging.getLogger(__name__)

SUPPORTED_DATA_TYPES = {
    "BasebandBootData": False,
    "BasebandData": False,
    "BasebandStackData": False,
    "BasebandUpdaterOutputData": False,
    "BootabilityBundle": False,
    "BuildIdentityDict": False,
    "BuildIdentityDictV2": False,
    "DataType": False,
    "DiagData": False,
    "EANData": False,
    "FDRMemoryCommit": False,
    "FDRTrustData": False,
    "FUDData": False,
    "FileData": False,
    "FileDataDone": False,
    "FirmwareUpdaterData": False,
    "GrapeFWData": False,
    "HPMFWData": False,
    "HostSystemTime": True,
    "KernelCache": False,
    "NORData": False,
    "NitrogenFWData": True,
    "OpalFWData": False,
    "OverlayRootDataCount": False,
    "OverlayRootDataForKey": True,
    "PeppyFWData": True,
    "PersonalizedBootObjectV3": False,
    "PersonalizedData": True,
    "ProvisioningData": False,
    "RamdiskFWData": True,
    "RecoveryOSASRImage": True,
    "RecoveryOSAppleLogo": True,
    "RecoveryOSDeviceTree": True,
    "RecoveryOSFileAssetImage": True,
    "RecoveryOSIBEC": True,
    "RecoveryOSIBootFWFilesImages": True,
    "RecoveryOSImage": True,
    "RecoveryOSKernelCache": True,
    "RecoveryOSLocalPolicy": True,
    "RecoveryOSOverlayRootDataCount": False,
    "RecoveryOSRootTicketData": True,
    "RecoveryOSStaticTrustCache": True,
    "RecoveryOSVersionData": True,
    "RootData": False,
    "RootTicket": False,
    "S3EOverride": False,
    "SourceBootObjectV3": False,
    "SourceBootObjectV4": False,
    "SsoServiceTicket": False,
    "StockholmPostflight": False,
    "SystemImageCanonicalMetadata": False,
    "SystemImageData": False,
    "SystemImageRootHash": False,
    "USBCFWData": False,
    "USBCOverride": False,
    "FirmwareUpdaterPreflight": True,
    "ReceiptManifest": True,
    "FirmwareUpdaterDataV2": False,
    "RestoreLocalPolicy": True,
    "AuthInstallCACert": True,
    "OverlayRootDataForKeyIndex": True,
    # Added in iOS 18.0 beta1
    "FirmwareUpdaterDataV3": True,
    "MessageUseStreamedImageFile": True,
    "UpdateVolumeOverlayRootDataCount": True,
    "URLAsset": True,
    # Added for macOS 27 / iOS 27. Values taken from Apple's own host
    # (MobileDevice.framework `restored_get_supported_data_types`, macOS 27.0), which
    # advertises the two new request types as supported; idevicerestore lists them as 0.
    "BootabilityBundleV2": False,
    "DeviceRestoreInfoPreflight": True,
    "SourceBootObjectV5": True,
}

# extracted from ac2
SUPPORTED_MESSAGE_TYPES = {
    "BBUpdateStatusMsg": False,
    "CheckpointMsg": True,
    "CrashLog": True,
    "DataRequestMsg": False,
    # Apple's host answers FDRSubmit only after uploading the data to Apple's FDR data store, which
    # is not implemented here, so do not invite restored to send it (see Restore.handle_fdr_submit_msg).
    "FDRSubmit": False,
    "MsgType": False,
    "PreviousRestoreLogMsg": False,
    "ProgressMsg": False,
    "ProvisioningAck": False,
    "ProvisioningInfo": False,
    "ProvisioningStatusMsg": False,
    "ReceivedFinalStatusMsg": False,
    "RestoredCrash": True,
    "StatusMsg": False,
    # Added in iOS 18.0 beta1
    "AsyncDataRequestMsg": True,
    "AsyncWait": True,
    "RestoreAttestation": True,
    # Added for macOS 27 / iOS 27 (MobileDevice.framework `restored_get_supported_message_types`)
    "RestoreProtocol": True,
}

# MobileDevice.framework `restored_get_supported_protocols`: the transports the host can serve
# data requests over. Only the usbmuxd socket is implemented here.
SUPPORTED_HOST_PROTOCOLS = ["MuxSocket"]

# components that are always counted into the RecoveryOS partition size, on top of everything
# loaded by iBoot (idevicerestore `_restore_calculate_recovery_os_partition_size`)
RECOVERY_OS_PARTITION_ASSETS = (
    "OS",
    "KernelCache",
    "DeviceTree",
    "iBEC",
    "AppleLogo",
    "StaticTrustCache",
    "iBootData",
    "Diags",
    "Ap,SystemVolumeCanonicalMetadata",
    "SystemVolume",
    "BaseSystemVolume",
    "Ap,BaseSystemTrustCache",
    "AVISP1,RTKitOS",
)


def recovery_os_partition_size(recovery_variant: BuildIdentity, file_sizes: Mapping[str, int]) -> tuple[int, int]:
    """
    Calculate the (minimum, maximum) RecoveryOS partition size in MiB, the way idevicerestore does.

    :param recovery_variant: the build identity of the recovery OS
    :param file_sizes: IPSW member path -> size in bytes (components missing from it are not counted)
    """
    total = 0.0
    for component, entry in recovery_variant["Manifest"].items():
        if not isinstance(entry, dict):
            continue
        info = cast(dict[str, Any], entry).get("Info", {})
        if component not in RECOVERY_OS_PARTITION_ASSETS and info.get("IsLoadedByiBoot") is not True:
            continue
        size = file_sizes.get(info.get("Path", ""))
        if size is not None:
            total += size / 0x100000
    total = math.ceil(total)
    return int(total * 1.05 + 25), int(total * 1.25 + 25)


class RestoreOptions:
    def __init__(
        self,
        firmware_preflight_info: Optional[dict[str, Any]] = None,
        sep: Optional[dict[str, Any]] = None,
        macos_variant: Optional[BuildIdentity] = None,
        build_identity: Optional[BuildIdentity] = None,
        restore_boot_args: Optional[str] = None,
        spp: Optional[dict[str, Any]] = None,
        restore_behavior: Optional[str] = None,
        msp: Optional[int] = None,
        recovery_variant: Optional[BuildIdentity] = None,
        recovery_os_partition_sizes: Optional[tuple[int, int]] = None,
    ):
        self.AutoBootDelay = 0

        try:
            if firmware_preflight_info is not None:
                bbus = dict(firmware_preflight_info)
                bbus.pop("FusingStatus")
                bbus.pop("PkHash")
                self.BBUpdaterState = bbus

                nonce = firmware_preflight_info.get("Nonce")
                if nonce is not None:
                    self.BasebandNonce = nonce
        except KeyError as e:
            logger.warning(f"Skipping addition of firmware_preflight_info due to: {e}")

        self.SupportedDataTypes = SUPPORTED_DATA_TYPES
        self.SupportedMessageTypes = SUPPORTED_MESSAGE_TYPES
        self.SupportedHostProtocols = SUPPORTED_HOST_PROTOCOLS

        # FIXME: Should be adjusted for update behaviors
        if macos_variant:
            if build_identity is None:
                raise ValueError("build_identity is required when macos_variant is set")
            self.AddSystemPartitionPadding = True
            self.AllowUntetheredRestore = False
            self.AuthInstallEnableSso = False

            self.AuthInstallRecoveryOSVariant = build_identity.macos_variant

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
            self.BootImageType = "UserOrInternal"
            self.DFUFileType = "RELEASE"
            self.DataImage = False
            self.FirmwareDirectory = "."
            self.FlashNOR = True
            self.KernelCacheType = "Release"
            self.NORImageType = "production"
            self.RestoreBundlePath = "/tmp/Per2.tmp"
            self.SystemImageType = "User"
            self.UpdateBaseband = False

            if recovery_variant is not None:
                self.InstallRecoveryOS = True
                self.RecoveryOSBundlePath = "/tmp/Per2.tmp"
                self.AuthInstallRecoveryOSVariant = recovery_variant["Info"]["Variant"]
                if recovery_os_partition_sizes is not None:
                    min_size, max_size = recovery_os_partition_sizes
                    logger.info(f"Calculated recoveryOSPartitionSize as {min_size} MB")
                    logger.info(f"Calculated recoveryOSMaxPartitionSize as {max_size} MB")
                    self.recoveryOSPartitionSize = min_size
                    self.recoveryOSMaxPartitionSize = max_size

            # Added for iOS 18.0 beta1
            self.HostHasFixFor99053849 = True
            self.SystemImageFormat = "AEAWrappedDiskImage"
            self.WaitForDeviceConnectionToFinishStateMachine = False

            if sep is not None:
                required_capacity = sep.get("RequiredCapacity")
                if required_capacity:
                    logger.debug(f"TZ0RequiredCapacity: {required_capacity}")
                    self.TZ0RequiredCapacity = required_capacity

            self.PersonalizedDuringPreflight = True

        # Added for iOS 18.0 and macOS 15.0
        self.SupportedAsyncDataTypes = {
            "BasebandData": False,
            "RecoveryOSASRImage": False,
            "StreamedImageDecryptionKey": False,
            "SystemImageData": False,
            "URLAsset": True,
        }

        self.RootToInstall = False
        self.UUID = str(uuid.uuid4()).upper()
        self.CreateFilesystemPartitions = True
        self.SystemImage = True

        if restore_boot_args is not None:
            self.RestoreBootArgs = restore_boot_args

        if spp:
            spp = dict(spp)
        else:
            spp = {
                "1024": 1280,
                "128": 1280,
                "16": 160,
                "256": 1280,
                "32": 320,
                "512": 1280,
                "64": 640,
                "768": 1280,
                "8": 80,
            }
        self.SystemPartitionPadding = spp

    def to_dict(self):
        return self.__dict__
