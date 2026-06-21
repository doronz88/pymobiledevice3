import asyncio
import logging
import plistlib
import typing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from uuid import uuid4

import asn1
import requests

from pymobiledevice3.exceptions import PyMobileDevice3Exception, TSSError
from pymobiledevice3.restore.img4 import COMPONENT_FOURCC
from pymobiledevice3.utils import bytes_to_uint, plist_access_path

# Use the following `defaults write` to easily sniff Apple Configurator:
#
# ```shell
# defaults write com.apple.configurator.ui AuthInstallSigningServerURL http://gs.apple.com:80
# defaults write com.apple.configurator.xpc.DeviceService AuthInstallSigningServerURL http://gs.apple.com:80
# defaults write com.apple.AMPDevicesAgent AuthInstallSigningServerURL http://gs.apple.com:80
# ```
TSS_CONTROLLER_ACTION_URL = "http://gs.apple.com/TSS/controller?action=2"

TSS_CLIENT_VERSION_STRING = "libauthinstall-1104.0.9"

logger = logging.getLogger(__name__)


def get_with_or_without_comma(obj: dict, k: str, default=None):
    val = obj.get(k, obj.get(k.replace(",", "")))
    if val is None and default is not None:
        val = default
    return val


def is_fw_payload(info: dict[str, typing.Any]) -> bool:
    return (
        info.get("IsFirmwarePayload")
        or info.get("IsSecondaryFirmwarePayload")
        or info.get("IsFUDFirmware")
        or info.get("IsLoadedByiBoot")
        or info.get("IsEarlyAccessFirmware")
        or info.get("IsiBootEANFirmware")
        or info.get("IsiBootNonEssentialFirmware")
    )


class TSSResponse(dict):
    @property
    def ap_img4_ticket(self):
        ticket = self.get("ApImg4Ticket")

        if ticket is None:
            raise PyMobileDevice3Exception("TSS response doesn't contain a ApImg4Ticket")

        return ticket

    @property
    def bb_ticket(self):
        return self.get("BBTicket")

    def get_path_by_entry(self, component: str):
        node = self.get(component)
        if node is not None:
            return node.get("Path")

        return None


class TSSRequest:
    def __init__(self):
        self._request: dict[str, typing.Any] = {
            "@HostPlatformInfo": "mac",
            "@VersionInfo": TSS_CLIENT_VERSION_STRING,
            "@UUID": str(uuid4()).upper(),
        }

    @staticmethod
    def apply_restore_request_rules(tss_entry: dict, parameters: dict, rules: list) -> dict:
        for rule in rules:
            conditions_fulfilled = True
            conditions = rule["Conditions"]
            for key, value in conditions.items():
                if not conditions_fulfilled:
                    break

                if key == "ApRawProductionMode" or key == "ApCurrentProductionMode":
                    value2 = parameters.get("ApProductionMode")
                elif key == "ApRawSecurityMode":
                    value2 = parameters.get("ApSecurityMode")
                elif key == "ApRequiresImage4":
                    value2 = parameters.get("ApSupportsImg4")
                elif key == "ApDemotionPolicyOverride":
                    value2 = parameters.get("DemotionPolicy")
                elif key == "ApInRomDFU":
                    value2 = parameters.get("ApInRomDFU")
                else:
                    logger.error(f"Unhandled condition {key} while parsing RestoreRequestRules")
                    value2 = None

                conditions_fulfilled = value == value2 if value2 else False

            if not conditions_fulfilled:
                continue

            actions = rule["Actions"]
            for key, value in actions.items():
                if value != 255:
                    value2 = tss_entry.get(key)
                    if value2:
                        tss_entry.pop(key)
                    logger.debug(f"Adding {key}={value} to TSS entry")
                    tss_entry[key] = value
        return tss_entry

    def add_tags(self, parameters: dict):
        for key, value in parameters.items():
            if isinstance(value, str) and value.startswith("0x"):
                value = int(value, 16)
            self._request[key] = value

    def add_common_tags(self, parameters: dict, overrides=None):
        keys = ("ApECID", "UniqueBuildID", "ApChipID", "ApBoardID", "ApSecurityDomain")
        for k in keys:
            if k in parameters:
                self._request[k] = parameters[k]
        if overrides is not None:
            self._request.update(overrides)

    def add_ap_recovery_tags(self, parameters: dict, overrides=None):
        skip_keys = (
            "BasebandFirmware",
            "SE,UpdatePayload",
            "BaseSystem",
            "ANS",
            "Ap,AudioBootChime",
            "Ap,CIO",
            "Ap,RestoreCIO",
            "Ap,RestoreTMU",
            "Ap,TMU",
            "Ap,rOSLogo1",
            "Ap,rOSLogo2",
            "AppleLogo",
            "DCP",
            "LLB",
            "RecoveryMode",
            "RestoreANS",
            "RestoreDCP",
            "RestoreDeviceTree",
            "RestoreKernelCache",
            "RestoreLogo",
            "RestoreRamDisk",
            "RestoreSEP",
            "SEP",
            "ftap",
            "ftsp",
            "iBEC",
            "iBSS",
            "rfta",
            "rfts",
            "Diags",
        )

        # add components to request
        manifest = parameters["Manifest"]
        for key, manifest_entry in manifest.items():
            if key in skip_keys:
                continue
            info = manifest_entry.get("Info")
            if not info:
                continue
            if parameters.get("_OnlyFWComponents", False):
                if not manifest_entry.get("Trusted", False):
                    logger.debug(f"skipping {key} as it is not trusted")
                    continue
                info = manifest_entry["Info"]
                if not is_fw_payload(info):
                    logger.debug(f"skipping {key} as it is not a firmware payload")
                    continue

            # copy this entry
            tss_entry = dict(manifest_entry)

            # remove obsolete Info node
            tss_entry.pop("Info")

            # handle RestoreRequestRules
            if "Info" in manifest_entry and "RestoreRequestRules" in manifest_entry["Info"]:
                rules = manifest_entry["Info"]["RestoreRequestRules"]
                if rules:
                    logger.debug(f"Applying restore request rules for entry {key}")
                    tss_entry = self.apply_restore_request_rules(tss_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            node = manifest_entry.get("Trusted", False)
            if node and manifest_entry.get("Digest") is None:
                tss_entry["Digest"] = b""

            self._request[key] = tss_entry

        if overrides:
            self._request.update(overrides)

    def add_timer_tags(self, parameters: dict, overrides=None):
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the Timer ticket
        self._request["@BBTicket"] = True

        key = f"@{parameters['TicketName']}"
        self._request[key] = True

        tag = parameters["TagNumber"]

        keys_to_copy_uint = (
            f"Timer,BoardID,{tag}",
            f"Timer,ChipID,{tag}",
            f"Timer,SecurityDomain,{tag}",
            f"Timer,ECID,{tag}",
        )

        for key in keys_to_copy_uint:
            value = parameters.get(key)

            if isinstance(value, bytes):
                self._request[key] = bytes_to_uint(value)
            else:
                self._request[key] = value

        keys_to_copy_bool = (
            f"Timer,ProductionMode,{tag}",
            f"Timer,SecurityMode,{tag}",
        )

        for key in keys_to_copy_bool:
            value = parameters.get(key)
            self._request[key] = bytes_to_uint(value) == 1

        nonce = parameters.get(parameters, f"Timer,Nonce,{tag}")

        if nonce is not None:
            self._request[f"Timer,Nonce,{tag}"] = nonce

        for comp_name, node in manifest.items():
            if not comp_name.startswith("Timer,"):
                continue

            manifest_entry = dict(node)

            # handle RestoreRequestRules
            rules = manifest_entry["Info"].get("RestoreRequestRules")
            if rules is not None:
                self.apply_restore_request_rules(manifest_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            trusted = manifest_entry.get("Trusted", False)

            if trusted:
                digest = manifest_entry.get("Digest")
                if digest is None:
                    logger.debug(f"No Digest data, using empty value for entry {comp_name}")
                    manifest_entry["Digest"] = b""

            manifest_entry.pop("Info")

            # finally add entry to request
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_local_policy_tags(self, parameters: dict):
        self._request["@ApImg4Ticket"] = True

        keys_to_copy = (
            "Ap,LocalBoot",
            "Ap,LocalPolicy",
            "Ap,NextStageIM4MHash",
            "Ap,RecoveryOSPolicyNonceHash",
            "Ap,VolumeUUID",
            "ApECID",
            "ApChipID",
            "ApBoardID",
            "ApSecurityDomain",
            "ApNonce",
            "ApSecurityMode",
            "ApProductionMode",
        )

        for k in keys_to_copy:
            if k in parameters:
                v = parameters[k]
                if isinstance(v, str) and v.startswith("0x"):
                    v = int(v, 16)
                self._request[k] = v

    def add_vinyl_prefetch_tags(self, parameters: dict, overrides=None):
        # Prefetch shim for Vinyl/eUICC: PreflightInfo nests the Gold/Main nonces under
        # eUICC,Gold / eUICC,Main, but add_vinyl_tags reads them from the flat
        # EUICCGoldNonce / EUICCMainNonce params (the recovery.py AP-batch path sets these).
        for nested, flat in (("eUICC,Gold", "EUICCGoldNonce"), ("eUICC,Main", "EUICCMainNonce")):
            node = parameters.get(nested)
            if isinstance(node, dict) and node.get("Nonce") is not None:
                parameters.setdefault(flat, node["Nonce"])
        self.add_vinyl_tags(parameters, overrides)

    def add_vinyl_tags(self, parameters: dict, overrides=None):
        self._request["@BBTicket"] = True
        self._request["@eUICC,Ticket"] = True

        self._request["eUICC,ApProductionMode"] = parameters.get(
            "eUICC,ApProductionMode", parameters.get("ApProductionMode")
        )

        keys = ("eUICC,ChipID", "eUICC,EID", "eUICC,RootKeyIdentifier")
        for k in keys:
            if k in parameters:
                self._request[k] = parameters[k]

        if self._request.get("eUICC,Gold") is None:
            n = plist_access_path(parameters, ("Manifest", "eUICC,Gold"))
            if n:
                self._request["eUICC,Gold"] = {"Digest": n["Digest"]}

        if self._request.get("eUICC,Main") is None:
            n = plist_access_path(parameters, ("Manifest", "eUICC,Main"))
            if n:
                self._request["eUICC,Main"] = {"Digest": n["Digest"]}

        # set Nonce for eUICC,Gold component
        node = parameters.get("EUICCGoldNonce")
        if node is not None:
            n = self._request.get("eUICC,Gold")
            if n is not None:
                n["Nonce"] = node

        # set Nonce for eUICC,Main component
        node = parameters.get("EUICCMainNonce")
        if node is not None:
            n = self._request.get("eUICC,Main")
            if n is not None:
                n["Nonce"] = node

        if overrides is not None:
            self._request.update(overrides)

    def add_ap_tags(self, parameters: dict, overrides=None):
        """loop over components from build manifest"""

        manifest_node = parameters["Manifest"]

        # add components to request
        skipped_keys = ("BasebandFirmware", "SE,UpdatePayload", "BaseSystem", "Diags", "Ap,ExclaveOS")
        for key, manifest_entry in manifest_node.items():
            if key in skipped_keys:
                continue

            if key.startswith("Cryptex1,"):
                continue

            info_dict = manifest_entry.get("Info")
            if info_dict is None:
                continue

            if parameters.get("ApSupportsImg4", False) and ("RestoreRequestRules" not in info_dict):
                logger.debug(f'Skipping "{key}" as it doesn\'t have RestoreRequestRules')
                continue

            if parameters.get("_OnlyFWComponents", False):
                if not manifest_node.get("Trusted", False):
                    logger.debug(f"skipping {key} as it is not trusted")
                    continue
                info = manifest_entry["Info"]
                if not is_fw_payload(info):
                    logger.debug(f"skipping {key} as it is not a firmware payload")
                    continue

            if info_dict.get("IsFTAB"):
                logger.debug("Skipping IsFTAB")
                continue

            # copy this entry
            tss_entry = dict(manifest_entry)

            # remove obsolete Info node
            tss_entry.pop("Info")

            # handle RestoreRequestRules
            if "Info" in manifest_entry and "RestoreRequestRules" in manifest_entry["Info"]:
                rules = manifest_entry["Info"]["RestoreRequestRules"]
                if rules:
                    logger.debug(f"Applying restore request rules for entry {key}")
                    tss_entry = self.apply_restore_request_rules(tss_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            node = manifest_entry.get("Trusted", False)
            if node and manifest_entry.get("Digest") is None:
                tss_entry["Digest"] = b""

            self._request[key] = tss_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_ap_img3_tags(self, parameters: dict):
        if "ApNonce" in parameters:
            self._request["ApNonce"] = parameters["ApNonce"]
        self._request["@APTicket"] = True

    def add_ap_img4_tags(self, parameters):
        keys_to_copy = (
            "ApNonce",
            "ApProductionMode",
            "ApSecurityMode",
            "Ap,OSLongVersion",
            "ApSecurityMode",
            "ApSepNonce",
            "Ap,SDKPlatform",
            "PearlCertificationRootPub",
            "NeRDEpoch",
            "ApSikaFuse",
            "Ap,SikaFuse",
            "Ap,OSReleaseType",
            "Ap,ProductType",
            "Ap,Target",
            "Ap,TargetType",
            "AllowNeRDBoot",
            "Ap,ProductMarketingVersion",
            "Ap,Timestamp",
        )
        for k in keys_to_copy:
            if k in parameters:
                v = parameters[k]
                if k == "ApSepNonce":
                    k = "SepNonce"
                if k == "ApSikaFuse":
                    k = "Ap,SikaFuse"
                self._request[k] = v

        uid_mode = parameters.get("UID_MODE")

        if "NeRDEpoch" in parameters:
            self._request["PermitNeRDPivot"] = b""

        if uid_mode is not None:
            self._request["UID_MODE"] = uid_mode
        self._request["@ApImg4Ticket"] = True
        self._request["@BBTicket"] = True

        if parameters.get("RequiresUIDMode"):
            # The logic here is missing why this value is expected to be 'false'
            self._request["UID_MODE"] = False

            # Workaround: We have only seen Ap,SikaFuse together with UID_MODE
            self._request["Ap,SikaFuse"] = 0

    def add_se2_tags(self, parameters: dict, overrides=None):
        # Modern Secure Enclave personalization (A19 / iOS 27+). The device generates an
        # @SE2,Ticket request (response key "SE2,Ticket"), NOT the legacy @SE,Ticket of
        # add_se_tags. Confirmed by a ramrod capture on iPhone 18,4: the
        # DeviceGeneratedRequest carries the SE,ChipID/ID/Nonce/RootKeyIdentifier device
        # fields plus the SE,RapRTKitOS / SE,RapSwBinDsp (Digest) and SE,UpdatePayload
        # (Production/Development hash) manifest components.
        manifest = parameters["Manifest"]

        self._request["@BBTicket"] = True
        self._request["@SE2,Ticket"] = True

        for key in ("SE,ChipID", "SE,ID", "SE,Nonce", "SE,RootKeyIdentifier"):
            value = get_with_or_without_comma(parameters, key)
            if value is not None:
                self._request[key] = value

        is_dev = bool(parameters.get("SE,IsDev", parameters.get("SEIsDev", False)))

        for comp in ("SE,RapRTKitOS", "SE,RapSwBinDsp"):
            node = manifest.get(comp)
            if node is not None and "Digest" in node:
                self._request[comp] = {"Digest": node["Digest"]}

        payload = manifest.get("SE,UpdatePayload")
        if payload is not None:
            hash_key = "DevelopmentUpdatePayloadHash" if is_dev else "ProductionUpdatePayloadHash"
            if hash_key in payload:
                self._request["SE,UpdatePayload"] = {hash_key: payload[hash_key]}

        if overrides is not None:
            self._request.update(overrides)

    def add_se_tags(self, parameters: dict, overrides=None):
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the SE,Ticket
        self._request["@BBTicket"] = True
        self._request["@SE,Ticket"] = True

        keys_to_copy = (
            "SE,ChipID",
            "SE,ID",
            "SE,Nonce",
            "SE,Nonce",
            "SE,RootKeyIdentifier",
            "SEChipID",
            "SEID",
            "SENonce",
            "SENonce",
            "SERootKeyIdentifier",
        )

        for src_key in keys_to_copy:
            if src_key not in parameters:
                continue

            if src_key.startswith("SE"):
                dst_key = src_key
                if not dst_key.startswith("SE,"):
                    # make sure there is a comma (,) after prefix
                    dst_key = "SE," + dst_key.split("SE", 1)[1]
                self._request[dst_key] = parameters[src_key]

        # 'IsDev' determines whether we have Production or Development
        is_dev = parameters.get("SE,IsDev")
        if is_dev is None:
            is_dev = parameters.get("SEIsDev", False)

        # add SE,* components from build manifest to request
        for key, manifest_entry in manifest.items():
            if not key.startswith("SE"):
                continue

            # copy this entry
            tss_entry = dict(manifest_entry)

            # remove Info node
            tss_entry.pop("Info")

            # remove Development or Production key/hash node
            if is_dev:
                if "ProductionCMAC" in tss_entry:
                    tss_entry.pop("ProductionCMAC")
                if "ProductionUpdatePayloadHash" in tss_entry:
                    tss_entry.pop("ProductionUpdatePayloadHash")
            else:
                if "DevelopmentCMAC" in tss_entry:
                    tss_entry.pop("DevelopmentCMAC")
                if "DevelopmentUpdatePayloadHash" in tss_entry:
                    tss_entry.pop("DevelopmentUpdatePayloadHash")

            # add entry to request
            self._request[key] = tss_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_savage_tags(self, parameters: dict, overrides=None, component_name=None):
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the Savage,Ticket
        self._request["@BBTicket"] = True
        self._request["@Savage,Ticket"] = True

        # add Savage,UID
        self._request["Savage,UID"] = get_with_or_without_comma(parameters, "Savage,UID")

        # add SEP
        self._request["SEP"] = {"Digest": manifest["SEP"]["Digest"]}

        keys_to_copy = (
            "Savage,PatchEpoch",
            "Savage,ChipID",
            "Savage,AllowOfflineBoot",
            "Savage,ReadFWKey",
            "Savage,ProductionMode",
            "Savage,Nonce",
            "Savage,Nonce",
        )

        for k in keys_to_copy:
            value = get_with_or_without_comma(parameters, k)
            if value is None:
                continue
            self._request[k] = value

        isprod = get_with_or_without_comma(parameters, "Savage,ProductionMode")

        # get the right component name
        comp_name = "Savage,B0-Prod-Patch" if isprod else "Savage,B0-Dev-Patch"
        node = get_with_or_without_comma(parameters, "Savage,Revision")

        if isinstance(node, bytes):
            savage_rev = node
            if ((savage_rev[0] | 0x10) & 0xF0) == 0x30:
                comp_name = "Savage,B2-Prod-Patch" if isprod else "Savage,B2-Dev-Patch"
            elif (savage_rev[0] & 0xF0) == 0xA0:
                comp_name = "Savage,BA-Prod-Patch" if isprod else "Savage,BA-Dev-Patch"

        # add Savage,B?-*-Patch
        d = dict(manifest[comp_name])
        d.pop("Info")
        self._request[comp_name] = d

        if overrides is not None:
            self._request.update(overrides)

        return comp_name

    def add_yonkers_tags(self, parameters: dict, overrides=None):
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the Yonkers,Ticket
        self._request["@BBTicket"] = True
        self._request["@Yonkers,Ticket"] = True

        # add SEP
        self._request["SEP"] = {"Digest": manifest["SEP"]["Digest"]}

        keys_to_copy = (
            "Yonkers,AllowOfflineBoot",
            "Yonkers,BoardID",
            "Yonkers,ChipID",
            "Yonkers,ECID",
            "Yonkers,Nonce",
            "Yonkers,PatchEpoch",
            "Yonkers,ProductionMode",
            "Yonkers,ReadECKey",
            "Yonkers,ReadFWKey",
        )

        for k in keys_to_copy:
            self._request[k] = get_with_or_without_comma(parameters, k)

        isprod = get_with_or_without_comma(parameters, "Yonkers,ProductionMode", 1)
        fabrevision = get_with_or_without_comma(parameters, "Yonkers,FabRevision", 0xFFFFFFFFFFFFFFFF)
        comp_node = None
        result_comp_name = None

        for comp_name, node in manifest.items():
            if not comp_name.startswith("Yonkers,"):
                continue

            target_node = 1
            sub_node = node.get("EPRO")
            if sub_node:
                target_node &= sub_node if isprod else not sub_node
            sub_node = node.get("FabRevision")
            if sub_node:
                target_node &= sub_node == fabrevision

            if target_node:
                comp_node = node
                result_comp_name = comp_name
                break

        if comp_node is None:
            raise PyMobileDevice3Exception(f"No Yonkers node for {isprod}/{fabrevision}")

        # add Yonkers,SysTopPatch
        comp_dict = dict(comp_node)
        comp_dict.pop("Info")
        self._request[result_comp_name] = comp_dict

        if overrides is not None:
            self._request.update(overrides)

        return result_comp_name

    def add_baseband_tags(self, parameters: dict, overrides=None):
        self._request["@BBTicket"] = True

        keys_to_copy = (
            "BbChipID",
            "BbProvisioningManifestKeyHash",
            "BbActivationManifestKeyHash",
            "BbCalibrationManifestKeyHash",
            "BbFactoryActivationManifestKeyHash",
            "BbFDRSecurityKeyHash",
            "BbSkeyId",
            "BbNonce",
            "BbGoldCertId",
            "BbSNUM",
            "PearlCertificationRootPub",
            "Ap,OSLongVersion",
        )

        for k in keys_to_copy:
            if k in parameters:
                self._request[k] = parameters[k]

        bb_chip_id = parameters["BbChipID"]
        bb_cert_id = parameters["BbGoldCertId"]

        bbfwdict = dict(parameters["Manifest"]["BasebandFirmware"])
        bbfwdict.pop("Info")

        if bb_chip_id == 0x68:
            # depending on the BasebandCertId remove certain nodes
            if bb_cert_id in (0x26F3FACC, 0x5CF2EC4E, 0x8399785A):
                bbfwdict.pop("PSI2-PartialDigest")
                bbfwdict.pop("RestorePSI2-PartialDigest")
            else:
                bbfwdict.pop("PSI-PartialDigest")
                bbfwdict.pop("RestorePSI-PartialDigest")

        self._request["BasebandFirmware"] = bbfwdict

        if overrides:
            self._request.update(overrides)

    def add_rose_tags(self, parameters: dict, overrides: typing.Optional[dict] = None):
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the Rap,Ticket
        self._request["@BBTicket"] = True
        self._request["@Rap,Ticket"] = True

        keys_to_copy_uint = (
            "Rap,BoardID",
            "Rap,ChipID",
            "Rap,ECID",
            "Rap,SecurityDomain",
        )

        for key in keys_to_copy_uint:
            value = get_with_or_without_comma(parameters, key)

            if isinstance(value, bytes):
                self._request[key] = bytes_to_uint(value)
            else:
                self._request[key] = value

        keys_to_copy_bool = (
            "Rap,ProductionMode",
            "Rap,SecurityMode",
        )

        for key in keys_to_copy_bool:
            value = get_with_or_without_comma(parameters, key)
            self._request[key] = bytes_to_uint(value) == 1

        nonce = get_with_or_without_comma(parameters, "Rap,Nonce")
        if nonce is not None:
            self._request["Rap,Nonce"] = nonce

        digest = get_with_or_without_comma(parameters, "Rap,FdrRootCaDigest")
        if digest is not None:
            self._request["Rap,FdrRootCaDigest"] = digest

        for comp_name, node in manifest.items():
            if not comp_name.startswith("Rap,"):
                continue

            manifest_entry = dict(node)

            # handle RestoreRequestRules
            rules = manifest_entry["Info"].get("RestoreRequestRules")
            if rules is not None:
                self.apply_restore_request_rules(manifest_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            trusted = manifest_entry.get("Trusted", False)

            if trusted:
                digest = manifest_entry.get("Digest")
                if digest is None:
                    logger.debug(f"No Digest data, using empty value for entry {comp_name}")
                    manifest_entry["Digest"] = b""

            manifest_entry.pop("Info")

            # finally add entry to request
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_centauri_tags(self, parameters: dict, overrides: typing.Optional[dict] = None):
        # Centauri (the converged Wi-Fi/BT/UWB coprocessor) is personalized exactly like
        # Rose/Rap: same Wireless1,* field set and the same @Wireless1,Ticket flag. Confirmed
        # by reversing libCentauriUpdater.dylib (response key "Wireless1,Ticket") and
        # libauthinstall.dylib (request flag "@Wireless1,Ticket", Wireless1,FdrRootCaDigest).
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the Wireless1,Ticket
        self._request["@BBTicket"] = True
        self._request["@Wireless1,Ticket"] = True

        keys_to_copy_uint = (
            "Wireless1,BoardID",
            "Wireless1,ChipID",
            "Wireless1,ECID",
            "Wireless1,SecurityDomain",
        )

        for key in keys_to_copy_uint:
            value = get_with_or_without_comma(parameters, key)
            if isinstance(value, bytes):
                self._request[key] = bytes_to_uint(value)
            else:
                self._request[key] = value

        keys_to_copy_bool = (
            "Wireless1,ProductionMode",
            "Wireless1,SecurityMode",
        )

        for key in keys_to_copy_bool:
            value = get_with_or_without_comma(parameters, key)
            self._request[key] = bytes_to_uint(value) == 1

        nonce = get_with_or_without_comma(parameters, "Wireless1,Nonce")
        if nonce is not None:
            self._request["Wireless1,Nonce"] = nonce

        # restored always includes these two even though PreflightInfo doesn't expose them
        # (ramrod capture: Wireless1,FdrRootCaDigest = b'', Wireless1,UID_MODE = False).
        self._request["Wireless1,FdrRootCaDigest"] = (
            get_with_or_without_comma(parameters, "Wireless1,FdrRootCaDigest") or b""
        )
        self._request["Wireless1,UID_MODE"] = bool(get_with_or_without_comma(parameters, "Wireless1,UID_MODE") or False)

        for comp_name, node in manifest.items():
            if not comp_name.startswith("Wireless1,"):
                continue

            manifest_entry = dict(node)

            # handle RestoreRequestRules
            rules = manifest_entry["Info"].get("RestoreRequestRules")
            if rules is not None:
                self.apply_restore_request_rules(manifest_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            trusted = manifest_entry.get("Trusted", False)

            if trusted:
                digest = manifest_entry.get("Digest")
                if digest is None:
                    logger.debug(f"No Digest data, using empty value for entry {comp_name}")
                    manifest_entry["Digest"] = b""

            manifest_entry.pop("Info")

            # finally add entry to request
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_cellular_tags(self, parameters: dict, overrides: typing.Optional[dict] = None):
        # A19 baseband personalization: device-generated @Cellular1,Ticket (response key
        # "Cellular1,Ticket"), structured like Rose/Centauri over the Cellular1,* field set
        # (ramrod capture on iPhone 18,4). The Bb*ManifestKeyHash fields come from the
        # baseband firmware-preflight info when available.
        manifest = parameters["Manifest"]

        self._request["@BBTicket"] = True
        self._request["@Cellular1,Ticket"] = True

        for key in ("Cellular1,BoardID", "Cellular1,ChipID", "Cellular1,ECID", "Cellular1,SecurityDomain"):
            value = get_with_or_without_comma(parameters, key)
            if isinstance(value, bytes):
                self._request[key] = bytes_to_uint(value)
            elif value is not None:
                self._request[key] = value

        for key in ("Cellular1,ProductionMode", "Cellular1,SecurityMode", "Cellular1,UID_MODE"):
            value = get_with_or_without_comma(parameters, key)
            if value is not None:
                self._request[key] = bytes_to_uint(value) == 1

        nonce = get_with_or_without_comma(parameters, "Cellular1,Nonce")
        if nonce is not None:
            self._request["Cellular1,Nonce"] = nonce

        for key in (
            "Cellular1,BbActivationManifestKeyHash",
            "Cellular1,BbProvisioningManifestKeyHash",
            "Cellular1,BbFDRSecurityKeyHash",
        ):
            value = get_with_or_without_comma(parameters, key)
            if value is not None:
                self._request[key] = value

        for comp_name, node in manifest.items():
            if not comp_name.startswith("Cellular1,"):
                continue
            manifest_entry = dict(node)
            rules = manifest_entry["Info"].get("RestoreRequestRules")
            if rules is not None:
                self.apply_restore_request_rules(manifest_entry, parameters, rules)
            if manifest_entry.get("Trusted", False) and manifest_entry.get("Digest") is None:
                manifest_entry["Digest"] = b""
            manifest_entry.pop("Info")
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_veridian_tags(self, parameters: dict, overrides: typing.Optional[dict] = None):
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the Rap,Ticket
        self._request["@BBTicket"] = True
        self._request["@BMU,Ticket"] = True

        self._request["BMU,ChipID"] = parameters["ChipID"]
        self._request["BMU,UniqueID"] = parameters["UniqueID"]
        self._request["BMU,ProductionMode"] = parameters["ProductionMode"]

        nonce = parameters.get("Nonce")
        if nonce is not None:
            self._request["BMU,Nonce"] = nonce

        for comp_name, node in manifest.items():
            if not comp_name.startswith("BMU,"):
                continue

            manifest_entry = dict(node)

            # handle RestoreRequestRules
            rules = manifest_entry["Info"].get("RestoreRequestRules")
            if rules is not None:
                self.apply_restore_request_rules(manifest_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            trusted = manifest_entry.get("Trusted", False)

            if trusted:
                digest = manifest_entry.get("Digest")
                if digest is None:
                    logger.debug(f"No Digest data, using empty value for entry {comp_name}")
                    manifest_entry["Digest"] = b""

            manifest_entry.pop("Info")

            # finally add entry to request
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def add_tcon_tags(self, parameters: dict, overrides: typing.Optional[dict] = None):
        manifest = parameters["Manifest"]

        # add tags indicating we want to get the Baobab,Ticket
        self._request["@BBTicket"] = True
        self._request["@Baobab,Ticket"] = True

        keys_to_copy_uint = (
            "Baobab,BoardID",
            "Baobab,ChipID",
            "Baobab,Life",
            "Baobab,ManifestEpoch",
            "Baobab,SecurityDomain",
        )

        for key in keys_to_copy_uint:
            value = get_with_or_without_comma(parameters, key)

            if isinstance(value, bytes):
                self._request[key] = bytes_to_uint(value)
            else:
                self._request[key] = value

        isprod = bool(get_with_or_without_comma(parameters, "Baobab,ProductionMode", False))
        self._request["Baobab,ProductionMode"] = isprod

        nonce = get_with_or_without_comma(parameters, "Baobab,UpdateNonce")

        if nonce is not None:
            self._request["Baobab,UpdateNonce"] = nonce

        ecid = get_with_or_without_comma(parameters, "Baobab,ECID")

        if ecid is not None:
            self._request["Baobab,ECID"] = ecid

        for comp_name, node in manifest.items():
            if not comp_name.startswith("Baobab,"):
                continue

            manifest_entry = dict(node)
            manifest_entry.pop("Info")
            manifest_entry["EPRO"] = isprod

            # finally add entry to request
            self._request[comp_name] = manifest_entry

        if overrides is not None:
            self._request.update(overrides)

    def img4_create_local_manifest(self, build_identity=None):
        manifest = None
        if build_identity is not None:
            manifest = build_identity["Manifest"]

        p = asn1.Encoder()
        p.start()

        p.write(b"MANP", asn1.Numbers.IA5String)
        p.enter(asn1.Numbers.Set)

        p.write(b"BORD", asn1.Numbers.IA5String)
        p.write(self._request["ApBoardID"], asn1.Numbers.Integer)

        p.write(b"CEPO", asn1.Numbers.IA5String)
        p.write(0, asn1.Numbers.Integer)

        p.write(b"CHIP", asn1.Numbers.IA5String)
        p.write(self._request["ApChipID"], asn1.Numbers.Integer)

        p.write(b"CPRO", asn1.Numbers.IA5String)
        p.write(self._request["ApProductionMode"], asn1.Numbers.Integer)

        p.write(b"CSEC", asn1.Numbers.IA5String)
        p.write(0, asn1.Numbers.Integer)

        p.write(b"SDOM", asn1.Numbers.IA5String)
        p.write(self._request["ApSecurityDomain"], asn1.Numbers.Integer)

        p.leave()

        # now write the components
        for k, v in self._request.items():
            if isinstance(v, dict):
                # check if component has Img4PayloadType
                comp = None
                if manifest is not None:
                    comp = manifest[k]["Info"].get("Img4PayloadType")

                if comp is None:
                    comp = COMPONENT_FOURCC.get(k)

                if comp is None:
                    raise NotImplementedError(f"Unhandled component {k} - can't create manifest")

                logger.debug(f"found component {comp} ({k})")

        # write manifest body header
        p.write(b"MANB", asn1.Numbers.IA5String)
        p.enter(asn1.Numbers.Set)
        p.leave()

        # write header values
        p.write(b"IM4M", asn1.Numbers.IA5String)
        p.write(0, asn1.Numbers.Integer)

        return p.output()

    def remove_key(self, key: str) -> None:
        if key in self._request:
            self._request.pop(key)

    def update(self, options) -> None:
        self._request.update(options)

    async def send_receive(self) -> TSSResponse:
        headers = {
            "Cache-Control": "no-cache",
            "Content-type": 'text/xml; charset="utf-8"',
            "User-Agent": "InetURL/1.0",
            "Expect": "",
        }

        logger.info("Sending TSS request...")
        logger.debug(self._request)

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:

            def post() -> bytes:
                return requests.post(
                    TSS_CONTROLLER_ACTION_URL, headers=headers, data=plistlib.dumps(self._request), verify=False
                ).content

            content = await loop.run_in_executor(executor, post)

        if b"MESSAGE=SUCCESS" in content:
            logger.info("response successfully received")

        message = content.split(b"MESSAGE=", 1)[1].split(b"&", 1)[0].decode()
        if message != "SUCCESS":
            raise TSSError(f"server replied: {message}")

        return TSSResponse(plistlib.loads(content.split(b"REQUEST_STRING=", 1)[1]))


@dataclass(frozen=True)
class PrefetchVariant:
    """One on-device shape of a prefetchable peripheral's TSS state.

    A chip may expose more than one shape (e.g. Savage is a flat ``Savage,*`` entry on
    older SoCs but a nested ``YonkersDeviceInfo`` on newer ones). Each shape is one
    variant; they're tried in order and the first whose nonce is actually present on the
    device wins. A chip with a single shape has exactly one variant.
    """

    # TSS response ticket key (e.g. ``"SE2,Ticket"``).
    ticket_name: str
    # the reactive ``TSSRequest`` helper that knows this chip's quirks; called as
    # ``add_tags(tss, parameters, None)`` on a fresh ``TSSRequest`` instance.
    add_tags: typing.Callable
    # nested key under the PreflightInfo entry holding this variant's state
    # (``None`` -> the entry itself, e.g. flat ``Savage,*``).
    preflight_subkey: typing.Optional[str] = None
    # nonce field name in the PreflightInfo entry; mutually exclusive with ``nonce_path``.
    preflight_nonce: typing.Optional[str] = None
    # list-of-paths whose bytes concatenate into one composite nonce (e.g. Vinyl's
    # ``eUICC,Gold.Nonce`` + ``eUICC,Main.Nonce``); mutually exclusive with ``preflight_nonce``.
    nonce_path: typing.Optional[list] = None
    # nonce field name in ``DataRequestMsg.DeviceGeneratedRequest`` at restore time
    # (used by ``Restore._lookup_prefetched_tss_by_ticket`` for nonce-match).
    devgen_nonce: typing.Optional[str] = None
    # composite (list-of-paths) variant of ``devgen_nonce``.
    devgen_nonce_path: typing.Optional[list] = None


@dataclass(frozen=True)
class PrefetchableUpdater:
    """A peripheral whose TSS ticket can be prefetched in the batched ``--tss-batch`` POST."""

    # cache key / log label for this updater (e.g. ``"SE"``, ``"Savage"``).
    name: str
    # where to find this updater's state in ``PreflightInfo.DeviceInfo``.
    preflight_key: str
    # candidate on-device shapes, tried in order (first whose nonce is present wins).
    variants: list[PrefetchVariant]


# Hardcoded set of peripherals whose tickets the batched --tss-batch prefetch fetches in a
# single combined TSS POST. Each chip's reactive add_*_tags helper is reused so the batched
# request's per-chip handling stays identical to the reactive path. Restore._merge_device_info
# preserves the manifest's int values when merging in DeviceInfo (Savage,ChipID otherwise gets
# clobbered with raw bytes and TSS responds with a misleading "not eligible" error).
PREFETCHABLE_UPDATERS: tuple[PrefetchableUpdater, ...] = (
    PrefetchableUpdater(
        "SE",
        "SE",
        [
            # Modern SoCs (A19/iOS 27+) request the SE2 ticket, not the legacy SE ticket
            # (ramrod capture on iPhone 18,4: ResponseTags == ['SE2,Ticket']). The legacy
            # add_se_tags path stays for the reactive pre-SE2 flow; the prefetch targets SE2.
            PrefetchVariant(
                ticket_name="SE2,Ticket",
                add_tags=TSSRequest.add_se2_tags,
                preflight_nonce="SE,Nonce",
                devgen_nonce="SE,Nonce",
            ),
        ],
    ),
    PrefetchableUpdater(
        "Rose",
        "Rose",
        [
            PrefetchVariant(
                ticket_name="Rap,Ticket",
                add_tags=TSSRequest.add_rose_tags,
                preflight_nonce="Rap,Nonce",
                devgen_nonce="Rap,Nonce",
            ),
        ],
    ),
    PrefetchableUpdater(
        "Centauri",
        "Centauri",
        [
            # Converged Wi-Fi/BT/UWB coprocessor. Restore loads usr/lib/updaters/
            # libCentauriUpdater.dylib for it; on iOS 18+ that flows through the generic
            # DeviceGenerated path with response ticket "Wireless1,Ticket". Personalized
            # identically to Rose/Rap (see add_centauri_tags).
            PrefetchVariant(
                ticket_name="Wireless1,Ticket",
                add_tags=TSSRequest.add_centauri_tags,
                preflight_nonce="Wireless1,Nonce",
                devgen_nonce="Wireless1,Nonce",
            ),
        ],
    ),
    # Savage has two on-device shapes. Newer SoCs (e.g. A19 / iPhone Air) expose a
    # nested YonkersDeviceInfo with Yonkers,* fields; older ones expose flat Savage,*
    # fields. Mirror get_device_generated_firmware_data's branch (YonkersDeviceInfo
    # present -> Yonkers ticket, else flat Savage ticket): try each variant and use
    # the first whose nonce is actually present on this device.
    PrefetchableUpdater(
        "Savage",
        "Savage",
        [
            PrefetchVariant(
                ticket_name="Yonkers,Ticket",
                add_tags=TSSRequest.add_yonkers_tags,
                preflight_subkey="YonkersDeviceInfo",
                preflight_nonce="Yonkers,Nonce",
                devgen_nonce="Yonkers,Nonce",
            ),
            PrefetchVariant(
                ticket_name="Savage,Ticket",
                add_tags=TSSRequest.add_savage_tags,
                preflight_nonce="Savage,Nonce",
                devgen_nonce="Savage,Nonce",
            ),
        ],
    ),
    PrefetchableUpdater(
        "T200",
        "T200",
        [
            PrefetchVariant(
                ticket_name="BMU,Ticket",
                add_tags=TSSRequest.add_veridian_tags,
                preflight_nonce="Nonce",
                devgen_nonce="BMU,Nonce",
            ),
        ],
    ),
    PrefetchableUpdater(
        "Vinyl",
        "Vinyl",
        [
            # eUICC (eSIM). Fires its own device-generated eUICC,Ticket during restore
            # (usr/lib/updaters/libVinylUpdater.dylib) in addition to the AP-batch copy.
            # Its nonce is a PAIR — eUICC,Gold.Nonce + eUICC,Main.Nonce — so we use a
            # composite nonce_path; tags are built from the top-level eUICC,* dict.
            PrefetchVariant(
                ticket_name="eUICC,Ticket",
                add_tags=TSSRequest.add_vinyl_prefetch_tags,
                nonce_path=[["eUICC,Gold", "Nonce"], ["eUICC,Main", "Nonce"]],
                devgen_nonce_path=[["eUICC,Gold", "Nonce"], ["eUICC,Main", "Nonce"]],
            ),
        ],
    ),
    PrefetchableUpdater(
        "Baseband",
        "Baseband",
        [
            # A19 baseband fires a device-generated Cellular1,Ticket during restore
            # (usr/lib/updaters/...). Prefetchable only when the baseband manifest-key
            # hashes are available pre-restore; if TSS rejects (or they're absent) the
            # per-chip fallback drops it to the reactive path.
            PrefetchVariant(
                ticket_name="Cellular1,Ticket",
                add_tags=TSSRequest.add_cellular_tags,
                preflight_nonce="Cellular1,Nonce",
                devgen_nonce="Cellular1,Nonce",
            ),
        ],
    ),
)
