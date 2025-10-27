import asyncio
import logging
import plistlib
import typing
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import asn1
import requests

from pymobiledevice3.exceptions import PyMobileDevice3Exception, TSSError
from pymobiledevice3.restore.img4 import COMPONENT_FOURCC
from pymobiledevice3.utils import bytes_to_uint, plist_access_path

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
