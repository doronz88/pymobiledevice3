import contextlib
import io
import plistlib
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any, Optional, cast

import pytest
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.restore import base_restore
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.restore.restore_options import RestoreOptions, recovery_os_partition_size
from pymobiledevice3.restore.tss import TSSResponse

HARDWARE_MODEL = "d23ap"
RECOVERY_VARIANT = "Recovery Customer Install"
MIB = 0x100000
RECOVERY_OS_IMAGE = b"AEA1" + bytes(range(256)) * 80  # three FileData chunks


def _entry(path: Optional[str] = None, **info: Any) -> dict[str, Any]:
    if path is not None:
        info["Path"] = path
    return {"Digest": b"d", "Info": info}


def _identity(variant: str, behavior: str, manifest: dict[str, Any], **info: Any) -> dict[str, Any]:
    return {
        "ApBoardID": "0x10",
        "ApChipID": "0x8150",
        "ProductMarketingVersion": "27.2",
        "Info": {"DeviceClass": "D23AP", "Variant": variant, "RestoreBehavior": behavior, **info},
        "Manifest": manifest,
    }


MAIN_MANIFEST = {
    "AppleLogo": _entry("Firmware/main/applelogo.im4p"),
    "SEP": _entry("Firmware/main/sep.im4p"),
    "OS": _entry("main-os.dmg"),
}

RECOVERY_MANIFEST = {
    "AppleLogo": _entry("Firmware/recovery/applelogo.im4p"),
    "AOP": _entry("Firmware/recovery/aop.im4p", IsLoadedByiBoot=True),
    "SIO": _entry("Firmware/recovery/sio.im4p", IsLoadedByiBootStage1=True),
    "Ap,MSRFirmware": _entry("Firmware/recovery/msr.im4p", IsLoadedByiBoot=False),
    "NoPath": _entry(IsLoadedByiBoot=True),
    "OS": _entry("recovery-os.dmg"),
    "KernelCache": _entry("kernelcache.release.d23"),
}

MANIFEST = {
    "ProductBuildVersion": "24B119",
    "ProductVersion": "27.2",
    "SupportedProductTypes": ["iPhone18,4"],
    "BuildIdentities": [
        _identity("Customer Erase Install (IPSW)", "Erase", MAIN_MANIFEST, RecoveryVariant=RECOVERY_VARIANT),
        _identity("Customer Upgrade Install (IPSW)", "Update", MAIN_MANIFEST, RecoveryVariant=RECOVERY_VARIANT),
        # a longer name containing the wanted one must not be picked by the exact match
        _identity(f"{RECOVERY_VARIANT} (Internal)", "Erase", {}),
        _identity(RECOVERY_VARIANT, "Erase", RECOVERY_MANIFEST, BuildNumber="24B119", BuildTrain="RaveB"),
    ],
}

FILES = {
    "Firmware/main/applelogo.im4p": b"main-logo",
    "Firmware/recovery/applelogo.im4p": b"recovery-logo",
    "Firmware/recovery/aop.im4p": b"recovery-aop",
    "Firmware/recovery/sio.im4p": b"recovery-sio",
    "Firmware/recovery/msr.im4p": b"recovery-msr",
    "recovery-os.dmg": RECOVERY_OS_IMAGE,
    "kernelcache.release.d23": b"kernel",
}


class _FakeIPSW:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self.build_manifest = BuildManifest(cast(IPSW, self), plistlib.dumps(manifest))
        self.filelist = [SimpleNamespace(filename=name, file_size=len(data)) for name, data in FILES.items()]

    def read(self, path: str) -> bytes:
        return FILES[path]

    @contextlib.contextmanager
    def open_path(self, path: str) -> Generator[io.BytesIO, None, None]:
        yield io.BytesIO(FILES[path])


class _FakeDevice:
    def get_hardware_model_value(self) -> str:
        return HARDWARE_MODEL

    async def get_ap_parameters(self) -> dict[str, Any]:
        return {}


class _RecordingService:
    def __init__(self, replies: Optional[list[dict[str, Any]]] = None) -> None:
        self.sent: list[dict[str, Any]] = []
        self._replies = replies or []

    async def send_plist(self, d: dict[str, Any], endianity: str = ">", fmt: Any = plistlib.FMT_XML) -> None:
        self.sent.append(d)

    async def recv_plist(self) -> dict[str, Any]:
        return self._replies.pop(0)


class _FakeRestored:
    def __init__(self, service: _RecordingService) -> None:
        self.service = service
        self.sent: list[dict[str, Any]] = []

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)


RECOVERY_TSS = TSSResponse({"ApImg4Ticket": b"recovery-ticket"})


@pytest.fixture
def stitched(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bytes, Any, Any]]:
    calls: list[tuple[str, bytes, Any, Any]] = []

    def stitch_component(name: str, data: bytes, tss: Any, build_identity: Any, ap_parameters: Any) -> bytes:
        calls.append((name, data, tss, build_identity))
        return b"img4:" + data

    monkeypatch.setattr(base_restore, "stitch_component", stitch_component)
    return calls


def _restore(manifest: Optional[dict[str, Any]] = None, service: Optional[_RecordingService] = None) -> Restore:
    restore = Restore(cast(IPSW, _FakeIPSW(manifest or MANIFEST)), cast(Device, _FakeDevice()))
    restore.recovery.tss_recoveryos_root_ticket = RECOVERY_TSS
    restore._restored = cast(Any, _FakeRestored(service or _RecordingService()))
    return restore


def _sent(restore: Restore) -> list[dict[str, Any]]:
    return cast(_FakeRestored, restore._restored).sent


def _manifest_without_recovery_variant() -> dict[str, Any]:
    manifest = dict(MANIFEST)
    manifest["BuildIdentities"] = [
        {**identity, "Info": {k: v for k, v in identity["Info"].items() if k != "RecoveryVariant"}}
        for identity in MANIFEST["BuildIdentities"]
    ]
    return manifest


@pytest.mark.asyncio
async def test_recovery_variant_is_matched_exactly() -> None:
    restore = _restore()
    assert restore.recovery_variant is not None
    assert restore.recovery_variant["Info"]["Variant"] == RECOVERY_VARIANT
    assert restore.recovery.recovery_variant is not None
    assert restore.recovery.recovery_variant["Info"]["Variant"] == RECOVERY_VARIANT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "data_type",
    ["RecoveryOSFileAssetImage", "RecoveryOSIBootFWFilesImages", "RecoveryOSImage", "RecoveryOSVersionData"],
)
async def test_advertised_recovery_os_data_types_have_handlers(data_type: str) -> None:
    assert data_type in _restore()._data_request_handlers


@pytest.mark.asyncio
async def test_file_asset_image_is_personalized_from_the_recovery_identity(stitched: list[Any]) -> None:
    restore = _restore()

    await restore.handle_data_request_msg({
        "DataType": "RecoveryOSFileAssetImage",
        "Arguments": {"FWOverrideKey": "RecoveryOSAppleLogo"},
    })

    assert _sent(restore) == [{"AdditionalBootImages": b"img4:recovery-logo"}]
    ((name, data, tss, build_identity),) = stitched
    assert (name, data, tss) == ("AppleLogo", b"recovery-logo", RECOVERY_TSS)
    assert build_identity is restore.recovery_variant


@pytest.mark.asyncio
@pytest.mark.parametrize("fw_override_key", ["AppleLogo", "RecoveryOSNoSuchComponent"])
async def test_file_asset_image_reports_a_missing_asset(fw_override_key: str, stitched: list[Any]) -> None:
    restore = _restore()

    await restore.send_recovery_os_file_asset_image({"Arguments": {"FWOverrideKey": fw_override_key}})

    assert _sent(restore) == [{"RecoveryOSNoAssetFound": True}]


@pytest.mark.asyncio
async def test_file_asset_image_without_recovery_variant_reports_a_missing_asset(stitched: list[Any]) -> None:
    restore = _restore(_manifest_without_recovery_variant())
    assert restore.recovery_variant is None

    await restore.send_recovery_os_file_asset_image({"Arguments": {"FWOverrideKey": "RecoveryOSAppleLogo"}})

    assert _sent(restore) == [{"RecoveryOSNoAssetFound": True}]


@pytest.mark.asyncio
async def test_iboot_fw_files_images_sends_every_component_loaded_by_iboot(stitched: list[Any]) -> None:
    restore = _restore()

    await restore.handle_data_request_msg({"DataType": "RecoveryOSIBootFWFilesImages", "Arguments": {}})

    assert _sent(restore) == [
        {"AdditionalBootImages": {"AOP": b"img4:recovery-aop", "SIO": b"img4:recovery-sio"}},
    ]
    assert {tss is RECOVERY_TSS for _, _, tss, _ in stitched} == {True}


@pytest.mark.asyncio
async def test_iboot_fw_files_images_without_any_reports_a_missing_asset(stitched: list[Any]) -> None:
    manifest = dict(MANIFEST)
    manifest["BuildIdentities"] = [*MANIFEST["BuildIdentities"][:3], _identity(RECOVERY_VARIANT, "Erase", {})]
    restore = _restore(manifest)

    await restore.send_recovery_os_iboot_fw_files_images({})

    assert _sent(restore) == [{"RecoveryOSNoAssetFound": True}]


@pytest.mark.asyncio
async def test_recovery_os_image_streams_the_recovery_os(monkeypatch: pytest.MonkeyPatch) -> None:
    url_asset_request = {"MsgType": "URLAsset", "Arguments": {"RequestURL": "https://example.invalid/key"}}
    service = _RecordingService(replies=[url_asset_request])
    restore = _restore(service=service)
    url_assets: list[dict[str, Any]] = []

    async def send_url_asset(message: dict[str, Any]) -> None:
        url_assets.append(message)

    monkeypatch.setattr(restore, "send_url_asset", send_url_asset)

    await restore.handle_data_request_msg({"DataType": "RecoveryOSImage", "Arguments": {}})

    chunks = [d["FileData"] for d in service.sent if "FileData" in d]
    assert len(chunks) == 3
    assert b"".join(chunks) == RECOVERY_OS_IMAGE
    assert service.sent[-1] == {"FileDataDone": True}
    # restored asks for the AEA decryption key right after the first chunk
    assert url_assets == [url_asset_request]


@pytest.mark.asyncio
async def test_recovery_os_version_data() -> None:
    restore = _restore()

    await restore.handle_data_request_msg({"DataType": "RecoveryOSVersionData", "Arguments": {}})

    ((reply,),) = [list(m.values()) for m in _sent(restore)]
    assert plistlib.loads(reply) == {
        "BuildNumber": "24B119",
        "BuildTrain": "RaveB",
        "ProductVersion": "27.2",
        "Variant": RECOVERY_VARIANT,
    }


@pytest.mark.asyncio
async def test_recovery_os_requests_fail_without_a_recovery_variant() -> None:
    restore = _restore(_manifest_without_recovery_variant())
    with pytest.raises(PyMobileDevice3Exception):
        await restore.send_recovery_os_version_data({})


def test_recovery_os_partition_size_counts_listed_and_iboot_loaded_components() -> None:
    manifest = {
        "OS": _entry("os.dmg"),  # listed asset
        "AOP": _entry("aop.im4p", IsLoadedByiBoot=True),
        "Ap,MSRFirmware": _entry("msr.im4p"),  # neither listed nor loaded by iBoot
        "KernelCache": _entry("missing-from-the-ipsw"),
    }
    sizes = {"os.dmg": 300 * MIB, "aop.im4p": MIB // 2, "msr.im4p": 50 * MIB}

    # ceil(300.5) = 301 MiB -> 301 * 1.05 + 25, 301 * 1.25 + 25
    assert recovery_os_partition_size(cast(Any, {"Manifest": manifest}), sizes) == (341, 401)


@pytest.mark.asyncio
async def test_restore_options_install_the_recovery_os() -> None:
    restore = _restore()
    assert restore.recovery_variant is not None
    sizes = restore._recovery_os_partition_sizes()

    opts = RestoreOptions(
        build_identity=restore.build_identity,
        recovery_variant=restore.recovery_variant,
        recovery_os_partition_sizes=sizes,
    ).to_dict()

    assert opts["InstallRecoveryOS"] is True
    assert opts["RecoveryOSBundlePath"] == "/tmp/Per2.tmp"
    assert opts["AuthInstallRecoveryOSVariant"] == RECOVERY_VARIANT
    assert sizes is not None
    assert (opts["recoveryOSPartitionSize"], opts["recoveryOSMaxPartitionSize"]) == sizes


def test_restore_options_without_recovery_variant() -> None:
    opts = RestoreOptions().to_dict()
    for key in ("InstallRecoveryOS", "RecoveryOSBundlePath", "AuthInstallRecoveryOSVariant", "recoveryOSPartitionSize"):
        assert key not in opts


class _FakeTSSDevice(_FakeDevice):
    async def get_ap_nonce(self) -> bytes:
        return b"nonce"

    async def get_is_image4_supported(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_recovery_os_root_ticket_is_requested_for_the_recovery_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    recovery = Recovery(cast(IPSW, _FakeIPSW(MANIFEST)), cast(Device, _FakeTSSDevice()))
    requested: list[Any] = []

    async def get_tss_response(build_identity: Any = None) -> TSSResponse:
        requested.append(build_identity)
        return TSSResponse({"ApImg4Ticket": f"ticket-{len(requested)}".encode()})

    monkeypatch.setattr(recovery, "get_tss_response", get_tss_response)

    await recovery.fetch_tss_record()

    assert requested == [None, recovery.recovery_variant]
    assert recovery.tss_recoveryos_root_ticket == {"ApImg4Ticket": b"ticket-2"}


@pytest.mark.asyncio
async def test_missing_recovery_variant_fails_the_tss_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = dict(MANIFEST)
    manifest["BuildIdentities"] = MANIFEST["BuildIdentities"][:2]
    recovery = Recovery(cast(IPSW, _FakeIPSW(manifest)), cast(Device, _FakeTSSDevice()))

    async def get_tss_response(build_identity: Any = None) -> TSSResponse:
        return TSSResponse({"ApImg4Ticket": b"ticket"})

    monkeypatch.setattr(recovery, "get_tss_response", get_tss_response)

    with pytest.raises(PyMobileDevice3Exception, match="not found"):
        await recovery.fetch_tss_record()


@pytest.mark.asyncio
async def test_recovery_identity_request_allows_nerd_boot() -> None:
    manifest = dict(MANIFEST)
    manifest["BuildIdentities"] = [
        *MANIFEST["BuildIdentities"][:-1],
        {**MANIFEST["BuildIdentities"][-1], "AllowNeRDBoot": True},
    ]
    recovery = Recovery(cast(IPSW, _FakeIPSW(manifest)), cast(Device, _FakeTSSDevice()))

    main_parameters: dict[str, Any] = {}
    recovery.populate_tss_request_from_manifest(main_parameters)
    recovery_parameters: dict[str, Any] = {}
    recovery.populate_tss_request_from_manifest(recovery_parameters, build_identity=recovery.recovery_variant)

    # TSS refuses the RecoveryOS ticket as "not eligible for the requested build" without it
    assert "AllowNeRDBoot" not in main_parameters
    assert recovery_parameters["AllowNeRDBoot"] is True
