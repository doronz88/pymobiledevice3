import dataclasses
import plistlib
from pathlib import Path
from typing import Any, Optional

from pymobiledevice3.darwin_errno import describe_errno
from pymobiledevice3.exceptions import CryptexdError
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import FileTransferType, XpcInt64Type, XpcUInt64Type
from pymobiledevice3.restore.tss import TSSRequest

#: ``nonce-domain`` index used for the cryptex nonce on current devices. The daemon resolves the
#: index through its own nonce-domain table, so unsupported indices fail with a ``cferr``.
NONCE_DOMAIN_CRYPTEX = 2

#: Identifier the mounted personalized DeveloperDiskImage is installed under.
DDI_CRYPTEX_IDENTIFIER = "com.apple.MobileAsset.DDI"

#: Values Xcode sends when installing the DDI cryptex, captured from a ``devicectl`` install.
CLIENT_VERSION = 3
DDI_IMAGE_TYPE_INDEX = 10
DDI_PERSISTENCE = 2
DDI_NONCE_PERSISTENCE = 1


#: Where Xcode unpacks ``CoreDevice/CandidateDDIs/iOS_DDI.dmg``. The Cryptex1 assets live only
#: here — the DDI repository pymobiledevice3 caches for the image mounter ships the
#: ``PersonalizedDMG`` variant, which has no ``cryptex_info`` or ``root_hash``.
XCODE_DDI_RESTORE_DIR = Path("/Library/Developer/DeveloperDiskImages/iOS_DDI/Restore")

#: The one build identity that describes a cryptex, out of ~141 in the DDI's BuildManifest.
CRYPTEX_VARIANT_SUFFIX = "Developer Disk Image Cryptex"


def unwrap_nonce(blob: bytes) -> bytes:
    """Extract the nonce from cryptexd's nonce structure.

    ``get-nonce`` returns 56 bytes: a 2-byte lead, the nonce, then a little-endian uint32 length.
    The nonce inside is what TSS wants (verified: it matches both
    `MobileImageMounterService.query_nonce` and the ``cnch`` tag of Xcode's ticket byte-for-byte).
    """
    return blob[2 : 2 + int.from_bytes(blob[-4:], "little")]


@dataclasses.dataclass
class InstalledCryptex:
    """A cryptex currently installed on the device (e.g. the mounted DeveloperDiskImage)."""

    identifier: str
    version: str


@dataclasses.dataclass
class Cryptex1Assets:
    """The four payloads and the parameters needed to install a Cryptex1 image."""

    image: bytes
    trustcache: bytes
    info: bytes
    volumehash: bytes
    cryptex1_properties: dict[str, Any]
    build_identity: dict[str, Any]

    @property
    def nonce_domain(self) -> int:
        return int(self.build_identity["Cryptex1,NonceDomain"])


def load_cryptex1_assets(restore_dir: Path = XCODE_DDI_RESTORE_DIR) -> Cryptex1Assets:
    """
    Load the Cryptex1 DDI payloads and parameters out of Xcode's DDI bundle.

    Unlike the mounter's ``PersonalizedDMG``, the ``Cryptex1,GenericDmg`` is not personalized —
    it is byte-identical across devices, and only the info plist, trust cache and volume hash are.

    :param restore_dir: Xcode's unpacked DDI ``Restore`` directory.
    :raises FileNotFoundError: if the bundle (or its cryptex build identity) is not present.
    """
    manifest_path = restore_dir / "BuildManifest.plist"
    if not manifest_path.exists():
        raise FileNotFoundError(f"no DDI BuildManifest at {manifest_path}; is Xcode installed?")
    build_manifest = plistlib.loads(manifest_path.read_bytes())
    build_identity = next(
        (
            identity
            for identity in build_manifest["BuildIdentities"]
            if identity.get("Info", {}).get("Variant", "").endswith(CRYPTEX_VARIANT_SUFFIX)
        ),
        None,
    )
    if build_identity is None:
        raise FileNotFoundError(f"no {CRYPTEX_VARIANT_SUFFIX!r} build identity in {manifest_path}")

    manifest = build_identity["Manifest"]

    def read(key: str) -> bytes:
        return (restore_dir / manifest[key]["Info"]["Path"]).read_bytes()

    # Mirrors the dict Xcode sends; the integers must be uint64 or the daemon rejects them.
    cryptex1_properties: dict[str, Any] = {
        "Cryptex1,UseProductClass": build_identity["Cryptex1,UseProductClass"],
        "MountedCryptex": False,
        "Cryptex1,SubType": XpcUInt64Type(build_identity["Cryptex1,SubType"]),
        "Cryptex1,NonceDomain": XpcUInt64Type(build_identity["Cryptex1,NonceDomain"]),
        "Cryptex1,Version": build_identity["Cryptex1,Version"],
        "Cryptex1,PreauthVersion": build_identity["Cryptex1,PreauthorizationVersion"],
    }
    return Cryptex1Assets(
        image=read("Cryptex1,GenericDmg"),
        trustcache=read("Cryptex1,GenericTrustCache"),
        info=read("Cryptex1,CryptexInfoPlist"),
        volumehash=read("Cryptex1,GenericVolume"),
        cryptex1_properties=cryptex1_properties,
        build_identity=build_identity,
    )


class CryptexdService(RemoteService):
    """
    Query ``cryptexd`` over RemoteXPC (``com.apple.security.cryptexd.remote``).

    The service takes ``{"routine": <name>, "argv": {...}}`` requests and answers with either
    ``{"error": 0, "argv": <result>}`` on success or ``{"cferr": {...}}`` on failure, where
    ``error`` is a device-side Darwin errno.

    All six routines the daemon dispatches are implemented: ``read-personalization-id``,
    ``copy-installed``, ``get-nonce``, ``roll-nonce``, ``uninstall`` and ``install``. The last one
    delivers its payloads as out-of-band XPC file transfers, so unlike the others it keeps one
    connection open across the request and the transfers.

    The daemon serves exactly one routine per connection and then closes it — a second request on
    the same connection fails with an incomplete read, whether or not the first one succeeded. Each
    call therefore opens and closes its own connection, and instances are freely reusable.

    Requires an iOS 17+ RSD tunnel.
    """

    SERVICE_NAME = "com.apple.security.cryptexd.remote"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def connect(self) -> None:
        """No-op: cryptexd is one-routine-per-connection, so `invoke` manages its own connection."""

    async def close(self) -> None:
        """No-op: `invoke` closes the connection it opened."""

    async def invoke(self, routine: str, argv: dict[str, Any]) -> Any:
        """
        Send a single ``routine`` request on a fresh connection and return its ``argv`` payload.

        :param routine: routine name, e.g. ``read-personalization-id``.
        :param argv: named arguments for the routine.
        :raises CryptexdError: if the daemon answered with a ``cferr`` or a non-zero ``error``.
        """
        connection = self.rsd.start_remote_service(self.SERVICE_NAME)
        await connection.connect()
        try:
            response = await connection.send_receive_request({"routine": routine, "argv": argv})
        finally:
            await connection.close()
        return self._unwrap(routine, response)

    @staticmethod
    def _unwrap(routine: str, response: dict[str, Any]) -> Any:
        """Raise on a failed reply, otherwise return its ``argv`` payload."""
        cferr: Optional[dict[str, Any]] = response.get("cferr")
        if cferr is not None:
            user_info: dict[str, Any] = cferr.get("cferr_userinfo") or {}
            raise CryptexdError(
                f"{routine} failed: {user_info.get('NSLocalizedDescription', cferr)} "
                f"({cferr.get('cferr_domain')}: {cferr.get('cferr_code')})"
            )
        # Successful replies carry error=0; read-personalization-id omits the key entirely.
        error = response.get("error", 0)
        if error:
            raise CryptexdError(f"{routine} failed: {describe_errno(error)}")
        return response.get("argv")

    async def install(
        self,
        image: bytes,
        trustcache: bytes,
        im4m: bytes,
        info: bytes,
        volumehash: bytes,
        cryptex1_properties: dict[str, Any],
        image_type_index: int = DDI_IMAGE_TYPE_INDEX,
        persistence: int = DDI_PERSISTENCE,
        nonce_persistence: int = DDI_NONCE_PERSISTENCE,
        auth: int = 0,
    ) -> None:
        """
        Install a cryptex.

        The five payloads are announced in the request as XPC file transfers and then pushed on
        their own streams; the daemon only replies once it has consumed all of them.

        The request shape mirrors what Xcode sends, captured off the wire during a
        ``devicectl`` DDI install. Two details are easy to get wrong: the cryptex is identified
        solely by `info` (a ``CryptexInfoPlist``) — there is no identifier argument, and omitting
        it makes the daemon log every line as ``[anonymous]`` — and the integers inside
        `cryptex1_properties` must be **uint64**, since int64 is rejected with
        ``Cryptex1,NonceDomain [79: Inappropriate file type or format]``.

        .. note::
            The request itself is verified: the daemon accepts it, consumes all five payloads and
            proceeds to image4 trust evaluation. Completing an install additionally needs an `im4m`
            that is a *Cryptex1* ticket bound to the current cryptex nonce; producing one is not
            implemented (see `TSSRequest.add_cryptex1_tags`).

        :param image: the cryptex disk image, i.e. the build manifest's ``Cryptex1,GenericDmg``.
        :param trustcache: ``Cryptex1,GenericTrustCache``.
        :param im4m: the Cryptex1 personalization ticket.
        :param info: ``Cryptex1,CryptexInfoPlist``; names and versions the cryptex.
        :param volumehash: ``Cryptex1,GenericVolume`` root hash; without it the daemon reports
            "AuthAPFS will not be supported".
        :param cryptex1_properties: the ``Cryptex1,*`` parameters from the build identity.
        :param image_type_index: index of the image type within the cryptex.
        :param persistence: cryptex persistence mode.
        :param nonce_persistence: nonce persistence mode.
        :param auth: authentication mode.
        :raises CryptexdError: if the daemon rejected the request or the install failed.
        """
        transfers = [
            ("image", image),
            ("trustcache", trustcache),
            ("im4m", im4m),
            ("info", info),
            ("volumehash", volumehash),
        ]
        argv: dict[str, Any] = {
            "auth": XpcUInt64Type(auth),
            "client-version": XpcUInt64Type(CLIENT_VERSION),
            "cryptex1-properties": cryptex1_properties,
            "image-type-index": XpcInt64Type(image_type_index),
            "nonce-persistence": XpcUInt64Type(nonce_persistence),
            "persistence": XpcUInt64Type(persistence),
        }
        for transfer_id, (key, payload) in enumerate(transfers, start=1):
            argv[key] = FileTransferType(transfer_size=len(payload), transfer_id=transfer_id)

        connection = self.rsd.start_remote_service(self.SERVICE_NAME)
        await connection.connect()
        try:
            await connection.send_request({"routine": "install", "argv": argv}, wanting_reply=True)
            for transfer_id, (_, payload) in enumerate(transfers, start=1):
                await connection.send_file_transfer(transfer_id, payload)
            response = await connection.receive_response()
        finally:
            await connection.close()
        self._unwrap("install", response)

    @staticmethod
    def _nonce_selector(nonce_domain: Optional[int], nonce_domain_handle: Optional[int]) -> dict[str, Any]:
        """Build the argv selecting a nonce domain, by index or by handle.

        The daemon accepts either form and reports them separately ("nonce domain doesn't exist for
        index: ..." versus "... for handle: ...").
        """
        if nonce_domain is not None and nonce_domain_handle is not None:
            raise ValueError("pass either nonce_domain or nonce_domain_handle, not both")
        if nonce_domain_handle is not None:
            return {"nonce-domain-handle": XpcUInt64Type(nonce_domain_handle)}
        domain = NONCE_DOMAIN_CRYPTEX if nonce_domain is None else nonce_domain
        return {"nonce-domain": XpcUInt64Type(domain)}

    async def cryptex_nonce(self, nonce_domain: int) -> bytes:
        """Read a nonce domain's nonce, unwrapped from the daemon's nonce structure.

        :param nonce_domain: index into the daemon's nonce-domain table.
        """
        return unwrap_nonce(await self.get_nonce(nonce_domain=nonce_domain))

    async def auto_install_ddi(self, restore_dir: Path = XCODE_DDI_RESTORE_DIR) -> InstalledCryptex:
        """
        Personalize and install the DeveloperDiskImage cryptex entirely through ``cryptexd``.

        Assembles everything from Xcode's DDI bundle, requests a Cryptex1 ticket, and installs.

        .. warning::
            Not working end to end: `TSSRequest.add_cryptex1_tags` does not yet produce a ticket
            Apple will sign, so this currently fails at image4 trust evaluation. Everything either
            side of that step is verified against a device.

        :param restore_dir: Xcode's unpacked DDI ``Restore`` directory.
        :returns: the installed cryptex, as reported back by `copy_installed`.
        :raises CryptexdError: if the daemon rejected the image.
        """
        assets = load_cryptex1_assets(restore_dir)
        request = TSSRequest()
        request.add_cryptex1_tags(
            assets.build_identity,
            await self.read_personalization_identifiers(),
            await self.cryptex_nonce(assets.nonce_domain),
        )
        response = await request.send_receive()
        im4m = response.get("Cryptex1,Ticket") or response["ApImg4Ticket"]

        await self.install(
            assets.image,
            assets.trustcache,
            im4m,
            assets.info,
            assets.volumehash,
            assets.cryptex1_properties,
        )
        installed = await self.copy_installed()
        ddi = next((cryptex for cryptex in installed if cryptex.identifier == DDI_CRYPTEX_IDENTIFIER), None)
        if ddi is None:
            raise CryptexdError(f"install reported success but {DDI_CRYPTEX_IDENTIFIER} is not installed")
        return ddi

    async def read_personalization_identifiers(self) -> dict[str, Any]:
        """
        Read the device's AppleImage4 chip instance, used to personalize a cryptex.

        The returned mapping uses the daemon's ``img4_chip_*`` key names, e.g. ``img4_chip_chip``
        (ChipID), ``img4_chip_bord`` (BoardID) and ``img4_chip_ecid`` (ECID).
        """
        return await self.invoke("read-personalization-id", {})

    async def copy_installed(self) -> list[InstalledCryptex]:
        """
        List the cryptexes currently installed on the device.

        On a device with a mounted personalized DeveloperDiskImage this reports
        ``com.apple.MobileAsset.DDI`` together with its version.
        """
        argv: dict[str, Any] = await self.invoke("copy-installed", {}) or {}
        entries: list[dict[str, Any]] = argv.get("remote-cryptex-array", [])
        return [
            InstalledCryptex(
                identifier=entry["remote-cryptex-identifier"],
                version=entry["remote-cryptex-version"],
            )
            for entry in entries
        ]

    async def get_nonce(self, nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> bytes:
        """
        Read the nonce for a nonce domain.

        The returned blob is the nonce structure, not the bare nonce: on current devices it is
        56 bytes carrying the 48-byte nonce at offset 2. `MobileImageMounterService.query_nonce`
        returns those 48 bytes alone.

        :param nonce_domain: index into the daemon's nonce-domain table; defaults to
                             `NONCE_DOMAIN_CRYPTEX` when neither selector is given.
        :param nonce_domain_handle: handle of the nonce domain, as an alternative to `nonce_domain`.
        :raises ValueError: if both selectors are given.
        :raises CryptexdError: if the domain does not exist or has no nonce.
        """
        argv = await self.invoke("get-nonce", self._nonce_selector(nonce_domain, nonce_domain_handle))
        return argv["nonce"]

    async def roll_nonce(self, nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> None:
        """
        Roll (regenerate) the nonce for a nonce domain.

        This invalidates anything personalized against the previous nonce — notably a mounted
        personalized DeveloperDiskImage, which must be re-personalized and re-mounted afterwards.

        .. warning::
            Unverified: no argv shape found so far actually rolls the nonce. Placing the selector
            in ``argv`` (which is where ``get-nonce`` reads it, and where uint64 works) fails with
            ``key nonce-domain doesn't exist``; placing it at the top level of the request returns
            a reply with no error but leaves the nonce unchanged. The daemon reads it from
            somewhere else again — ``_sub_remote_service_demux`` fetches both selectors with
            ``xpc_dictionary_get_uint64``, so the type is right and only the location is wrong.

        :param nonce_domain: index into the daemon's nonce-domain table; defaults to
                             `NONCE_DOMAIN_CRYPTEX` when neither selector is given.
        :param nonce_domain_handle: handle of the nonce domain, as an alternative to `nonce_domain`.
        :raises ValueError: if both selectors are given.
        :raises CryptexdError: if the domain does not exist or the roll failed.
        """
        await self.invoke("roll-nonce", self._nonce_selector(nonce_domain, nonce_domain_handle))

    async def uninstall(self, identifier: str, version: Optional[str] = None) -> None:
        """
        Uninstall an installed cryptex.

        :param identifier: cryptex identifier as reported by `copy_installed`, e.g.
                           ``com.apple.MobileAsset.DDI``.
        :param version: optional version to scope the removal to.
        :raises CryptexdError: if no such cryptex is installed (``errno 2``) or removal failed.
        """
        argv: dict[str, Any] = {"remote-cryptex-identifier": identifier}
        if version is not None:
            argv["remote-cryptex-version"] = version
        await self.invoke("uninstall", argv)
