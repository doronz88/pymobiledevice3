"""The preflight data a device exposes before a restore, and the device-built updater requests.

Two sources exist. Lockdown's ``PreflightInfo`` (plus ``FirmwarePreflightInfo`` and
``ApParameters``) is what Apple's host reads: each peripheral updater's identity fields and
current nonce. restoreserviced's ``getdevicesidepreflightinfo`` can additionally run the updaters'
own request builders on the device when it is handed the build identity and the firmware files the
updater binds (the "tethered preflight payload"); the result is the TSS request restored would send
for that chip during a restore. Apple's host only builds that payload for Apple displays; on iPhones
this is the only way to see the device's request before a restore.
"""

from typing import Any, Optional

from ipsw_parser.ipsw import IPSW

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.restore_service import RestoreService

# The build-manifest tag prefixes whose firmware each updater's preflight may ask for (their
# BuildIdentityTags, as observed in ramrod captures). Extra files are ignored by the device; a
# missing one fails that updater's request.
UPDATER_FIRMWARE_PREFIXES: dict[str, tuple[str, ...]] = {
    "T200": ("BMU,",),
    "Rose": ("Rap,",),
    "SE": ("SE,",),
    "Vinyl": ("eUICC,",),
    "Savage": ("SEP", "JasmineIR1,", "Yonkers,", "Savage,"),
    "Centauri": ("Wireless1,",),
    "Baseband": ("Cellular1,",),
}


def build_tethered_preflight_payload(ipsw: IPSW, build_identity: dict[str, Any], updater: str) -> dict[str, Any]:
    """The ``payload`` of a ``getdevicesidepreflightinfo`` request for one updater.

    :param ipsw: the firmware the device is being restored to.
    :param build_identity: the build identity selected for the device (with its ``Manifest``).
    :param updater: the updater name as it appears in ``PreflightInfo.DeviceInfo``.
    :returns: ``{"BuildIdentity": build_identity, updater: {<tag>: <bytes>}}``.
    :raises KeyError: if the updater has no known firmware prefixes.
    """
    prefixes = UPDATER_FIRMWARE_PREFIXES[updater]
    files: dict[str, bytes] = {}
    cache: dict[str, bytes] = {}
    for tag, entry in build_identity["Manifest"].items():
        if not tag.startswith(prefixes):
            continue
        path = entry.get("Info", {}).get("Path")
        if path is None:
            continue
        if path not in cache:
            cache[path] = ipsw.read(path)
        files[tag] = cache[path]
    return {"BuildIdentity": dict(build_identity), updater: files}


async def collect_device_side_preflight(
    rsd: RemoteServiceDiscoveryService,
    ipsw: IPSW,
    build_identity: dict[str, Any],
    updaters: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Ask the device to build the TSS request of each updater, one restoreserviced command each.

    :param updaters: the updaters to query; defaults to every one with known firmware prefixes
        except Baseband, whose normal-mode preflight fails (and whose firmware is ~200 MB).
    :returns: ``DeviceInfo``, ``DeviceInfoTags``, ``DeviceInfoRequests`` and ``DeviceInfoFailures``
        merged over all queried updaters, plus ``ApParameters`` from the last reply.
    """
    if updaters is None:
        updaters = [name for name in UPDATER_FIRMWARE_PREFIXES if name != "Baseband"]
    merged: dict[str, Any] = {
        "DeviceInfo": {},
        "DeviceInfoTags": {},
        "DeviceInfoRequests": {},
        "DeviceInfoFailures": {},
    }
    for updater in updaters:
        payload = build_tethered_preflight_payload(ipsw, build_identity, updater)
        # one connection per command: restoreserviced aborts on a second request over the same one
        async with RestoreService(rsd) as service:
            info = await service.get_device_side_preflightinfo(payload)
        for key in ("DeviceInfo", "DeviceInfoTags", "DeviceInfoRequests"):
            if updater in info.get(key, {}):
                merged[key][updater] = info[key][updater]
        merged["DeviceInfoFailures"].update(info.get("DeviceInfoFailures", {}))
        merged["ApParameters"] = info.get("ApParameters")
    return merged
