---
search:
  boost: 0.5
---

# Lockdown services

Every service takes a service provider and is used as an async context manager. Most derive
from `LockdownService`; `CrashReportsManager` instead wraps other services. See the
[Python API guide](../guides/python-api.md#2-the-service-pattern) for the pattern.

## Base class

::: pymobiledevice3.services.lockdown_service.LockdownService

## Common services

::: pymobiledevice3.services.os_trace.OsTraceService

::: pymobiledevice3.services.installation_proxy.InstallationProxyService

::: pymobiledevice3.services.streaming_zip_conduit.StreamingZipConduitService

::: pymobiledevice3.services.afc.AfcService

::: pymobiledevice3.services.diagnostics.DiagnosticsService

::: pymobiledevice3.services.springboard.SpringBoardServicesService

::: pymobiledevice3.services.crash_reports.CrashReportsManager

::: pymobiledevice3.services.mobile_image_mounter.MobileImageMounterService

::: pymobiledevice3.services.storage_mounter_bridge.StorageMounterBridgeService

## DDI over cryptexd (iOS 17+)

`CryptexdService` installs the Developer Disk Image (DDI) as a cryptex, without the image
mounter. It is a RemoteXPC service: construct it with a `RemoteServiceDiscoveryService` (it
requires an RSD tunnel), not a lockdown client.

`auto_mount` uses it from `CRYPTEX_IMAGE_MIN_VERSION` (iOS 27) on, and then requires an RSD,
raising `RSDRequiredError` for a plain lockdown client; `uses_cryptex_image` reports whether a
device qualifies. Below that version it mounts the image mounter's `PersonalizedDMG`, since older
`cryptexd` versions reject the install. Devices newer than the DDI (e.g. the iPhone 18 series)
are not in the `PersonalizedDMG`'s build manifest, so for them the cryptex is the only option.

::: pymobiledevice3.services.cryptexd.CryptexdService

::: pymobiledevice3.services.cryptexd.fetch_cryptex_ddi

::: pymobiledevice3.services.cryptexd.InstalledCryptex

::: pymobiledevice3.services.bt_packet_logger.BtPacketLoggerService
