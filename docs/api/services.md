---
search:
  boost: 0.5
---

# Lockdown services

Every service takes a service provider and is used as an async context manager. Unless noted
otherwise, they derive from `LockdownService`.

## Base class

::: pymobiledevice3.services.lockdown_service.LockdownService

## Common services

::: pymobiledevice3.services.os_trace.OsTraceService

::: pymobiledevice3.services.installation_proxy.InstallationProxyService

::: pymobiledevice3.services.afc.AfcService

::: pymobiledevice3.services.diagnostics.DiagnosticsService

::: pymobiledevice3.services.springboard.SpringBoardServicesService

::: pymobiledevice3.services.crash_reports.CrashReportsManager

::: pymobiledevice3.services.mobile_image_mounter.MobileImageMounterService

## DDI over cryptexd (iOS 17+)

`CryptexdService` installs the DeveloperDiskImage as a cryptex without the image mounter. It is a
RemoteXPC service: construct it with a `RemoteServiceDiscoveryService` (it requires an RSD
tunnel), not a lockdown client.

::: pymobiledevice3.services.cryptexd.CryptexdService

::: pymobiledevice3.services.cryptexd.fetch_cryptex_ddi

::: pymobiledevice3.services.cryptexd.InstalledCryptex

::: pymobiledevice3.services.bt_packet_logger.BtPacketLoggerService
