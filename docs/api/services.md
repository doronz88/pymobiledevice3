---
search:
  boost: 0.5
---

# Lockdown services

Every service takes a service provider and is used as an async context manager. They all derive
from `LockdownService`.

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
