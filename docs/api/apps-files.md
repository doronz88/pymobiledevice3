---
search:
  boost: 0.5
---

# Apps, files &amp; profiles

App-container file access, configuration profiles, and provisioning profiles.
(`InstallationProxyService` and `AfcService` live under [Lockdown services](services.md).)

::: pymobiledevice3.services.house_arrest.HouseArrestService

::: pymobiledevice3.services.mobile_config.MobileConfigService

::: pymobiledevice3.services.misagent.MisagentService

::: pymobiledevice3.services.file_relay.FileRelayService

## Install records (iOS 17+)

`InstallCoordinationProxyService` is a RemoteXPC service: construct it with a
`RemoteServiceDiscoveryService` (it requires an RSD tunnel), not a lockdown client.

::: pymobiledevice3.services.install_coordination_proxy.InstallCoordinationProxyService

::: pymobiledevice3.services.install_coordination_proxy.InstallRecord
