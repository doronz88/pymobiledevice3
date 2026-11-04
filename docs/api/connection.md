---
search:
  boost: 0.5
---

# Connecting to a device

These are the entry points for obtaining a **service provider**, the object every service is
built on top of: a lockdown client for classic services, or a `RemoteServiceDiscoveryService`
(RSD) for iOS 17+ developer services.

## Lockdown (USB / network)

::: pymobiledevice3.lockdown.create_using_usbmux

::: pymobiledevice3.lockdown.LockdownClient

::: pymobiledevice3.lockdown.UsbmuxLockdownClient

## RemoteServiceDiscovery (iOS 17+ tunnel)

::: pymobiledevice3.remote.remote_service_discovery.RemoteServiceDiscoveryService

## No-root tunnels (iOS 17+)

The preferred way to obtain an iOS 17+ RSD from your own code: in-process tunnels that need no
root and no separate `tunneld` daemon. `PreferredRsdTunnel` picks the transport for you; the
other two select one explicitly.

::: pymobiledevice3.remote.rsd_tunnel.PreferredRsdTunnel

::: pymobiledevice3.remote.userspace_tunnel.UserspaceRsdTunnel

::: pymobiledevice3.remote.userspace_tunnel.establish_userspace_rsd

::: pymobiledevice3.remote.native_tunnel.NativeRemotedTunnel

## tunneld discovery

::: pymobiledevice3.tunneld.api.get_tunneld_devices
