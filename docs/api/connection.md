---
search:
  boost: 0.5
---

# Connecting to a device

These are the entry points for obtaining a **service provider** — the object every service is
built on top of.

## Lockdown (USB / network)

::: pymobiledevice3.lockdown.create_using_usbmux

::: pymobiledevice3.lockdown.LockdownClient

::: pymobiledevice3.lockdown.UsbmuxLockdownClient

## RemoteServiceDiscovery (iOS 17+ tunnel)

::: pymobiledevice3.remote.remote_service_discovery.RemoteServiceDiscoveryService

## Userspace tunnel (no root)

The preferred way to obtain an iOS 17+ RSD from your own code: an in-process tunnel that needs no
root and no separate `tunneld` daemon.

::: pymobiledevice3.remote.userspace_tunnel.UserspaceRsdTunnel

::: pymobiledevice3.remote.userspace_tunnel.establish_userspace_rsd

## tunneld discovery

::: pymobiledevice3.tunneld.api.get_tunneld_devices
