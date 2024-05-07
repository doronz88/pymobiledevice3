# Understanding iDevice protocol layers

- [Understanding iDevice protocol layers](#understanding-idevice-protocol-layers)
  - [Overview](#overview)
  - [usbmuxd](#usbmuxd)
  - [lockdownd](#lockdownd)
  - [Lockdown services](#lockdown-services)
  - [DeveloperDiskImage](#developerdiskimage)
  - [DVT](#dvt)
  - [RemoteXPC](#remotexpc)
  - [Other python service examples](#other-python-service-examples)

## Overview

In this article we're going to review how communicating to an iDevice (iOS/iPadOS/...) actually works.

In order to understand it all, we are going to review:

- [`usbmuxd`](#usbmuxd)
- [`lockdownd`](#lockdownd)
- [Lockdown services](#lockdown-services)
- [DeveloperDiskImage](#developerdiskimage)
- [DVT](#dvt)
- [RemoteXPC](#remotexpc)

Once we understand each part, we'll discuss how [`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3) is
structured to handle communication to all these moving parts.

## usbmuxd

The `usbmuxd` (USB Multiplexer Daemon, though technically it supports both USB and Wi-Fi) daemon is responsible for two
main tasks:

- Detecting iDevices in both your LAN and via USB.
- Proxying traffic to any TCP port onto the target device.

It provides this api by exposing a unix domain socket `/var/run/usbmuxd`.

In order to interact with `usbmuxd`, you may use the following commands from your shell:

```shell
# List connected iDevices
pymobiledevice3 usbmux list

# Start a TCP server listening on port 2222, transferring all received traffic to
# TCP port 22 on the device
# NOTE: you may use `-d` in order to start this process as daemonized
pymobiledevice3 usbmux forward 2222 22

# If you are using corellium, you may want to forward all the commands to use their
# remote usbmuxd, listening on the hard-coded port 5000
# As such, (almost) all of pymobiledevice3's commands, may accept an optional `--usbmux` option 
pymobiledevice3 usbmux list --usbmux 10.11.1.2:5000
```

The same can be accessed via python API:

```python
from pymobiledevice3.usbmux import list_devices

# Listing all connected devices locally
usbmux_devices = list_devices()

# Or if using corellium, or any other remote usbmuxd
usbmux_devices = list_devices('10.11.1.2:5000')

# Now may list them and establish a TCP connection to any port on-device
for device in usbmux_devices:
    # The serial can either be the device UDID if it's connected via USB, or its Wi-Fi mac address
    if device.serial == '11223344':
        sock = device.connect(22)  # return a pure python socket object
```

On a macOS workstation this daemon is builtin. On other platforms however you'll need an external tool for that:

- Windows
  - iTunes' installations includes "Apple Mobile Service" to perform the same thing
  - This version exposes the same API as `usbmuxd`, but over TCP port 27015
- Linux
  - <https://github.com/libimobiledevice/usbmuxd>
    - Can be installed from APT on ubuntu, but only supports USB devices
  - <https://github.com/tihmstar/usbmuxd2>
    - Technically supports both USB and Wi-Fi devices, but I haven't tested it myself

Okay, so now that we understand `usbmuxd` main purpose is to simply connecting to TCP ports in an iDevice, but where
will we wish to connect to? Probably to [`lockdownd`](#lockdownd).

## lockdownd

The `lockdownd` is daemon that listens on the hard-coded TCP port 62078. It has 3 main purposes:

- Query general device information (ProductVersion, UDID, ...)
- Pairing
- Accessing lockdown services

You may query the device information via `lockdownd` using `LockdownClient` from python:

```python
from pymobiledevice3.lockdown import create_using_usbmux, create_using_tcp

# If we avoid passing the `serial` option, we'll get a `LockdownClient` instance 
# of the first available device 
# By default, pymobiledevice3 attempts to pair with the device, if it was not already 
# paired (presenting a "Trust/Don't Trust" dialog). We use the `autopair=False` when 
# we don't want to block on that operation
lockdown = create_using_usbmux(serial='11223344', autopair=False)

# Corellium anyone?
correlium_lockdown = create_using_usbmux(serial='11223344', autopair=False, usbmux_address='10.11.1.2:5000')

# If the device can be found in our LAN, and we know it's address, we simply connect to it
# Please note the device does not allow pairing over LAN, so we must first pair it over USB
lockdown = create_using_tcp('192.168.2.7', autopair=False)

# An example for accessing a lockdown attribute
print(lockdown.product_version)
```

As you may have noticed, we mentioned the iDevice can be interacted over Wi-Fi. For that, we'll need to first enable
this feature over USB:

```shell
# Turn it on
pymobiledevice3 lockdown wifi-connection on

# Or off
pymobiledevice3 lockdown wifi-connection off
```

Now the device will use the [bonjour](https://en.wikipedia.org/wiki/Bonjour_(software)) protocol in order to announce
its availability over the LAN. You may query these available devices using:

```shell
# It announces itself using the `_apple-mobdev2._tcp.local.` name
pymobiledevice3 bonjour mobdev2
```

Of course this can also be done in python in asyncio API:

```python
from pymobiledevice3.lockdown import get_mobdev2_lockdowns

async for ip, lockdown in get_mobdev2_lockdowns():
    print(ip, lockdown.product_version)
```

However, as long as we don't pair, we can only access a pretty small pool of data. We won't delve into how the pairing
is actually performed, since this is a top-level guide, but we'll tell you that after a key-exchange, followed by a user
prompt to trust our client, we can access everything `lockdownd` has to offer.

*If you're interested, Jon Gabilondo wrote a fantastic thorough article about all the
process. You may read about it in
here: <https://jon-gabilondo-angulo-7635.medium.com/understanding-usbmux-and-the-ios-lockdown-service-7f2a1dfd07ae>*

We may interact with `lockdownd` using any of the `lockdown` subcommands:

```shell
# Pair with the device
pymobiledevice3 lockdown pair

# Or unpair
pymobiledevice3 lockdown unpair

# Or just view general information
pymobiledevice3 lockdown info
```

This is all nice and all, but usually the more interesting stuff can be found in
the [lockdown services](#lockdown-services).

## Lockdown services

The `lockdownd` daemon can also be used to spawn other device services and access their data. It does so according to a
hard-coded plist built into one of `lockdownd` sections. We may examine them using:

```shell
segedit /path/to/lockdownd -extract __TEXT __services /tmp/lockdown_services.plist
```

In that plist we'll see different service names, where each of them can be started using lockdown's `StartService`
protocol command.

The response to the `StartService` command we may then connect to using `usbmuxd` as discussed earlier. Each of these
services implements its own unique protocol. You may try to play around these services using:

```shell
# You may try any other service name in order to study and mess with its protocol messages
pymobiledevice3 lockdown service com.apple.mobile.heartbeat
```

And of course this is also available from code:

```python
from pymobiledevice3.lockdown import create_using_usbmux

# Create the LockdownClient instance 
lockdown = create_using_usbmux()

# Get a handle to the service
service = lockdown.start_lockdown_service(SERIVCE_NAME)

# Attempt to send and receive messages from it
service.sendall(b'hello')
response = service.recvall(20)
```

Many of the services exposed by `lockdownd`, are already implemented in `pymobiledevice3`.

For example consider the following examples:

```shell
# View device syslog
pymobiledevice3 syslog live

# Reboot the device
pymobiledevice3 diagnostics restart

# And the list goes on and on...
```

In order to access the different services, the project is structured in the following
from: `pymobiledevice3.services.service_name.ServiceClass`.

For example:

```python
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.os_trace import OsTraceService

lockdown = create_using_usbmux()

# Print all syslog line entries, whereas `OsTraceService` as a wrapper to the 
# `com.apple.os_trace_relay` lockdown service, and the `syslog` method is a protocol operation
# for that service
for entry in OsTraceService(lockdown).syslog():
    print(entry)
```

## DeveloperDiskImage

Some of the more interesting services we can interact with for automation purposes can only be accessed from an external
image, called the DeveloperDiskImage (or DDI for short). Once we mount it, `lockdownd` searches for
services in `/Lockdown/ServiceAgents`, in an attempt to increase its possibilities for lockdown services.

As of iOS 15, Apple added the "DeveloperMode" option, forcing users to first enable it before they can mount the DDI.
Assuming, your iDevice doesn't have a pin-code defined, you can simply enable it from CLI:

```shell
# Enable it
pymobiledevice3 amfi enable-developer-mode

# Or just query its state
pymobiledevice3 amfi developer-mode-status
```

As any other lockdown service, this of course can be accessed from python API:

```python
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.amfi import AmfiService

lockdown = create_using_usbmux()
amfi = AmfiService(lockdown)
amfi.enable_developer_mode()
```

Once the DeveloperMode is on, we can mount the DDI. This however has very much changed in many aspects in iOS 17. For
short, we'll just say you can simply use the following CLI command:

```shell
# This will automatically deduct the correct way to mount the DDI onto your device
# Please note this will require network activity for mounting on iOS 17
pymobiledevice3 mounter auto-mount
```

Once this is done, you may access a much wider variety of features in the device, such as process management, debugging,
simulate locations and much more.

In order to make it clear which of `pymobiledevice3` commands require the DeveloperMode to be on together with the DDI
being mounted, we put it all in the `developer` subcommand.

For example:

```shell
pymobiledevice3 developer dvt launch com.apple.mobilesafari
```

## DVT

One of the more interesting developer services, is the one exposed by `DTServiceHub`. It is using DTX protocol messages,
but since it mainly wraps and allows access to stuff in `DVTFoundation.framework` we called it DVT in our
implementation (probably standing for DeveloperTools).

We don't delve too much into this protocol, but we'll say in general it allows us to invoke a whitelist of ObjC methods
in different ObjC objects. The terminology used by DVT to each such ObjC object is called "channels".

In order to access this different object use the following APIs:

```python
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot

# Create a LockdownClient instance
lockdown = create_using_usbmux()

# Use it to create a DVT instance
dvt = DvtSecureSocketProxyService(lockdown)
dvt.perform_handshake()

# Use it to invoke methods on a DVT channel
dvt_channel = Screenshot(dvt)
open('/tmp/screen.png', 'wb').write(dvt_channel.get_screenshot())
```

Looking for an unimplemented feature/channel? Feel free to play with it (and submit a PR afterwards 🙏) using the
following shell:

```shell
pymobiledevice3 developer dvt shell
```

## RemoteXPC

Starting at iOS 17.0, Apple made a large refactor in the manner we all interact with the developer services. There can
be multiple reasons for that decision, but in general this refactor main key points are:

- Create a single standard for interacting with the new lockdown services (XPC Messages, Apple's proprietary IPC)
- Optimize the protocol for large file transfers (such as the dyld_shared_cache)
- Perform authentication with the device only once, and connect to each service via an encrypted tunnel from different
  places

However, Apple implemented it in a very confusing way, and seemed to regret some of its own steps along the way, so
we'll cover all the chaotic mess we now can use to connect to the device.

Firstly, we'll just say the protocol messages are layered as follows:

- HTTP/2 messages for more efficient parallel file transfers
- XPC messages (Apple's proprietary IPC)
- Remote Service Discovery protocol (or RSD for short)

However, the connection broker used for this communication is `remoted` instead of `lockdownd`, using its own completely
different pairing logic, leading into two different "Trust/Don't Trust" dialogs (though they appear exactly
the same).

Since all this communication is IP-based, but without any additional exported TCP port from the device, `usbmuxd` can't
help us here. Instead, starting at iOS 16.0, when connecting an iDevice, it exports another none-standard USB-Ethernet
adapter (with IPv6 link-local address), placing us in a subnet with the device's `remoted`.

As we've said this communication is none-standard, and requires either:

- macOS Monterey or higher
- Special driver on your linux/windows machine

> **Spoiler Alert:** Apple may have regretted this, since starting at iOS 17.4, they added the `CodeDeviceProxy` - a new
> lockdown service, allowing us skip all the steps this special driver is required for.

You can use the following shell command in order to query RSD instances over bonjour (over the USB Ethernet device
specifically):

```shell
pymobiledevice3 bonjour rsd
```

We don't delve too much as to what RSD exposes. For that you may read in:

<https://github.com/doronz88/pymobiledevice3/blob/master/misc/RemoteXPC.md>

In short, it will allow us to both pair and start a VPN tunnel onto device, where we can access all the other both
lockdown and other RemoteXPC services. As we previously mentioned, starting at iOS 17.0, this is the only way to access
the developer services.

You'll have to start this tunnel using a privileged process, since it requires creating a TUN/TAP device:

```shell
# This will create a QUIC VPN tunnel to the connected USB device. 
sudo pymobiledevice3 remote start-tunnel

# Apple later switched from QUIC to TCP tunnels, but my SSLPSK seemed to cause troubles to some workstations
# However, using TCP tunnels is much faster especially since the TCP stack is implemented by the OS, instead
# of the QUIC which is implemented in pure python code
# If the following command works for you, it will create MUCH faster tunnels
sudo pymobiledevice3 remote start-tunnel -p tcp
```

If you're using a corellium instance, since you cannot pair it first over USB, they patched the iOS platform to expose
another service over `remoted` to allow remote pairing. So, assuming you are on the same LAN as the device, you may use
the following command:

```shell
sudo pymobiledevice3 remote pair
```

Once we have established pairing with the iDevice's `remoted`, we can now also establish trusted tunnels over Wi-Fi as
follows:

```shell
sudo pymobiledevice3 remote start-tunnel -t wifi
```

This is all nice and all, and as previously mentioned, Apple may have regretted this `remoted` separate pairing, or
maybe thanks to EU ruling because of the special drivers needed for this pairing, but iOS 17.4 added a new lockdown
service, allowing us to just establish this trusted tunnel over our existing lockdown connection - meaning no extra
pairing process is required - and the cherry on top is that it's always TCP tunnels, making it MUCH faster.

To do so, simply use:

```shell
# You may also add a `--usbmux` option for working with a corellium instance
# And of course, since `lockdownd` can be accessed over Wi-Fi, this can also be done remotely
sudo pymobiledevice3 lockdown start-tunnel
```

Anyhow, once the tunnel has been established, you'll get an output that looks like this:

```
Identifier: <DEVICE-UDID>
Interface: utun5
Protocol: TunnelProtocol.QUIC
RSD Address: fdc3:16b1:5cac::1
RSD Port: 52954
Use the follow connection option:
--rsd fdc3:16b1:5cac::1 52954
```

You may simply add this extra `--rsd` option to any existing `pymobiledevice3` subcommand for all its services to be
available once more (including the developer ones) as follows:

```shell
pymobiledevice3 developer dvt launch com.apple.mobilesafari --rsd fdc3:16b1:5cac::1 52954 
```

This is of course also available via a python API:

```python
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.os_trace import OsTraceService

# Assuming 
host = 'fdc3:16b1:5cac::1'
port = 52954
rsd = RemoteServiceDiscoveryService((host, port))
await rsd.connect()

# Both LockdownClient and RemoteServiceDiscoveryService implement LockdownServiceProvider, 
# meaning you can simply use this instance as any other LockdownClient instance
for entry in OsTraceService(rsd).syslog():
    print(entry)
```

Confused by all these "start-tunnel" permutations? Don't blame yourself - it's very confusing especially since there
isn't only one way to achieve cross-platform for iOS 17.0-17.4.

Because of that, and because it requires starting a privileged process to each tunnel, we made this process much simpler
by implementing our own version of `remoted` called `tunneld`. To start it use the following:

```shell
sudo pymobiledevice3 remote tunneld
```

Now `tunneld` will always search for newly connected devices via all available manners of connecting to them (both USB
and Wi-Fi) and just start establishing tunnels to them on its own.

You can then request `pymobiledevice3` to work over the existing tunnel instead by adding the `--tunnel` option as
follows:

```shell
# You'll get a prompt asking to which device you wish to connect to, if there are several active tunnels
pymobiledevice3 developer dvt launch com.apple.mobilesafari --tunnel ''

# Or you can supply a specific UDID to not be prompted
pymobiledevice3 developer dvt launch com.apple.mobilesafari --tunnel '11223344'
```

This is of course also available via a python API:

```python
from pymobiledevice3.tunneld import async_get_tunneld_devices
from pymobiledevice3.services.os_trace import OsTraceService

rsds = await async_get_tunneld_devices()

# We can now simply use the returned list of RSDs as any other LockdownClients
for entry in OsTraceService(rsds[0]).syslog():
    print(entry)
```

## Other python service examples

The best way to search for examples is via
the [`pymobiledevice.cli`](https://github.com/doronz88/pymobiledevice3/tree/refactor/docs/pymobiledevice3/cli) module.

Each submodule represents a CLI subcommand. You can copy each subcommand implementation and simply replace
the `service_provider` variable with any other `LockdownServiceProvider` (either `RemoteServiceDiscoveryService`
or `LockdownClient`).
