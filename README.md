[![Python application](https://github.com/doronz88/pymobiledevice3/workflows/Python%20application/badge.svg)](https://github.com/doronz88/pymobiledevice3/actions/workflows/python-app.yml "Python application action")
[![Pypi version](https://img.shields.io/pypi/v/pymobiledevice3.svg)](https://pypi.org/project/pymobiledevice3/ "PyPi package")
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/doronz88/pymobiledevice3.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doronz88/pymobiledevice3/context:python)

- [Description](#description)
- [Installation](#installation)
    * [Lower iOS versions (<13)](#lower-ios-versions-13)
- [Usage](#usage)
    * [Example](#example)
- [The bits and bytes](#the-bits-and-bytes)
    * [Sending your own messages](#sending-your-own-messages)
        + [Lockdown messages](#lockdown-messages)
        + [Instruments messages](#instruments-messages)
    * [Lockdown services](#lockdown-services)
        + [com.apple.instruments.remoteserver.DVTSecureSocketProxy](#comappleinstrumentsremoteserverdvtsecuresocketproxy)
        + [com.apple.os_trace_relay](#comappleos_trace_relay)
        + [com.apple.mobile.diagnostics_relay](#comapplemobilediagnostics_relay)
        + [com.apple.mobile.file_relay](#comapplemobilefile_relay)
        + [com.apple.pcapd](#comapplepcapd)
- [Contributing](#contributing)

# Description

`pymobiledevice3` started as a fork of `pymobiledevice`, but became something much more. This tool offers a full python
implementation to work with iDevices (iPhone, etc...).

Main features include:

* TCP port forwarding
* Viewing syslog lines (including debug)
* Profile management
* Application management
* File system management (AFC)
* Crash reports management
* Network sniffing
* Mounting images
* Notification listening and triggering (`notify_post()` api)
* Querying and setting SpringBoard options
* DeveloperDiskImage features:
    * Taking screenshots
    * Simulate locations
    * Process management
    * Sniffing KDebug messages (**strace** capabilities++)
    * Process monitoring (`top` like)
    * Accessibility features

# Installation

Install the last released version using `pip`:

```shell
python3 -m pip install --user -U pymobiledevice3
```

Or install the latest version from sources:

```shell
git clone git@github.com:doronz88/pymobiledevice3.git
cd pymobiledevice3
python3 -m pip install --user -U -e .
```

You can also install auto-completion for all available sub-commands by adding the following into your `~/.zshrc`:

```shell
# python-click<8.0
eval "$(_PYMOBILEDEVICE3_COMPLETE=source_zsh pymobiledevice3)"
# python-click>=8.0
eval "$(_PYMOBILEDEVICE3_COMPLETE=zsh_source pymobiledevice3)"
```

## Lower iOS versions (<13)

If you wish to use pymobiledevice3 with iOS versions lower than 13, Make sure to install `M2Crypto`
(requires `swig` and `openssl`):

On MAC:

```shell
brew install swig openssl

LDFLAGS="-L$(brew --prefix openssl)/lib" \
CFLAGS="-I$(brew --prefix openssl)/include" \
SWIG_FEATURES="-cpperraswarn -includeall -I$(brew --prefix openssl)/include" \
python3 -m pip install --user -U m2crypto
```

On Linux:

```shell
sudo apt install swig openssl
```

# Usage

You can either use the CLI:

```
Usage: pymobiledevice3 [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  afc              FileSystem utils
  apps             application options
  crash            crash report options
  developer        developer options.
  diagnostics      diagnostics options
  list-devices     list connected devices
  lockdown         lockdown options
  mounter          mounter options
  notification     API for notify_post() & notify_register_dispatch().
  pcap             sniff device traffic
  power-assertion  Create a power assertion (wraps...
  processes        processes cli
  profile          profile options
  springboard      springboard options
  syslog           syslog options
```

Or import and use the API yourself:

```python
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.syslog import SyslogService

lockdown = LockdownClient()
for line in SyslogService(lockdown=lockdown).watch():
    # just print all syslog lines as is
    print(line)
```

## Example

![](https://github.com/doronz88/pymobiledevice3/blob/master/example.gif?raw=true)

# Lockdown services

Support | Service | Description
--------|---------|----------------------
DONE |  `com.apple.afc` | File access for `/var/mobile/Media`
DONE | `com.apple.crashreportcopymobile` | File access for `/var/mobile/Library/Logs/CrashReports`
DONE | `com.apple.pcapd` | Sniff device's network traffic
DONE | `com.apple.syslog_relay` | Just streams syslog lines as raw strings
DONE | `com.apple.os_trace_relay` | More extensive syslog monitoring
DONE | `com.apple.mobile.diagnostics_relay` | General diagnostic tools
DONE | `com.apple.mobile.notification_proxy` | API wrapper for `notify_post()` & `notify_register_dispatch()`
DONE | `com.apple.crashreportmover` | Just trigger `crash_mover` to move all crash reports into crash directory
DONE | `com.apple.mobile.MCInstall` | Profile management
DONE | `com.apple.mobile.assertion_agent` | Create power assertion to prevent different kinds of sleep
DONE | `com.apple.springboardservices` | Icon related
DONE | `com.apple.mobile.mobile_image_mounter` | Image mounter service (used for DeveloperDiskImage mounting)
DONE | `com.apple.mobile.house_arrest` | Get AFC utils (file management per application bundle)
DONE | `com.apple.mobile.installation_proxy`|  Application management
DONE | `com.apple.instruments.remoteserver` | Developer instrumentation service, iOS<14  (DeveloperDiskImage)
DONE | `com.apple.instruments.remoteserver.DVTSecureSocketProxy` | Developer instrumentation service, iOS>=14  (DeveloperDiskImage)
DONE | `com.apple.mobile.screenshotr` | Take screenshot into a PNG format (DeveloperDiskImage)
DONE | `com.apple.accessibility.axAuditDaemon.remoteserver` | Accessibility features (DeveloperDiskImage)
DONE | `com.apple.dt.simulatelocation` | Allows to simulate locations (DeveloperDiskImage)
DONE | `com.apple.dt.fetchsymbols` | Allows fetching of `dyld` and dyld shared cache files (DeveloperDiskImage)
Not yet | `com.apple.idamd` | Allows settings the IDAM configuration (whatever that means...)
Not yet | `com.apple.atc` | AirTraffic related
Not yet | `com.apple.ait.aitd` | AirTraffic related
Not yet | `com.apple.misagent` | Profile related
Not yet | `com.apple.mobile.file_relay` | File access for iOS <= 8
Not yet | `com.apple.mobile.heartbeat` | Just a ping to `lockdownd` service
Not yet | `com.apple.mobile.insecure_notification_proxy` | API wrapper for `notify_post()` & `notify_register_dispatch()` from whitelist
Not yet | `com.apple.mobilebackup` |
Not yet | `com.apple.mobilebackup2` |
Not yet | `com.apple.mobilesync` |
Not yet | `com.apple.purpletestr` |
Not yet | `com.apple.webinspector` | Used to debug WebViews

## `com.apple.instruments.remoteserver.DVTSecureSocketProxy`

Exports several ObjC objects and allows calling their respective selectors.
The `/Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub` service reads the
configuration stored from `[[NSUserDefaults standardUserDefaults] boolForKey:@"DTXConnectionTracer"]`
If the value is true, then `/tmp/DTServiceHub[PID].DTXConnection.RANDOM.log` is created and can be used to debug the
transport protocol.

For example:

```
root@iPhone (/var/root)# tail -f /tmp/DTServiceHub[369].DTXConnection.qNjM2U.log
170.887982 x4 resuming [c0]: <DTXConnection 0x100d20670 : x4>
170.889120 x4   sent   [c0]: < DTXMessage 0x100d52b10 : i2.0 c0 dispatch:[_notifyOfPublishedCapabilities:<NSDictionary 0x100d0e1b0 | 92 key/value pairs>] >
170.889547 x4 received [c0]: < DTXMessage 0x100d0a550 : i1.0 c0 dispatch:[_notifyOfPublishedCapabilities:<NSDictionary 0x100d16a40 | 2 key/value pairs>] >
170.892101 x4 received [c0]: < DTXMessage 0x100d0a550 : i3.0e c0 dispatch:[_requestChannelWithCode:[1]identifier :"com.apple.instruments.server.services.deviceinfo"] >
170.892238 x4   sent   [c0]: < DTXMessage 0x100d61830 : i3.1 c0 >
170.892973 x4 received [c1f]: < DTXMessage 0x100d0a550 : i4.0e c1 dispatch:[runningProcesses] >
171.204957 x4   sent   [c1f]: < DTXMessage 0x100c557a0 : i4.1 c1 object:(__NSArrayM*)<NSArray 0x100c199d0 | 245 objects> { <NSDictionary 0x100c167c0 | 5 key/value pairs>, <NSDictionary 0x100d17970 | 5 key/value pairs>, <NSDictionary 0x100d17f40 | 5 key/value pairs>, <NSDictionary 0x100d61750 | 5 key/value pairs>, <NSDictionary 0x100c16760 | 5 key/value pairs>, ...  } >
171.213326 x4 received [c0]: < DTXMessage : kDTXInterruptionMessage >
171.213424 x4  handler [c0]: < DTXMessage : i1 kDTXInterruptionMessage >
171.213477 x4 received [c1f]: < DTXMessage : kDTXInterruptionMessage >
```

For editing the configuration we can simply add the respected key into:
`/var/mobile/Library/Preferences/.GlobalPreferences.plist` and kill `cfprefsd`

The valid selectors for triggering can be found using the following Frida script the same way Troy Bowman used for
iterating all classes which implement the protocol `DTXAllowedRPC`:

```shell
frida -U DTServiceHub
```

```javascript
for (var name in ObjC.protocols) {
    var protocol = ObjC.protocols[name]
    if ('DTXAllowedRPC' in protocol.protocols) {
        console.log('@protocol', name)
        console.log('  ' + Object.keys(protocol.methods).join('\n  '))
    }
}
```

The complete list for the relevant APIs can be found here:

* [14.2](./DTServices-14.2.txt)
* [14.5](./DTServices-14.5.txt)

## `com.apple.os_trace_relay`

Provides API for the following operations:

* Show process list (process name and pid)
* Stream syslog lines in binary form with optional filtering by pid.
* Get old stored syslog archive in PAX format (can be extracted using `pax -r < filename`).
    * Archive contain the contents are the `/var/db/diagnostics` directory

## `com.apple.mobile.diagnostics_relay`

Provides an API to:

* Query MobileGestalt & IORegistry keys.
* Reboot, shutdown or put the device in sleep mode.

## `com.apple.mobile.file_relay`

On older iOS versions, this was the main relay used for file operations, which was later replaced with AFC.

## `com.apple.pcapd`

Starting iOS 5, apple added a remote virtual interface (RVI) facility that allows mirroring networks trafic from an iOS
device. On Mac OSX the virtual interface can be enabled with the rvictl command. This script allows to use this service
on other systems.

# The bits and bytes

To understand the bits and bytes of the communication with lockdownd you are advised to take a look at this article:

https://jon-gabilondo-angulo-7635.medium.com/understanding-usbmux-and-the-ios-lockdown-service-7f2a1dfd07ae

## Sending your own messages

### Lockdown messages

Every such subcommand may wrap several relay requests underneath. If you wish to try and play with some the relays
yourself, you can run:

```shell
pymobiledevice3 lockdown service <service-name>
```

This will start an IPython shell where you already have the connection established using the `client` variable and you
can send & receive messages.

```python
# This shell allows you to communicate directly with every service layer behind the lockdownd daemon.

# For example, you can do the following:
client.send_plist({"Command": "DoSomething"})

# and view the reply
print(client.recv_plist())

# or just send raw message
client.sendall(b"hello")

# and view the result
print(client.recvall(20))
```

### Instruments messages

If you want to play with `DTServiceHub` which lies behind the `developer` options, you can also use:

```shell
pymobiledevice3 developer shell
```

To also get an IPython shell, which lets you call ObjC methods from the exported objects in the instruments' namespace
like so:

```python
# This shell allows you to send messages to the DVTSecureSocketProxy and receive answers easily.
# Generally speaking, each channel represents a group of actions.
# Calling actions is done using a selector and auxiliary (parameters).
# Receiving answers is done by getting a return value and seldom auxiliary (private / extra parameters).
# To see the available channels, type the following:
developer.supported_identifiers

# In order to send messages, you need to create a channel:
channel = developer.make_channel('com.apple.instruments.server.services.deviceinfo')

# After creating the channel you can call allowed selectors:
channel.runningProcesses()

# If an answer is expected, you can receive it using the receive method:
processes = channel.receive_plist()

# Sometimes the selector requires parameters, You can add them using MessageAux. For example lets kill a process:
channel = developer.make_channel('com.apple.instruments.server.services.processcontrol')
args = MessageAux().append_obj(80)  # This will kill pid 80
channel.killPid_(args, expects_reply=False)  # Killing a process doesn't require an answer.

# In some rare cases, you might want to receive the auxiliary and the selector return value.
# For that cases you can use the recv_plist method.
return_value, auxiliary = developer.recv_plist()
```

# Contributing

See [CONTRIBUTING](CONTRIBUTING.md).
