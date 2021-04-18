# Description

`pymobiledevice3` is a fork from `pymobiledevice`, which is a cross-platform implementation of the mobiledevice library that
talks the protocols to support iPhone®, iPod Touch®, iPad® and Apple TV® devices.

This version uses more recent coding standards and adds a lot more features. Also, many of the features not present
in `libimobiledevice` can be found here.

To understand the bits and bytes of the communication with `lockdownd` you are advised to take a look at this article:

https://jon-gabilondo-angulo-7635.medium.com/understanding-usbmux-and-the-ios-lockdown-service-7f2a1dfd07ae

# Features

* TCP portwarding 
  * `pymobiledevice3 lockdown forward src_port dst_port`)
* Screenshots
  * `pymobiledevice3 screenshot screen.png`
* Live and past syslogs
  * `pymobiledevice3 syslog live`
  * `pymobiledevice3 syslog archive syslogs.pax`
* Profile installation
  * `pymobiledevice3 profile install/remove/list`
* Application management
  * `pymobiledevice3 apps`
* File system management (AFC)
  * `pymobiledevice3 afc`
* Crash reports management
  * `pymobiledevice3 crash`
* Network sniffing
  * `pymobiledevice3 pcap [out.pcap]`
* Raw shell for experimenting:
    * `pymobiledevice3 lockdown service service_name`
* Mounting images
  * `pymobiledevice3 mounter`
* Notification listening and triggering (`notify_post()` api)
  * `pymobiledevice3 notification post notification_name`
  * `pymobiledevice3 notification observe notification_name`
* DeveloperDiskImage features:
  * Process management
    * `pymobiledevice3 developer kill/launch/....`
  * **Non-chrooted** directory listing
    * `pymobiledevice3 developer ls /`
  * Raw shell for experimenting:
    * `pymobiledevice3 developer shell`

* And some more 😁

# Installation

```shell
git clone git@github.com:doronz88/pymobiledevice3.git
cd pymobiledevice3
python3 -m pip install --user -U -e .
```

# Usage

You can either use the CLI:

```
Usage: pymobiledevice3 [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  afc           FileSystem utils
  apps          application options
  crash         crash utils
  developer     developer options
  diagnostics   diagnostics options
  lockdown      lockdown options
  mounter       mounter options
  notification  API for notify_post() & notify_register_dispatch().
  pcap          sniff device traffic
  profile       profile options
  ps            show process list
  screenshot    take a screenshot in PNG format
  syslog        syslog options
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

## Sending your own messages

### Lockdown messages

Every such subcommand may wrap several relay requests underneath. If you wish to try and play with some the relays yourself,
you can run:

```shell
pymobiledevice3 lockdown service <service-name>
```

This will start an IPython shell where you already have the connection established using the `client` variable and you can send
& receive messages.

```python
# This shell allows you to communicate directly with every service layer behind the lockdownd daemon.

# For example, you can do the following:
client.send_plist({"Command": "DoSomething"})

# and view the reply
print(client.recv_plist())

# or just send raw message
client.send(b"hello")

# and view the result
print(client.recv_exact(20))
```

### Instruments messages

If you want to play with `DTServiceHub` which lies behind the `developer` options, you can also use:

```shell
pymobiledevice3 developer shell
```

To also get an IPython shell, which lets you call ObjC methods from the exported objects in the instruments' namespace like so:

```python
# This shell allows you to send messages to the DVTSecureSocketProxy and receive answers easily.
# Generally speaking, each channel represents a group of actions.
# Calling actions is done using a selector and auxiliary (parameters).
# Receiving answers is done by getting a return value and seldom auxiliary (private / extra parameters).
# To see the available channels, type the following:
developer.channels

# In order to send messages, you need to create a channel:
channel = developer.make_channel('com.apple.instruments.server.services.deviceinfo')

# After creating the channel you can call allowed selectors:
channel.runningProcesses()

# If an answer is expected, you can receive it using the receive method:
processes = channel.receive()

# Sometimes the selector requires parameters, You can add them using MessageAux. For example lets kill a process:
channel = developer.make_channel('com.apple.instruments.server.services.processcontrol')
args = MessageAux().append_obj(80)  # This will kill pid 80
channel.killPid_(args, expects_reply=False)  # Killing a process doesn't require an answer.

# In some rare cases, you might want to receive the auxiliary and the selector return value.
# For that cases you can use the recv_message method.
return_value, auxiliary = developer.recv_message()
```

## Example

![](example.gif)

# Lockdown services

Support | Service | Process | Description
--------|---------|---------|----------------------
DONE |  `com.apple.afc` | `/usr/libexec/afcd --xpc -d /private/var/mobile/Media` | File access for `/var/mobile/Media`
DONE | `com.apple.crashreportcopymobile` | `/usr/libexec/afcd --xpc--service-name com.apple.crashreportcopymobile -d /private/var/mobile/Library/Logs/CrashReporter` | File access for `/var/mobile/Library/Logs/CrashReports`
DONE | `com.apple.pcapd` | `/usr/libexec/pcapd` | Sniff device's network traffic
DONE | `com.apple.syslog_relay` | `/usr/libexec/diagnosticd` | Just streams syslog lines as raw strings
DONE | `com.apple.os_trace_relay` | `/usr/libexec/diagnosticd` | More extensive syslog monitoring
DONE | `com.apple.mobile.diagnostics_relay` | `com.apple.mobile.diagnostics_relay` | General diagnostic tools
DONE | `com.apple.mobile.notification_proxy` | `/usr/libexec/notification_proxy` | API wrapper for `notify_post()` & `notify_register_dispatch()`
DONE | `com.apple.crashreportmover` | `/usr/libexec/crash_mover` | Just trigger `crash_mover` to move all crash reports into crash directory
DONE | `com.apple.mobile.MCInstall` | `/usr/libexec/mc_mobile_tunnel` | Profile management
DONE | `com.apple.mobile.screenshotr` | `/Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/XPCServices/com.apple.dt.DTScreenshotService.xpc/com.apple.dt.DTScreenshotService` | Take screenshot into a PNG format
DONE | `com.apple.instruments.remoteserver.DVTSecureSocketProxy` | `/Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub` | Developer instrumentation service
DONE | `com.apple.mobile.mobile_image_mounter` | `/usr/libexec/mobile_storage_proxy`
DONE | `com.apple.mobile.house_arrest` | `/usr/libexec/mobile_house_arrest` | Get AFC utils (file management per application bundle)
DONE | `com.apple.mobile.installation_proxy` | `/usr/libexec/mobile_installation_proxy` | Application managementNot yet | `com.apple.idamd` | `/usr/libexec/idamd` | Allows settings the IDAM configuration (whatever that means...) 
Not yet | `com.apple.atc` | `/usr/libexec/atc` | AirTraffic related
Not yet | `com.apple.mobile.assertion_agent` | `/usr/libexec/mobile_assertion_agent` | Create power assertion to prevent different kinds of sleep
Not yet | `com.apple.ait.aitd` | `/usr/libexec/atc` | AirTraffic related
Not yet | `com.apple.misagent` | `/usr/libexec/misagent` | Profile related
Not yet | `com.apple.mobile.file_relay` | `/usr/libexec/mobile_file_relay` | File access for iOS <= 8
Not yet | `com.apple.mobile.heartbeat` | `/usr/libexec/lockdownd`
Not yet | `com.apple.mobile.insecure_notification_proxy` | `/usr/libexec/notification_proxy -i` | API wrapper for `notify_post()` & `notify_register_dispatch()` from whitelist
Not yet | `com.apple.mobilebackup` | `/usr/libexec/BackupAgent --lockdown`
Not yet | `com.apple.mobilebackup2` | `/usr/libexec/BackupAgent2 --lockdown`
Not yet | `com.apple.mobilesync` | `/usr/libexec/SyncAgent --lockdown --oneshot -v`
Not yet | `com.apple.purpletestr` | `/usr/libexec/PurpleTestr --lockdown --oneshot`
Not yet | `com.apple.radios.wirelesstester.mobile` | `/usr/local/bin/WirelessTester -l 1 -o /var/mobile/WirelessTester_mobile.log`
Not yet | `com.apple.radios.wirelesstester.root` | `/usr/local/bin/WirelessTester -l 1 -o /var/mobile/WirelessTester_mobile.log`
Not yet | `com.apple.springboardservices` | `/usr/libexec/springboardservicesrelay`
Not yet | `com.apple.thermalmonitor.thermtgraphrelay` | `/usr/libexec/thermtgraphrelay`
Not yet | `com.apple.webinspector` | `/usr/libexec/webinspectord`
BUG | `com.apple.iosdiagnostics.relay` | `/usr/libexec/ios_diagnostics_relay` | Failed to connect to it from some reason

## `com.apple.instruments.remoteserver.DVTSecureSocketProxy`

Exports several ObjC objects and allows calling their respective selectors.
The `/Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub` service reads the configuration
stored from `[[NSUserDefaults standardUserDefaults] boolForKey:@"DTXConnectionTracer"]`
If the value is true, then `/tmp/DTServiceHub[PID].DTXConnection.RANDOM.log` is created and can be used to debug the transport
protocol.

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

The valid selectors for triggering can be found using the following Frida script the same way Roy Bowman used for iterating all
classes which implement the protocol `DTXAllowedRPC`:

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

The complete list for the following XCode versions can be found in:

* [12.4](./DTServices-12.4.txt)

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

Starting iOS 5, apple added a remote virtual interface (RVI) facility that allows mirroring networks trafic from an iOS device.
On Mac OSX the virtual interface can be enabled with the rvictl command. This script allows to use this service on other
systems.
