[![Python application](https://github.com/doronz88/pymobiledevice3/workflows/Python%20application/badge.svg)](https://github.com/doronz88/pymobiledevice3/actions/workflows/python-app.yml "Python application action")
[![Pypi version](https://img.shields.io/pypi/v/pymobiledevice3.svg)](https://pypi.org/project/pymobiledevice3/ "PyPi package")
[![Downloads](https://static.pepy.tech/personalized-badge/pymobiledevice3?period=total&units=none&left_color=grey&right_color=blue&left_text=Downloads)](https://pepy.tech/project/pymobiledevice3)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/doronz88/pymobiledevice3.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doronz88/pymobiledevice3/context:python)

- [Description](#description)
- [Installation](#installation)
    * [Lower iOS versions (<13)](#lower-ios-versions---13-)
        + [Known issues using OpenSSL](#known-issues-using-openssl)
- [Usage](#usage)
    * [Example](#example)
- [The bits and bytes](#the-bits-and-bytes)
    * [Lockdown services](#lockdown-services)
        + [Implemented services](#implemented-services)
        + [Un-implemented services](#un-implemented-services)
        + [Sending your own messages](#sending-your-own-messages)
            - [Lockdown messages](#lockdown-messages)
            - [Instruments messages](#instruments-messages)
- [Contributing](#contributing)

# Description

`pymobiledevice3` is a pure python3 implementation for working with iDevices (iPhone, etc...). This means this tool is both
architecture and platform generic and is supported and tested on:

* Windows
* Linux
* macOS

Main features include:

* TCP port forwarding
* Viewing syslog lines (including debug)
* Profile management
* Application management
* File system management (AFC)
* Crash reports management
* Network sniffing
* Firmware update
* Mounting images
* Notification listening and triggering (`notify_post()` api)
* Querying and setting SpringBoard options
* Automating WebInspector features
* DeveloperDiskImage features:
    * Taking screenshots
    * Simulate locations
    * Process management
    * Sniffing KDebug messages (**strace** capabilities++)
    * Process monitoring (`top` like)
    * Accessibility features
* Backup

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

If you wish to use pymobiledevice3 with iOS versions lower than 13, Make sure to install `openssl`:

On MAC:

```shell
brew install openssl
```

On Linux:

```shell
sudo apt install openssl
```

### Known issues using OpenSSL

Please refer to the following closed issue if you are receiving errors from the OpenSSL library:

https://github.com/doronz88/pymobiledevice3/issues/171

# Usage

The CLI subcommands are divided roughly by the protocol layer used for interacting in the device. For example, all features
derived from the DeveloperDiskImage will be accessible from the `developer`
subcommand. This also means that every feature which isn't there won't require it.

This is the main CLI usage:

```
Usage: pymobiledevice3 [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  activation       activation options
  afc              FileSystem utils
  apps             application options
  backup2          backup utils
  companion        companion options
  crash            crash report options
  developer        developer options.
  diagnostics      diagnostics options
  list-devices     list connected devices
  lockdown         lockdown options
  mounter          mounter options
  notification     notification options
  pcap             sniff device traffic
  power-assertion  Create a power assertion (wraps...
  processes        processes cli
  profile          profile options
  provision        privision options
  restore          restore options
  springboard      springboard options
  syslog           syslog options
  webinspector     webinspector options
```

Or import the modules and use the API yourself:

```python
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.syslog import SyslogService

lockdown = LockdownClient()
for line in SyslogService(lockdown=lockdown).watch():
    # just print all syslog lines as is
    print(line)
```

## Example

A recorded example for using a variety of features can be viewed at:
https://terminalizer.com/view/18920b405193

There is A LOT you may do on the device using `pymobiledevice3`. This is just a TL;DR of some common operations:

* Listing connected devices:
    * `pymobiledevice3 list-devices`
* View all syslog lines (including debug messages):
    * `pymobiledevice3 syslog live`
* Filter out only messages containing the word "SpringBoard":
    * `pymobiledevice3 syslog live -m SpringBoard`
* Restart device:
    * `pymobiledevice3 diagnostics restart`
* Pull all crash reports from device:
    * `pymobiledevice3 crash pull /path/to/crashes`
* Manage the media directory:
    * `pymobiledevice3 afc shell`
* List all installed applications and their details:
    * `pymobiledevice3 apps list --user --system`
* Create a TCP tunnel from your HOST to the device:
    * `pymobiledevice3 lockdown forward HOST_PORT DEVICE_PORT`
* Create a full backup of the device:
    * `pymobiledevice3 backup2 backup --full DIRECTORY`
* Restore a given backup:
    * `pymobiledevice3 backup2 restore DIRECTORY`
* The following will require the Remote Automation & Web Inspector features to be turned on:
    * List currently opened tabs is device's browser:
        * `pymobiledevice3 webinspector opened-tabs`
    * Launch an automation session to view a given URL:
        * `pymobiledevice3 webinspector launch URL`
    * Get a a selenium-like shell:
        * `pymobiledevice3 webinspector shell`
* Mount DeveloperDiskImage:
    * `pymobiledevice3 mounter mount`
    * The following will assume the DeveloperDiskImage is already mounted:
        * Simulate an `x y` location:
            * `pymobiledevice3 developer simulate-location set x y`
        * Taking a screenshot from the device:
            * `pymobiledevice3 developer screenshot /path/to/screen.png`
        * View detailed process list (including ppid, uid, guid, sandboxed, etc...):
            * `pymobiledevice3 developer dvt sysmon process single`
        * Kill a process:
            * `pymobiledevice3 developer dvt kill PID`
        * List files in a given directory (un-chrooted):
            * `pymobiledevice3 developer dvt ls PATH`
        * Launch an app by its bundle name:
            * `pymobiledevice3 developer dvt launch com.apple.mobilesafari`
        * Sniff all KDebug events to get an `strace`-like output:
            * `pymobiledevice3 developer dvt core-profile-session parse-live`
        * Sniff all KDebug events into a file for parsing later with tools such
          as [`pykdebugparser`](https://github.com/matan1008/pykdebugparser), `fs_usage` and so on...
            * `pymobiledevice3 developer dvt core-profile-session save FILENAME`
        * Get device extended information (kernel name, chipset, etc...):
            * `pymobiledevice3 developer dvt device-information`
        * Monitor energy-consumption for a specific PID:
            * `pymobiledevice3 developer dvt energy PID1 PID2 ...`

# The bits and bytes

To understand the bits and bytes of the communication with lockdownd you are advised to take a look at this article:

https://jon-gabilondo-angulo-7635.medium.com/understanding-usbmux-and-the-ios-lockdown-service-7f2a1dfd07ae

## Lockdown services

### Implemented services

This is the list of all the services from `lockdownd` which we reversed and implemented API wrappers for. A click on each will
lead to each one's implementation, where you can learn more about.

* [`com.apple.mobile.heartbeat`](pymobiledevice3/services/heartbeat.py)
    * Just a ping to `lockdownd` service.
    * Used to keep an active connection with `lockdownd`
* [`com.apple.mobileactivationd`](pymobiledevice3/services/mobile_activation.py)
    * Activation services
* [`com.apple.afc`](pymobiledevice3/services/afc.py)
    * File access for `/var/mobile/Media`
    * Based on afcd's protocol
* [`com.apple.crashreportcopymobile`](pymobiledevice3/services/crash_reports.py)
    * File access for `/var/mobile/Library/Logs/CrashReports`
    * Based on afcd's protocol
* [`com.apple.pcapd`](pymobiledevice3/services/pcapd.py)
    * Sniff device's network traffic
* [`com.apple.syslog_relay`](pymobiledevice3/services/syslog.py)
    * Just streams syslog lines as raw strings
    * For a more robust structural parsing, it's better to access the `com.apple.os_trace_relay` relay.
* [`com.apple.os_trace_relay`](pymobiledevice3/services/os_trace.py)
    * More extensive syslog monitoring
* [`com.apple.mobile.diagnostics_relay`](pymobiledevice3/services/diagnostics.py)
    * General diagnostic tools
* [`com.apple.mobile.notification_proxy` & `com.apple.mobile.insecure_notification_proxy`](pymobiledevice3/services/notification_proxy.py)
    * API wrapper for `notify_post()` & `notify_register_dispatch()`
* [`com.apple.crashreportmover`](pymobiledevice3/services/crash_reports.py)
    * Just trigger `crash_mover` to move all crash reports into crash directory
* [`com.apple.mobile.MCInstall`](pymobiledevice3/services/mobile_config.py)
    * Profile management (MDM)
* [`com.apple.misagent`](pymobiledevice3/services/misagent.py)
    * Provisioning Profiles management
* [`com.apple.companion_proxy`](pymobiledevice3/services/companion.py)
    * Companion features (watches and etc.)
* [`com.apple.mobilebackup2`](pymobiledevice3/services/mobilebackup2.py)
    * Local backup management
* [`com.apple.mobile.assertion_agent`](pymobiledevice3/services/power_assertion.py)
    * Create power assertion to prevent different kinds of sleep
* [`com.apple.springboardservices`](pymobiledevice3/services/springboard.py)
    * Play with device's button layout
* [`com.apple.mobile.mobile_image_mounter`](pymobiledevice3/services/mobile_image_mounter.py)
    * Image mounter service (used for DeveloperDiskImage mounting)
* [`com.apple.mobile.house_arrest`](pymobiledevice3/services/house_arrest.py)
    * Get AFC utils (file management per application bundle)
* [`com.apple.mobile.installation_proxy`](pymobiledevice3/services/installation_proxy.py)
    * Application management
* [`com.apple.instruments.remoteserver`](pymobiledevice3/services/remote_server.py)
    * Developer instrumentation service, iOS<14  (DeveloperDiskImage)
* [`com.apple.instruments.remoteserver.DVTSecureSocketProxy`](pymobiledevice3/services/remote_server.py)
    * Developer instrumentation service, iOS>=14  (DeveloperDiskImage)
* [`com.apple.mobile.screenshotr`](pymobiledevice3/services/screenshot.py)
    * Take screenshot into a PNG format (DeveloperDiskImage)
* [`com.apple.accessibility.axAuditDaemon.remoteserver`](pymobiledevice3/services/accessibilityaudit.py)
    * Accessibility features (DeveloperDiskImage)
* [`com.apple.dt.simulatelocation`](pymobiledevice3/services/simulate_location.py)
    * Allows to simulate locations (DeveloperDiskImage)
* [`com.apple.dt.fetchsymbols`](pymobiledevice3/services/dtfetchsymbols.py)
    * Allows fetching of `dyld` and dyld shared cache files (DeveloperDiskImage)
* [`com.apple.webinspector`](pymobiledevice3/services/webinspector.py)
    * Used to debug WebViews

### Un-implemented services

This is the list of services we haven't dedicated time in implementing. If you feel the need to use one of them or any other
that is not listed in here, feel free
to [create us an issue request](https://github.com/doronz88/pymobiledevice3/issues/new?assignees=&labels=&template=feature_request.md&title=)
.

* `com.apple.idamd`
    * Allows settings the IDAM configuration (whatever that means...)
* `com.apple.atc`
    * AirTraffic related
* `com.apple.ait.aitd`
    * AirTraffic related
* `com.apple.mobile.file_relay`
    * On older iOS versions (iOS <= 8), this was the main relay used for file operations, which was later replaced with AFC.
* `com.apple.mobilesync`
* `com.apple.purpletestr`

### Sending your own messages

#### Lockdown messages

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
client.sendall(b"hello")

# and view the result
print(client.recvall(20))
```

#### Instruments messages

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
