# Description

`pymobiledevice3` is a pure python3 implementation for working with iDevices (iPhone, etc...). This means this tool is
both architecture and platform generic and is supported and tested on:

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
* Network sniffing (PCAP)
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
    * Sniffing oslog which includes both syslog and signposts
* Backup

# Installation

Install the last released version using `pip`:

```shell
python3 -m pip install -U pymobiledevice3
```

Or install the latest version from sources:

```shell
git clone git@github.com:doronz88/pymobiledevice3.git
cd pymobiledevice3
python3 -m pip install -U -e .
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

# Usage

The CLI subcommands are divided roughly by the protocol layer used for interacting in the device. For example, all
features derived from the DeveloperDiskImage will be accessible from the `developer`
subcommand. This also means that every feature which isn't there won't require it.

This is the main CLI usage:

```
Usage: python -m pymobiledevice3 [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  activation       activation options
  afc              FileSystem utils
  amfi             amfi options
  apps             application options
  backup2          backup utils
  companion        companion options
  crash            crash report options
  developer        developer options.
  diagnostics      diagnostics options
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
  usbmuxd          usbmuxd options
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
    * `pymobiledevice3 usbmux forward HOST_PORT DEVICE_PORT`
* Create a full backup of the device:
    * `pymobiledevice3 backup2 backup --full DIRECTORY`
* Restore a given backup:
    * `pymobiledevice3 backup2 restore DIRECTORY`
* The following will require Web Inspector feature to be turned on:
    * Get interactive JavaScript shell on any open tab:
        * `pymobiledevice3 webinspector js_shell`
    * List currently opened tabs is device's browser:
        * `pymobiledevice3 webinspector opened-tabs`
    * The following will require also the Remote Automation feature to be turned on:
        * Get interactive JavaScript shell on new remote automation tab:
            * `pymobiledevice3 webinspector js_shell --automation`
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
        * Sniffing oslog:
            * `pymobiledevice3 developer dvt oslog`
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

This is the list of all the services from `lockdownd` which we reversed and implemented API wrappers for. A click on
each will lead to each one's implementation, where you can learn more about.

* [`com.apple.mobile.heartbeat`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.heartbeat.html)
    * Just a ping to `lockdownd` service.
    * Used to keep an active connection with `lockdownd`
* [`com.apple.mobileactivationd`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.mobile_activation.html)
    * Activation services
* [`com.apple.afc`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.afc.html)
    * File access for `/var/mobile/Media`
    * Based on afcd's protocol
* [`com.apple.crashreportcopymobile`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.crash_reports.html)
    * File access for `/var/mobile/Library/Logs/CrashReports`
    * Based on afcd's protocol
* [`com.apple.pcapd`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.pcapd.html)
    * Sniff device's network traffic
* [`com.apple.syslog_relay`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.syslog.html)
    * Just streams syslog lines as raw strings
    * For a more robust structural parsing, it's better to access the `com.apple.os_trace_relay` relay.
* [`com.apple.os_trace_relay`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.os_trace.html)
    * More extensive syslog monitoring
* [`com.apple.mobile.diagnostics_relay`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.diagnostics.html)
    * General diagnostic tools
* [`com.apple.mobile.notification_proxy` & `com.apple.mobile.insecure_notification_proxy`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.notification_proxy.html)
    * API wrapper for `notify_post()` & `notify_register_dispatch()`
* [`com.apple.crashreportmover`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.crash_reports.html)
    * Just trigger `crash_mover` to move all crash reports into crash directory
* [`com.apple.mobile.MCInstall`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.mobile_config.html)
    * Profile management (MDM)
* [`com.apple.misagent`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.misagent.html)
    * Provisioning Profiles management
* [`com.apple.companion_proxy`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.companion.html)
    * Companion features (watches and etc.)
* [`com.apple.mobilebackup2`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.mobilebackup2.html)
    * Local backup management
* [`com.apple.mobile.assertion_agent`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.power_assertion.html)
    * Create power assertion to prevent different kinds of sleep
* [`com.apple.springboardservices`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.springboard.html)
    * Play with device's button layout
* [`com.apple.mobile.mobile_image_mounter`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.mobile_image_mounter.html)
    * Image mounter service (used for DeveloperDiskImage mounting)
* [`com.apple.mobile.house_arrest`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.house_arrest.html)
    * Get AFC utils (file management per application bundle)
* [`com.apple.mobile.installation_proxy`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.installation_proxy.html)
    * Application management
* [`com.apple.instruments.remoteserver`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.remote_server.html)
    * Developer instrumentation service, iOS<14  (DeveloperDiskImage)
* [`com.apple.instruments.remoteserver.DVTSecureSocketProxy`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.remote_server.html)
    * Developer instrumentation service, iOS>=14  (DeveloperDiskImage)
* [`com.apple.mobile.screenshotr`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.screenshot.html)
    * Take screenshot into a PNG format (DeveloperDiskImage)
* [`com.apple.accessibility.axAuditDaemon.remoteserver`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.accessibilityaudit.html)
    * Accessibility features (DeveloperDiskImage)
* [`com.apple.dt.simulatelocation`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.simulate_location.html)
    * Allows to simulate locations (DeveloperDiskImage)
* [`com.apple.dt.fetchsymbols`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.dtfetchsymbols.html)
    * Allows fetching of `dyld` and dyld shared cache files (DeveloperDiskImage)
* [`com.apple.webinspector`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.webinspector.html)
    * Used to debug WebViews
* [`com.apple.amfi.lockdown`](https://pymobiledevice3.readthedocs.io/en/latest/api_reference/pymobiledevice3.services.amfi.html)
    * Used to enable developer-mode

### Un-implemented services

This is the list of services we haven't dedicated time in implementing. If you feel the need to use one of them or any
other that is not listed in here, feel free
to [create us an issue request](https://github.com/doronz88/pymobiledevice3/issues/new?assignees=&labels=&template=feature_request.md&title=)
.

* `com.apple.idamd`
    * Allows settings the IDAM configuration (something to do with loading of AppleUSBDeviceAudioDevice)
* `com.apple.atc`
    * AirTraffic related
* `com.apple.atc2`
* `com.apple.ait.aitd`
    * AirTraffic related
* `com.apple.mobile.file_relay` (Deprecated)
    * On older iOS versions (iOS <= 8), this was the main relay used for file operations, which was later replaced with
      AFC.
* `com.apple.mobilesync`
* `com.apple.purpletestr` (Deprecated)
* `com.apple.PurpleReverseProxy.Conn`
    * Something to do with tethering internet connection to restored devices
* `com.apple.PurpleReverseProxy.Ctrl`
    * Something to do with tethering internet connection to restored devices
* `com.apple.dt.remotepairingdeviced.lockdown`
* `com.apple.commcenter.mobile-helper-cbupdateservice`
* `com.apple.carkit.service`
    * Used to transfer data to accessories. Data is transferred using iAP2 packets.
* `com.apple.bluetooth.BTPacketLogger`
* `com.apple.streaming_zip_conduit`
    * Another relay used to install IPAs

### Sending your own messages

#### Lockdown messages

Every such subcommand may wrap several relay requests underneath. If you wish to try and play with some the relays
yourself, you can run:

```shell
pymobiledevice3 lockdown service <service-name>
```

This will start an IPython shell where you already have the connection established using the `client` variable, and you
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

#### Instruments messages

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

