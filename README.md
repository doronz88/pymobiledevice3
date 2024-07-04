# PyMobileDevice3

<!-- markdownlint-disable MD013 -->
[![Python application](https://github.com/doronz88/pymobiledevice3/workflows/Python%20application/badge.svg)](https://github.com/doronz88/pymobiledevice3/actions/workflows/python-app.yml "Python application action")
[![Pypi version](https://img.shields.io/pypi/v/pymobiledevice3.svg)](https://pypi.org/project/pymobiledevice3/ "PyPi package")
[![Downloads](https://static.pepy.tech/personalized-badge/pymobiledevice3?period=total&units=none&left_color=grey&right_color=blue&left_text=Downloads)](https://pepy.tech/project/pymobiledevice3)
[![Discord](https://img.shields.io/discord/1133265168051208214?logo=Discord&label=Discord)](https://discord.gg/52mZGC3JXJ)
<!-- markdownlint-enable MD013 -->

- [PyMobileDevice3](#pymobiledevice3)
  - [Overview](#overview)
  - [Installation](#installation)
    - [OpenSSL libraries](#openssl-libraries)
    - [libusb dependency](#libusb-dependency)
  - [Usage](#usage)
    - [Working with developer tools (iOS \>= 17.0)](#working-with-developer-tools-ios--170)
    - [Commonly used actions](#commonly-used-actions)
  - [The bits and bytes (Python API)](#the-bits-and-bytes-python-api)
  - [Contributing](#contributing)
  - [Useful info](#useful-info)
  - [Copyright notice](#copyright-notice)

## Overview

`pymobiledevice3` is a pure python3 implementation for working with iDevices (iPhone, etc...). This means this tool is
both architecture and platform generic and is supported and tested on:

- Windows
- Linux
- macOS

Main features include:

- Device discovery over bonjour
- TCP port forwarding
- Viewing syslog lines (including debug)
- Profile management
- Application management
- File system management (AFC)
- Crash reports management
- Network sniffing (PCAP)
- Firmware update
- Mounting images
- Notification listening and triggering (`notify_post()` api)
- Querying and setting SpringBoard options
- Automating WebInspector features
- DeveloperDiskImage features:
  - Taking screenshots
  - Simulate locations
  - Process management
  - Sniffing KDebug messages (**strace** capabilities++)
  - Process monitoring (`top` like)
  - Accessibility features
  - Sniffing oslog which includes both syslog and signposts
- Backup

## Installation

You can install from PyPi:

```shell
python3 -m pip install -U pymobiledevice3
```

Or install the latest version directly from sources:

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

### OpenSSL libraries

Currently, openssl is explicitly required if using on older iOS version (<13).

On macOS:

```shell
brew install openssl
```

On Linux:

```shell
sudo apt install openssl
```

### libusb dependency

Interacting with the device in Recovery or DFU modes requires `libusb` to be installed (necessary for handling the `restore` subcommands).

The installation steps differentiate depending on your exact platform:

On macOS:

```shell
# using homebrew
brew install libusb

# using MacPorts
sudo port install libusb
```

On Linux:

```shell
# Debian/Ubuntu
sudo apt-get install libusb-1.0-0-dev

# Fedora
sudo dnf install libusb-devel

# Arch Linux
sudo pacman -S libusb
```

On windows:

Following libusb website to download latest release binaries:

<https://libusb.info/>

## Usage

The CLI subcommands are divided roughly by the protocol layer used for interacting in the device. For example, all
features derived from the DeveloperDiskImage will be accessible from the `developer`
subcommand. This also means that every feature which isn't there won't require it.

This is the main CLI usage:

```
Usage: pymobiledevice3 [OPTIONS] COMMAND [ARGS]...

  Interact with a connected iDevice (iPhone, iPad, ...)
  For more information please look at:
      https://github.com/doronz88/pymobiledevice3

Options:
  -h, --help  Show this message and exit.

Commands:
  activation       Perform iCloud activate/deactivation or query the state
  afc              Manage device multimedia files
  amfi             Enable/Disable developer-mode or query its state
  apps             Manage installed applications
  backup2          Backup/Restore options
  bonjour          Browse devices over bonjour
  companion        List paired "companion" devices
  crash            Manage crash reports
  developer        Perform developer operations
  diagnostics      Reboot/Shutdown device or diagnostics services
  lockdown         Pair/Unpair device or access other lockdown services
  mounter          Mount/Umount DeveloperDiskImage or query related info
  notification     Post/Observe notifications
  pcap             Sniff device traffic
  power-assertion  Create a power assertion
  processes        View process list using diagnosticsd API
  profile          Managed installed profiles or install SSL certificates
  provision        Manage installed provision profiles
  remote           Create RemoteXPC tunnels
  restore          Restore an IPSW or access device in recovery mode
  springboard      Access device UI
  syslog           Watch syslog messages
  usbmux           List devices or forward a TCP port
  webinspector     Access webinspector services
  version          Query pymobiledevice3 version
```

### Working with developer tools (iOS >= 17.0)

> **NOTE:** Currently, this is only officially supported on macOS & Windows (up to iOS 17.3.1), but fully supported on
> all platforms starting at iOS 17.4 using the new lockdown tunnel. For windows interaction with iOS 17.0-17.3.1, you'll
> need to install the additional drivers (we don't provide them)

Starting at iOS 17.0, Apple introduced the new CoreDevice framework to work with iOS devices. This framework relies on
the [RemoteXPC](https://github.com/doronz88/pymobiledevice3/blob/master/misc/RemoteXPC.md) protocol. In order to
communicate with the developer services you'll be required to first
create [trusted tunnel](https://github.com/doronz88/pymobiledevice3/blob/master/misc/RemoteXPC.md#trusted-tunnel) in one
of the two forms:

- Launch a tunnel-server named `tunneld` to automatically detect devices and establish connections
  - Execute the following:

    ```shell
    # if the device supports remote pairing, such as corellium instances or AppleTVs,
    # you'll need to first pair them
    # normal iOS devices don't require this step 
    python3 -m pymobiledevice3 remote pair
    
    # on windows, use a privileged shell
    sudo python3 -m pymobiledevice3 remote tunneld
    ```

- Create tunnel manually using `start-tunnel`
  - Execute the following:

    ```shell
    # if the device supports remote pairing, such as corellium instances or AppleTVs,
    # you'll need to first pair them
    # normal iOS devices don't require this step 
    python3 -m pymobiledevice3 remote pair
    
    # NOTE: on windows, use a privileged shell for the following commands

    # starting at iOS 17.4 you can use the much faster lockdown tunnel
    sudo python3 -m pymobiledevice3 lockdown start-tunnel
    
    # if you need this connection type to be also available over wifi, you can enable it
    python3 -m pymobiledevice3 lockdown wifi-connections on

    # on older iOS version use the following instead
    # you may pass `-t wifi` to force a WiFi tunnel
    sudo python3 -m pymobiledevice3 remote start-tunnel
    ```

    You will be printed with the following output providing you with the required connection details:

    ```
    Interface: utun6
    RSD Address: fd7b:e5b:6f53::1
    RSD Port: 64337
    Use the follow connection option:
    --rsd fd7b:e5b:6f53::1 64337
    ```

_Ths command must be run with high privileges since it creates a new TUN/TAP device which is a high
privilege operation._

Now, (almost) all of pymobiledevice3 accept an additional `--rsd`/`--tunnel` option for connecting to the service over
the tunnel. The `--tunnel` option specifically, is always attempted implicitly upon an `InvalidServiceError` error to
simplify the work with developer services. You can now try to execute any of them as follows:

```shell
# Accessing the DVT services
# The --tunnel option may accept either an empty string, or a UDID for a specific device 
# The UDID may be suffixed with :PORT in case tunneld in serving at a non-default port 
python3 -m pymobiledevice3 developer dvt ls / --tunnel ''

# Or simply without the `--tunnel` option, assuming the tunneld is running
python3 -m pymobiledevice3 developer dvt ls /

# Or we could use the manual tunnel details
python3 -m pymobiledevice3 developer dvt ls / --rsd fd7b:e5b:6f53::1 64337

# And we can also access or the other "normal" lockdown services
python3 -m pymobiledevice3 syslog live --tunnel ''
```

### Commonly used actions

There is A LOT you may do on the device using `pymobiledevice3`. This is just a TL;DR of some common operations:

```shell
# Listing connected devices
pymobiledevice3 usbmux list

# Discover network devices using bonjour
pymobiledevice3 bonjour browse

# View all syslog lines (including debug messages
pymobiledevice3 syslog live

# Filter out only messages containing the word "SpringBoard"
pymobiledevice3 syslog live -m SpringBoard

# Restart device
pymobiledevice3 diagnostics restart

# Pull all crash reports from device
pymobiledevice3 crash pull /path/to/crashes

# Manage the media directory
pymobiledevice3 afc shell

# List all installed applications and their details
pymobiledevice3 apps list

# List query only a specific set os apps
pymobiledevice3 apps query BUNDLE_ID1 BUNDLE_ID2

# Create a TCP tunnel from your HOST to the device
pymobiledevice3 usbmux forward HOST_PORT DEVICE_PORT

# Create a full backup of the device
pymobiledevice3 backup2 backup --full DIRECTORY

# Restore a given backup
pymobiledevice3 backup2 restore DIRECTORY

# Perform a software upate by a given IPSW file/url:
pymobiledevice3 restore update -i /path/to/ipsw | url

# Note: The following webinspector subcommands will require the Web Inspector feature to be turned on

# Get interactive JavaScript shell on any open tab
pymobiledevice3 webinspector js-shell

# List currently opened tabs is device's browser
pymobiledevice3 webinspector opened-tabs

# Note: The following webinspector subcommands will require also the Remote Automation feature to be turned on

# Get interactive JavaScript shell on new remote automation tab
pymobiledevice3 webinspector js-shell --automation

# Launch an automation session to view a given URL
pymobiledevice3 webinspector launch URL

# Get a a selenium-like shell
pymobiledevice3 webinspector shell

# Note: The following subcommand will require DeveloperMode to be turned on. If your device doesn't have a pin-code, you can turn it on automatically using the following command
pymobiledevice3 amfi enable-developer-mode

# Mount the DDI (DeveloperDiskImage)
pymobiledevice3 mounter auto-mount

# Note: The following subcommands assume both DeveloperMode is turned on and the DDI has been mounted

# Simulate a `lat long` location (iOS < 17.0)
pymobiledevice3 developer simulate-location set -- lat long

# Simulate a `lat long` location (iOS >= 17.0)
pymobiledevice3 developer dvt simulate-location set -- lat long

# Play a .GPX file
pymobiledevice3 developer dvt simulate-location play route.gpx

# Add random timing noise between -500 and 500ms on the time between two points in the GPX file
pymobiledevice3 developer dvt simulate-location play route.gpx 500

# Clear the simulated location:
pymobiledevice3 developer dvt simulate-location clear

# Taking a screenshot from the device:
pymobiledevice3 developer dvt screenshot /path/to/screen.png

# View detailed process list (including ppid, uid, guid, sandboxed, etc...)
pymobiledevice3 developer dvt sysmon process single

# Sniffing oslog
pymobiledevice3 developer dvt oslog

# Kill a process
pymobiledevice3 developer dvt kill PID

# List files in a given directory (un-chrooted)
pymobiledevice3 developer dvt ls PATH

# Launch an app by its bundle name
pymobiledevice3 developer dvt launch com.apple.mobilesafari

# Sniff all KDebug events to get an `strace`-like output:
pymobiledevice3 developer dvt core-profile-session parse-live

# Sniff all KDebug events into a file for parsing later with tools such as [`pykdebugparser`](https://github.com/matan1008/pykdebugparser), `fs_usage` and so on...
pymobiledevice3 developer dvt core-profile-session save FILENAME

# Get device extended information (kernel name, chipset, etc...)
pymobiledevice3 developer dvt device-information

# Monitor energy-consumption for a specific PID
pymobiledevice3 developer dvt energy PID1 PID2 ...
```

## The bits and bytes (Python API)

To understand the bits and bytes of the communication with `lockdownd`, or if are willing to learn the python API, you
are advised to take a look at this article:

[Understanding iDevice protocol layers](https://github.com/doronz88/pymobiledevice3/blob/master/misc/understanding_idevice_protocol_layers.md)

## Contributing

See [CONTRIBUTING](https://github.com/doronz88/pymobiledevice3/blob/master/CONTRIBUTING.md).

## Useful info

Please see [misc](https://github.com/doronz88/pymobiledevice3/blob/master/misc)

## Copyright notice

This work is licensed under GPL 3.0, and as, credited to several major contributors:

- Hector Martin "marcan" <hector@marcansoft.com>
- Mathieu Renard
- [doronz](https://github.com/doronz88) <doron88@gmail.com>
- [matan1008](https://github.com/matan1008) <matan1008@gmail.com>
- [Guy Salton](https://github.com/guysalt)
- [netanelc305](https://github.com/netanelc305) <netanelc305@protonmail.com>
