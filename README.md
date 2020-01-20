# pymobiledevice

[![GitHub license](https://img.shields.io/cran/l/devtools.svg)](LICENSE)

pymobiledevice is a cross-platform implementation of the mobiledevice library
that talks the protocols to support iPhone®, iPod Touch®, iPad® and Apple TV® devices.


## Requirements

* Python 2.7 and 3.x
* M2Crypto
* construct >= 2.9.29
* pyasn1
* future
* six
* biplist
* usbmuxd must be installed and running

## Lockdownd.py [com.apple.lockownd]

This script can be used in order to pair with the device & starts other services.

*Other services can only be accessed after successful pairing.
Succesful pairing requires the device to be unlocked and the user to click
"Trust this device" on their phone screen.*


## afc.py [com.apple.afc]

This service is responsible for things such as copying music and photos. AFC Clients like iTunes
are allowed accessing to a “jailed” or limited area of the device filesystem. Actually, AFC clients can
only access certain files, namely those located in the Media folder.


## house_arrest.py [com.apple.mobile.house_arrest]

This service allows accessing to AppStore applications folders and their content.
In other words, by using an AFC client, a user/attacker can download the application resources and data.
It also includes the “default preferences” file where credentials are sometimes stored.


## installation_proxy.py [com.apple.mobile.installation_proxy]

The installation proxy manages applications on a device.
It allows execution of the following commands:
- List installed applications
- List archived applications
- ...


## mobilebackup.py & mobilebackup2.py [ com.apple.mobilebackup & com.apple.mobilebackup2 ]

Those services are used by iTunes to backup the device.


## diagnostics_relay.py [com.apple.mobile.diagnostics_relay]

The diagnostic relay allows requesting iOS diagnostic information.
The service handles the following actions:
- [ Sleep ]Puts the device into deep sleep mode and disconnects from host.
- [ Restart ] Restart the device and optionally show a user notification.
- [ Shutdown ] Shutdown of the device and optionally show a user notification.
- [ NAND, IORegistry, GasGauge, MobileGestalt ] Querry diagnostic informations.
- ...


## filerelay.py [com.apple.mobile.file_relay]

Depending of the iOS version, the file relay service may support the following commands:
    Accounts, AddressBook, AppleSupport, AppleTV, Baseband, Bluetooth, CrashReporter, CLTM
    Caches, CoreLocation, DataAccess, DataMigrator, demod, Device-o-Matic, EmbeddedSocial, FindMyiPhone
    GameKitLogs, itunesstored, IORegUSBDevice, HFSMeta, Keyboard, Lockdown, MapsLogs, MobileAsset,
    MobileBackup, MobileCal, MobileDelete, MobileInstallation, MobileMusicPlayer, MobileNotes, NANDDebugInfo
    Network, Photos, SafeHarbor, SystemConfiguration, tmp, Ubiquity, UserDatabases, VARFS, VPN, Voicemail
    WiFi, WirelessAutomation.

All the files returned by the iPhone are stored in clear text in a gziped CPIO archive.


## pcapd.py [com.apple.pcapd]

Starting iOS 5, apple added a remote virtual interface (RVI) facility that allows mirroring networks trafic from an iOS device.
On Mac OSX the virtual interface can be enabled with the rvictl command. This script allows to use this service on other systems.


# How to contribute
Contributors are essential to pymobiledevice (as they are to most open source projects).
Drop us a line if you want to contribute.
We also accept pull request.


# Reporting issues
### Questions
It is OK so submit issues to ask questions (more than OK, encouraged). There is a label "question" that you can use for that.

### Bugs
If you have installed pymobiledevice through a package manager (from your Linux or BSD system, from PyPI, etc.), please get and install the current development code, and check that the bug still exists before submitting an issue.

Please label your issues "bug".

If you're not sure whether a behavior is a bug or not, submit an issue and ask, don't be shy!

Enhancements / feature requests
If you want a feature in pymobiledevice, but cannot implement it yourself or want some hints on how to do that, open an issue with label "enhancement".

Explain if possible the API you would like to have (e.g., give examples of function calls, etc.).
