- [RemoteXPC](#remotexpc)
    * [Overview](#overview)
    * [Previous research](#previous-research)
    * [USB Ethernet](#usb-ethernet)
    * [Process: `remoted`](#process-remoted)
    * [Pairing](#pairing)
    * [Trusted tunnel](#trusted-tunnel)
        + [Reusing the macOS trusted tunnel](#reusing-the-macos-trusted-tunnel)
    * [Accessing services over the trusted tunnel](#accessing-services-over-the-trusted-tunnel)
        + [Lockdown services](#lockdown-services)
        + [RemoteXPC services](#remotexpc-services)
            - [CoreDevice services](#coredevice-services)
    * [Using `pymobiledevice3` as a client](#using-pymobiledevice3-as-a-client)
        + [Handshake & Pairing](#handshake--pairing)
        + [Accessing services over RemoteXPC](#accessing-services-over-remotexpc)

# RemoteXPC

## Overview

Starting at iOS 17.0, Apple refactored a lot in the way iOS devices communicate with the macOS. Up until iOS 16, The
communication was TCP based (using the help of `usbmuxd` for USB devices) with TLS (for making sure only trusted peers
are able to connect). You can read more about
the old protocol in this article:

https://jon-gabilondo-angulo-7635.medium.com/understanding-usbmux-and-the-ios-lockdown-service-7f2a1dfd07ae

The new protocol stack relies on [QUIC](https://en.wikipedia.org/wiki/QUIC)+RemoteXPC which should reduce much of the
communication overhead in general - allowing faster and more stable connections, especially over WiFi.

## Previous research

RemoteXPC was introduced for macOS much earlier. You can read more about it here:

https://duo.com/labs/research/apple-t2-xpc

However, our protocol stack is a bit different.

## USB Ethernet

Starting in iOS 17, whenever you connect an iPhone to your macOS, it creates a new network device (with an IPv6 address
😱) using [Ethernet over USB](https://en.wikipedia.org/wiki/Ethernet_over_USB) - Meaning, the device is always on
your LAN and you can communicate with it using Ethernet protocols.

## Process: `remoted`

Each Apple device runs a daemon named `remoted`. This daemon allows processes running on the same host to register XPC
services they wish to export to other clients over the network (hence the RemoteXPC name).

Other processes can ask (over XPC) to `browse` for newly connected devices. This browse occurs
using [bonjour](https://en.wikipedia.org/wiki/Bonjour_(software)).

Once a device is found, `remoted` establishes a RemoteXPC connection (XPC dictionaries serialized
over [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2)) to the RSD (RemoteServiceDiscovery) port (hard-coded `58783`) to
get a list of exported services:

<details>
<summary>Show RSD handshake response</summary>

```json
{
  "MessageType": "Handshake",
  "MessagingProtocolVersion": 3,
  "Properties": {
    "AppleInternal": false,
    "BoardId": 14,
    "BootSessionUUID": "a4ba4745-5925-4e45-93ab-46ec91880c91",
    "BuildVersion": "21A5277j",
    "CPUArchitecture": "arm64e",
    "CertificateProductionStatus": true,
    "CertificateSecurityMode": true,
    "ChipID": 33056,
    "DeviceClass": "iPhone",
    "DeviceColor": "1",
    "DeviceEnclosureColor": "1",
    "DeviceSupportsLockdown": true,
    "EffectiveProductionStatusAp": true,
    "EffectiveProductionStatusSEP": true,
    "EffectiveSecurityModeAp": true,
    "EffectiveSecurityModeSEP": true,
    "EthernetMacAddress": "aa:bb:cc:dd:ee:ff",
    "HWModel": "D74AP",
    "HardwarePlatform": "t8120",
    "HasSEP": true,
    "HumanReadableProductVersionString": "17.0",
    "Image4CryptoHashMethod": "sha2-384",
    "Image4Supported": true,
    "IsUIBuild": true,
    "IsVirtualDevice": false,
    "MobileDeviceMinimumVersion": "1600",
    "ModelNumber": "MQ9U3",
    "OSInstallEnvironment": false,
    "OSVersion": "17.0",
    "ProductName": "iPhone OS",
    "ProductType": "iPhone15,3",
    "RegionCode": "HX",
    "RegionInfo": "HX/A",
    "ReleaseType": "Beta",
    "RemoteXPCVersionFlags": 72057594037927942,
    "RestoreLongVersion": "21.1.277.5.10,0",
    "SecurityDomain": 1,
    "SensitivePropertiesVisible": true,
    "SerialNumber": 1111111,
    "SigningFuse": true,
    "StoreDemoMode": false,
    "SupplementalBuildVersion": "21A5277j",
    "ThinningProductType": "iPhone15,3",
    "UniqueChipID": 111111,
    "UniqueDeviceID": "222222222"
  },
  "Services": {
    "com.apple.fusion.remote.service": {
      "Entitlement": "com.apple.fusion.remote.service",
      "Port": "52286",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.gputools.remote.agent": {
      "Entitlement": "com.apple.private.gputoolstransportd",
      "Port": "52292",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.internal.dt.coredevice.untrusted.tunnelservice": {
      "Entitlement": "com.apple.dt.coredevice.tunnelservice.client",
      "Port": "52291",
      "Properties": {
        "ServiceVersion": 2,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.mobile.insecure_notification_proxy.remote": {
      "Entitlement": "com.apple.mobile.insecure_notification_proxy.remote",
      "Port": "52289",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.mobile.insecure_notification_proxy.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.untrusted",
      "Port": "52287"
    },
    "com.apple.mobile.lockdown.remote.untrusted": {
      "Entitlement": "com.apple.mobile.lockdown.remote.untrusted",
      "Port": "52288",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.osanalytics.logTransfer": {
      "Entitlement": "com.apple.ReportCrash.antenna-access",
      "Port": "52290",
      "Properties": {
        "UsesRemoteXPC": true
      }
    }
  },
  "UUID": "1d701c76-cf8e-45c7-a6c9-d794ee85411c"
}
```

</details>

As you can see, we get quite some info:

- The device general information
- Each service may report the following metadata:
    - `UsesRemoteXPC`: Whether the communication is done over RemoteXPC or not.
    - `Entitlement`: From my understanding, this just regards the entitlement needed by the
      connecting on-device client.
    - `ServiceVersion`: Probably refers to some protocol changes being done to help backward compatibility of other
      clients.

Each of this services can be accessed from any untrusted peer.

## Pairing

One of the clients asking `remoted` for `browse` is `remotepairingd` which is in charge of.. well.. pairing.
It does so via the `com.apple.internal.dt.coredevice.untrusted.tunnelservice` service.

The pairing is done in a state machine as follows:

- Wait user consent (The "Trust / Don't Trust" dialog)
- Key exchange ([SRP](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol), with the dummy password: `000000`)
- Request to save pair record on remote device

And... that's it! The client can now use the saved pair record to request a **trusted tunnel**.

## Trusted tunnel

Over the now paired connection to `com.apple.internal.dt.coredevice.untrusted.tunnelservice` the
client (`remotepairingd`) can now request to establish a trusted tunnel. This tunnel acts a VPN to the device for
trusted connections.

The client then generates its own keypair and send the following request:

```json
{
  "request": {
    "_0": {
      "createListener": {
        "key": "CLIENT-PUBLIC-KEY",
        "transportProtocolType": "quic"
      }
    }
  }
}
```

The `transportProtocolType` specifies which transport protocol we would like to use for our VPN connection. The two
options are either `quic` which includes TLVv1.3 authentication - or a TLS over `udp` using a PSK.

Once the request has been made, the client then receives a response with the created QUIC server public key and port
number. It then connects and receives details for creating a local TUN device that will tunnel all the trusted traffic.

This response looks as follows:

```json
{
  "clientParameters": {
    "address": "fd58:8c92:8961::2",
    "mtu": 1280,
    "netmask": "ffff:ffff:ffff:ffff::"
  },
  "serverAddress": "fd58:8c92:8961::1",
  "serverRSDPort": 56307,
  "type": "serverHandshakeResponse"
}
```

The `clientParameters` are used to configure a TUN device on the local machine, while the other "server" related info is
for the new **trusted RSD connection**. That's right, we are going to use this trusted to (again) use RSD, and connect
to device XPC services - but this time as a fully trusted client.

The client now establishes another RSD connection to the specified `serverAddress` and `serverRSDPort` (which are now
done over the created TUN device, meaning they are going through a TLS encryption) and can now access new and wide range
of services.

### Reusing the macOS trusted tunnel

`remotepairingd` is generous enough to share this connection information into the host syslog. We can sniff
and deduct the VPN parameters by viewing the syslog (you can `sudo pkill -9 remoted` to force a reconnection):

```shell
log stream --debug --info --predicate 'eventMessage LIKE "*Tunnel established*" OR eventMessage LIKE "*for server port*"'
```

The output should be something similar to:

```
Timestamp                       Thread     Type        Activity             PID    TTL
2023-07-19 08:22:51.916784+0300 0x3058     Info        0x0                  599    0    remotepairingd: (RemotePairing) [com.apple.dt.remotepairing:networktunnelmanager] tunnel-1: Tunnel established for interface: utun3, local fd41:8efc:c0f8::2 -> fd41:8efc:c0f8::1
2023-07-19 08:22:51.917310+0300 0x559c     Info        0x0                  599    0    remotepairingd: [com.apple.dt.remotepairing:remotepairingd] device-0: Tunnel established - interface: utun3, local fd41:8efc:c0f8::2-> remote fd41:8efc:c0f8::1
2023-07-19 08:22:51.917414+0300 0x559c     Info        0x0                  599    0    remotepairingd: [com.apple.dt.remotepairing:remotepairingd] device-0: Creating RSD backend client device for server port 60364
```

## Accessing services over the trusted tunnel

The client now has a much wider list of services he is able to connect to:

<details>
<summary>Show RSD handshake response</summary>

```json
{
  "MessageType": "Handshake",
  "MessagingProtocolVersion": 3,
  "Properties": {
    "AppleInternal": false,
    "BoardId": 14,
    "BootSessionUUID": "a4ba4745-5925-4e45-93ab-46ec91880c91",
    "BuildVersion": "21A5277j",
    "CPUArchitecture": "arm64e",
    "CertificateProductionStatus": true,
    "CertificateSecurityMode": true,
    "ChipID": 33056,
    "DeviceClass": "iPhone",
    "DeviceColor": "1",
    "DeviceEnclosureColor": "1",
    "DeviceSupportsLockdown": true,
    "EffectiveProductionStatusAp": true,
    "EffectiveProductionStatusSEP": true,
    "EffectiveSecurityModeAp": true,
    "EffectiveSecurityModeSEP": true,
    "EthernetMacAddress": "aa:bb:cc:dd:ee:ff",
    "HWModel": "D74AP",
    "HardwarePlatform": "t8120",
    "HasSEP": true,
    "HumanReadableProductVersionString": "17.0",
    "Image4CryptoHashMethod": "sha2-384",
    "Image4Supported": true,
    "IsUIBuild": true,
    "IsVirtualDevice": false,
    "MobileDeviceMinimumVersion": "1600",
    "ModelNumber": "MQ9U3",
    "OSInstallEnvironment": false,
    "OSVersion": "17.0",
    "ProductName": "iPhone OS",
    "ProductType": "iPhone15,3",
    "RegionCode": "HX",
    "RegionInfo": "HX/A",
    "ReleaseType": "Beta",
    "RemoteXPCVersionFlags": 72057594037927942,
    "RestoreLongVersion": "21.1.277.5.10,0",
    "SecurityDomain": 1,
    "SensitivePropertiesVisible": true,
    "SerialNumber": 1111111,
    "SigningFuse": true,
    "StoreDemoMode": false,
    "SupplementalBuildVersion": "21A5277j",
    "ThinningProductType": "iPhone15,3",
    "UniqueChipID": 111111,
    "UniqueDeviceID": "222222222"
  },
  "Services": {
    "com.apple.GPUTools.MobileService.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55307"
    },
    "com.apple.PurpleReverseProxy.Conn.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55305"
    },
    "com.apple.PurpleReverseProxy.Ctrl.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55291"
    },
    "com.apple.RestoreRemoteServices.restoreserviced": {
      "Entitlement": "com.apple.private.RestoreRemoteServices.restoreservice.remote",
      "Port": "55298",
      "Properties": {
        "ServiceVersion": 2,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.accessibility.axAuditDaemon.remoteserver.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55269"
    },
    "com.apple.afc.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55255"
    },
    "com.apple.amfi.lockdown.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55261"
    },
    "com.apple.atc.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55268"
    },
    "com.apple.atc2.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55309"
    },
    "com.apple.backgroundassets.lockdownservice.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55310"
    },
    "com.apple.bluetooth.BTPacketLogger.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55266"
    },
    "com.apple.carkit.remote-iap.service": {
      "Entitlement": "AppleInternal",
      "Port": "55296",
      "Properties": {
        "UsesRemoteXPC": true
      }
    },
    "com.apple.carkit.service.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55312"
    },
    "com.apple.commcenter.mobile-helper-cbupdateservice.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55273"
    },
    "com.apple.companion_proxy.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55285"
    },
    "com.apple.corecaptured.remoteservice": {
      "Entitlement": "com.apple.corecaptured.remoteservice-access",
      "Port": "55302",
      "Properties": {
        "UsesRemoteXPC": true
      }
    },
    "com.apple.coredevice.appservice": {
      "Entitlement": "com.apple.private.CoreDevice.canInstallCustomerContent",
      "Port": "55278",
      "Properties": {
        "Features": [
          "com.apple.coredevice.feature.launchapplication",
          "com.apple.coredevice.feature.spawnexecutable",
          "com.apple.coredevice.feature.monitorprocesstermination",
          "com.apple.coredevice.feature.installapp",
          "com.apple.coredevice.feature.uninstallapp",
          "com.apple.coredevice.feature.listroots",
          "com.apple.coredevice.feature.installroot",
          "com.apple.coredevice.feature.uninstallroot",
          "com.apple.coredevice.feature.sendsignaltoprocess",
          "com.apple.coredevice.feature.sendmemorywarningtoprocess",
          "com.apple.coredevice.feature.listprocesses",
          "com.apple.coredevice.feature.rebootdevice",
          "com.apple.coredevice.feature.listapps",
          "com.apple.coredevice.feature.fetchappicons"
        ],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.coredevice.deviceinfo": {
      "Entitlement": "com.apple.private.CoreDevice.canRetrieveDeviceInfo",
      "Port": "55259",
      "Properties": {
        "Features": [
          "com.apple.coredevice.feature.getdeviceinfo",
          "com.apple.coredevice.feature.querymobilegestalt",
          "com.apple.coredevice.feature.getlockstate"
        ],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.coredevice.diagnosticsservice": {
      "Entitlement": "com.apple.private.CoreDevice.canObtainDiagnostics",
      "Port": "55274",
      "Properties": {
        "Features": [
          "com.apple.coredevice.feature.capturesysdiagnose"
        ],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.coredevice.fileservice.control": {
      "Entitlement": "com.apple.private.CoreDevice.canTransferFilesToDevice",
      "Port": "55284",
      "Properties": {
        "Features": [
          "com.apple.coredevice.feature.transferFiles"
        ],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.coredevice.fileservice.data": {
      "Entitlement": "com.apple.private.CoreDevice.canTransferFilesToDevice",
      "Port": "55275",
      "Properties": {
        "Features": [],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.coredevice.openstdiosocket": {
      "Entitlement": "com.apple.private.CoreDevice.canInstallCustomerContent",
      "Port": "55301",
      "Properties": {
        "Features": [],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.crashreportcopymobile.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55304"
    },
    "com.apple.crashreportmover.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55289"
    },
    "com.apple.dt.ViewHierarchyAgent.remote": {
      "Entitlement": "com.apple.private.dt.ViewHierarchyAgent.client",
      "Port": "55277",
      "Properties": {
        "UsesRemoteXPC": true
      }
    },
    "com.apple.dt.remoteFetchSymbols": {
      "Entitlement": "com.apple.private.dt.remoteFetchSymbols.client",
      "Port": "55263",
      "Properties": {
        "Features": [
          "com.apple.dt.remoteFetchSymbols.dyldSharedCacheFiles"
        ],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.dt.remotepairingdeviced.lockdown.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55293"
    },
    "com.apple.dt.testmanagerd.remote": {
      "Entitlement": "com.apple.private.dt.testmanagerd.client",
      "Port": "55299",
      "Properties": {
        "UsesRemoteXPC": false
      }
    },
    "com.apple.dt.testmanagerd.remote.automation": {
      "Entitlement": "AppleInternal",
      "Port": "55260",
      "Properties": {
        "UsesRemoteXPC": false
      }
    },
    "com.apple.fusion.remote.service": {
      "Entitlement": "com.apple.fusion.remote.service",
      "Port": "55311",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.gputools.remote.agent": {
      "Entitlement": "com.apple.private.gputoolstransportd",
      "Port": "55303",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.idamd.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55264"
    },
    "com.apple.instruments.dtservicehub": {
      "Entitlement": "com.apple.private.dt.instruments.dtservicehub.client",
      "Port": "55270",
      "Properties": {
        "Features": [
          "com.apple.dt.profile"
        ],
        "version": 1
      }
    },
    "com.apple.internal.devicecompute.CoreDeviceProxy": {
      "Entitlement": "AppleInternal",
      "Port": "55271",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": false
      }
    },
    "com.apple.internal.dt.coredevice.untrusted.tunnelservice": {
      "Entitlement": "com.apple.dt.coredevice.tunnelservice.client",
      "Port": "55267",
      "Properties": {
        "ServiceVersion": 2,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.internal.dt.remote.debugproxy": {
      "Entitlement": "com.apple.private.CoreDevice.canDebugApplicationsOnDevice",
      "Port": "55249",
      "Properties": {
        "Features": [
          "com.apple.coredevice.feature.debugserverproxy"
        ],
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.iosdiagnostics.relay.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55287"
    },
    "com.apple.misagent.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55257"
    },
    "com.apple.mobile.MCInstall.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55313"
    },
    "com.apple.mobile.assertion_agent.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55314"
    },
    "com.apple.mobile.diagnostics_relay.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55253"
    },
    "com.apple.mobile.file_relay.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55300"
    },
    "com.apple.mobile.heartbeat.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55272"
    },
    "com.apple.mobile.house_arrest.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55265"
    },
    "com.apple.mobile.insecure_notification_proxy.remote": {
      "Entitlement": "com.apple.mobile.insecure_notification_proxy.remote",
      "Port": "55315",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.mobile.insecure_notification_proxy.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.untrusted",
      "Port": "55308"
    },
    "com.apple.mobile.installation_proxy.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55276"
    },
    "com.apple.mobile.lockdown.remote.trusted": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55294",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.mobile.lockdown.remote.untrusted": {
      "Entitlement": "com.apple.mobile.lockdown.remote.untrusted",
      "Port": "55251",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.mobile.mobile_image_mounter.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55252"
    },
    "com.apple.mobile.notification_proxy.remote": {
      "Entitlement": "com.apple.mobile.notification_proxy.remote",
      "Port": "55292",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.mobile.notification_proxy.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55286"
    },
    "com.apple.mobile.storage_mounter_proxy.bridge": {
      "Entitlement": "com.apple.private.mobile_storage.remote.allowedSPI",
      "Port": "55279",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.mobileactivationd.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55295"
    },
    "com.apple.mobilebackup2.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55281"
    },
    "com.apple.mobilesync.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55282"
    },
    "com.apple.os_trace_relay.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55254"
    },
    "com.apple.osanalytics.logTransfer": {
      "Entitlement": "com.apple.ReportCrash.antenna-access",
      "Port": "55256",
      "Properties": {
        "UsesRemoteXPC": true
      }
    },
    "com.apple.pcapd.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55290"
    },
    "com.apple.preboardservice.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55258"
    },
    "com.apple.preboardservice_v2.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55288"
    },
    "com.apple.remote.installcoordination_proxy": {
      "Entitlement": "com.apple.private.InstallCoordinationRemote",
      "Port": "55297",
      "Properties": {
        "ServiceVersion": 1,
        "UsesRemoteXPC": true
      }
    },
    "com.apple.springboardservices.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55250"
    },
    "com.apple.streaming_zip_conduit.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55280"
    },
    "com.apple.sysdiagnose.remote": {
      "Entitlement": "com.apple.private.sysdiagnose.remote",
      "Port": "55306",
      "Properties": {
        "UsesRemoteXPC": true
      }
    },
    "com.apple.syslog_relay.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55283"
    },
    "com.apple.webinspector.shim.remote": {
      "Entitlement": "com.apple.mobile.lockdown.remote.trusted",
      "Port": "55262"
    }
  },
  "UUID": "289ff0d8-cbbb-4f46-867e-48a68f3b65f8"
}
```

</details>

Now let's divide them into two main groups:

- Lockdown services
- RemoteXPC services

### Lockdown services

All the services that used to be accessible via `lockdownd`, are now accessible via `remoted` "directly". All the
services that require the `com.apple.mobile.lockdown.remote.trusted` entitlement will actually be spawned
via `lockdownd`, but in a transparent manner to us.

We need to first send the following message:

```json
{
  "Label": "userAgent",
  "ProtocolVersion": "2",
  "Request": "RSDCheckin",
  "EscrowBag": "if any..."
}
```

This causes `remoted` to connect to `lockdownd` and request to start the service we want to talk to - Allowing a very
nice abstract way to keep communicating with the old device the same way we used to.

### RemoteXPC services

The RemoteXPC services will declare the `UsesRemoteXPC` property. We communicate with them the same was as with the RSD
service.

#### CoreDevice services

Some of the RemoteXPC services are CoreDevice services. We can distinguish them by having the `Features` key, telling us
of all the available methods these services support.

The format of each XPC dictionary sent as a request is as follows:

```python
request = {
    'CoreDevice.CoreDeviceDDIProtocolVersion': XpcInt64Type(0),
    'CoreDevice.action': {},

    'CoreDevice.coreDeviceVersion': {
        'components': [XpcUInt64Type(325), XpcUInt64Type(3), XpcUInt64Type(0),
                       XpcUInt64Type(0), XpcUInt64Type(0)],
        'originalComponentsCount': XpcInt64Type(2),
        'stringValue': '325.3'},
    'CoreDevice.deviceIdentifier': '7454ABFD-F789-4F99-9EE1-5FB8F7035ECE',
    'CoreDevice.featureIdentifier': feature_identifier,
    'CoreDevice.input': parameters,
    'CoreDevice.invocationIdentifier': '14A17AB8-0576-4E73-94C6-C0282A4F66E3'}
```

The response is just what the invoked function returned.

## Using `pymobiledevice3` as a client

See [main documentation](/README.md#working-with-developer-tools-ios--170) for details.

### Accessing services over RemoteXPC

Almost every command of `pymobiledevice` now receives an optional `--rsd`, allowing us to communicate the same old
services over RSD. Please notice some of them, such as all the developer services will now only be accessible this way. 
