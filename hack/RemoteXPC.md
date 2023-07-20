# RemoteXPC

## Overview

Starting at iOS 17.0, Apple refactored at lot in the way iOS devices communicate with the macOS. Up until iOS 16, The
communication was TCP based (using the help of `usbmuxd` for USB devices) with TLS (for making sure only trusted peers
are able to connect). You can read more about
the old protocol in this article:

https://jon-gabilondo-angulo-7635.medium.com/understanding-usbmux-and-the-ios-lockdown-service-7f2a1dfd07ae

The new protocol stack relies on [QUIC](https://en.wikipedia.org/wiki/QUIC)+RemoteXPC which should reduce much of the
communication overhead in general - allowing faster and more stable connections, especially over WiFi.

## RemoteXPC

RemoteXPC was introduced for macOS much earlier. You can read more about it here:

https://duo.com/labs/research/apple-t2-xpc

However, our protocol stack is a bit different.

## Discover

Starting in iOS 17, whenever you connect an iPhone to your macOS, it creates a new network device (with an IPv6 😱
address) using [Ethernet over USB](https://en.wikipedia.org/wiki/Ethernet_over_USB) - Meaning, the device is always on
your LAN and you can communicate with it using Ethernet protocols.

Each Apple device runs a daemon named `remoted`. This daemon is in charge of discovering other Apple devices over LAN
using [bonjour](https://en.wikipedia.org/wiki/Bonjour_(software)) and allowing to call exported XPC services over it.

Once a device is found, `remoted` establishes a RemoteXPC connection (XPC dictionaries serialized
over [HTTP/2](https://en.wikipedia.org/wiki/HTTP/2)) to the RSD (RemoteServiceDiscovery) port (hard-coded `58783`) to
get a list of exported services:

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

As you can see, we get quite some info:

- The device general information
- Exported services we can communicate to
    - Each such service even tells us if it also communicates over RemoteXPC or not
    - Each also reports an `Entitlement`. From my understanding, this just regards the entitlement needed by the
      connecting on-device client.
    - I guess the `ServiceVersion` refers to some protocol changes being done to help backward compatibility of other
      clients.

Each of this services can be access from any untrusted peer.

## Pairing

One these service is used for both pairing and accessing a much wider list of
services - `com.apple.internal.dt.coredevice.untrusted.tunnelservice`.

The pairing is done in a state machine as follows:

- Wait user consent (The "Trust / Don't Trust" dialog)
- Key exchange (SRP, with the dummy password: `000000`)
- Verify proof (SRP)
- Request to save pair record on remote device

And... that's it! The client can now use the saved pair record to request a **trusted tunnel**.

## Trusted tunnel

Over the now paired connection to `com.apple.internal.dt.coredevice.untrusted.tunnelservice` the client can now request
to establish a trusted tunnel. This tunnel acts a VPN to the device for trusted connections.

The client then generates its own keypair and sends the following request:

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

The `transportProtocolType` what transport protocol we would like to use for our VPN connection. The two options are
either `quic` which includes TLVv1.3 authentication - or a TLS over `udp` with a PSK.

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
for the new **trusted RSD connection**.

The client can now establish another RSD connection to the specified `serverAddress` and `serverRSDPort` (which are now
done over the created TUN device, meaning they are going through a TLS encryption) and can now view a new and wide range
of services.

The usual client on macOS to perform this handshake is `remotepairingd`. We can sniff and deduct the VPN parameters by
viewing the syslog:

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

