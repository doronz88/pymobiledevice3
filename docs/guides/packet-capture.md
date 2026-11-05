# Capturing Network Traffic (pcap)

`pymobiledevice3 pcap` records every packet an iPhone or iPad sends and receives, on every
interface (Wi-Fi, cellular, VPN, loopback), and labels each packet with the **process** that sent or
received it. It needs no jailbreak, no Developer Mode, no Xcode and no Mac, and runs the same on
macOS, Linux and Windows. It uses the device's built-in `pcapd` service, the same one behind Apple's
macOS-only `rvictl`.

--8<-- "docs/assets/terminal/pcap.html"

## Quick start

Connect the device over USB, unlock it and trust the computer, then:

```shell
pymobiledevice3 pcap --out capture.pcapng
```

Use the device, press Ctrl+C to stop, and open `capture.pcapng` in
[Wireshark](https://www.wireshark.org/). While capturing, each packet is also printed to the terminal
(a one-line summary plus a hex dump); without `--out`, that terminal output is all you get.

!!! note "The file is always pcapng"
    The output is written in the pcapng format whatever extension you give it, because pcapng is what
    carries the per-packet process labels. Name it `.pcapng` so every tool recognizes it.

## Filtering while you capture

| Option | Keeps only packets... | Example |
| --- | --- | --- |
| `--process NAME_OR_PID` | owned by this process (exact name, or PID) | `--process MobileSafari` |
| `-i`, `--interface NAME` | on this interface (`en0`), or on all units of one (`en`) | `-i en0` |
| `-c`, `--count N` | ...and stops after N of them | `-c 200` |

The options combine:

```shell
# The first 200 Wi-Fi packets of Safari
pymobiledevice3 pcap --process MobileSafari -i en0 -c 200 --out safari.pcapng
```

- **Process names** are the executable names the kernel reports (as `pymobiledevice3 processes ps`
  shows them), not the app's display name, and are truncated to 16 characters. Matching is exact and
  case-sensitive. A PID only matches while that process runs, so the name is usually the better
  choice.
- **Interfaces** you will typically see: `en0` (Wi-Fi), `pdp_ip0` and friends (cellular), `utun0`...
  (VPNs and system tunnels), `lo0` (loopback). Capture without `-i` first to see which ones carry
  traffic on your device.

## Which process sent this packet?

Every packet in the file carries a comment like:

```none
PID: 312, ProcName: nsurlsessiond, EPID: 1045, EProcName: MyApp, SVC: 0
```

- `ProcName` / `PID` is the process that owns the socket.
- `EProcName` / `EPID` is the **effective** process: the one the traffic is really for. iOS often
  lets a system daemon do networking on an app's behalf (for example `nsurlsessiond` for background
  transfers). Then `ProcName` is the daemon and `EProcName` is the app. For ordinary traffic both name
  the same process.

`--process` matches `ProcName` only. To find everything an app caused, including work delegated to
daemons, capture without `--process` and filter on `EProcName` afterwards.

### In Wireshark

Wireshark shows the comment under *Packet comments* in the packet details. Right-click it and
choose *Apply as Column* to see the process next to every packet. Display filters:

```none
frame.comment contains "EProcName: MyApp,"
frame.comment matches "^PID: [0-9]+, ProcName: MobileSafari,"
```

The first keeps everything done for `MyApp`; the second keeps only packets whose socket
`MobileSafari` itself owns. The trailing comma stops `MyApp` from also matching `MyAppExtension`.

### With tshark

`tshark` (Wireshark's command-line tool) can answer the common questions directly:

```shell
# Packets per effective process, busiest first
tshark -r capture.pcapng -T fields -e frame.comment \
  | sed -E 's/.*EProcName: ([^,]*),.*/\1/' | sort | uniq -c | sort -rn

# Which hosts did each process connect to over TLS (from the SNI)
tshark -r capture.pcapng -Y tls.handshake.extensions_server_name \
  -T fields -e frame.comment -e tls.handshake.extensions_server_name

# DNS lookups and who asked for them
tshark -r capture.pcapng -Y "dns.flags.response == 0" -T fields -e frame.comment -e dns.qry.name
```

## Live capture in Wireshark

On macOS and Linux, point Wireshark at a named pipe and let pymobiledevice3 write into it:

```shell
mkfifo /tmp/ios.pcapng
wireshark -k -i /tmp/ios.pcapng &
pymobiledevice3 pcap --out /tmp/ios.pcapng > /dev/null
```

Packets appear in Wireshark as they arrive (`> /dev/null` silences the terminal copy). On macOS,
`wireshark` is `/Applications/Wireshark.app/Contents/MacOS/Wireshark` unless you installed the
command-line wrapper.

## What a capture shows

- Encrypted traffic (HTTPS, QUIC, most app traffic) shows its endpoints, sizes, timing and the TLS
  server name, not its contents. DNS queries are usually readable.
- Packets from interfaces without an Ethernet header (cellular, VPN, loopback) get a placeholder
  Ethernet header with the address `be:ef:be:ef:be:ef` so every pcap tool can open the file. That
  address is not real hardware.
- The capture includes everything on the device, possibly personal data. Treat capture files as
  sensitive.

## From Python

```python
import asyncio

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.pcapd import PcapdService


async def main():
    async with await create_using_usbmux() as lockdown, PcapdService(lockdown) as pcap:
        async for packet in pcap.watch(packets_count=20):
            print(packet.comm, packet.ecomm, packet.interface_name, len(packet.data))

        # Or write a pcapng file, with the same filters as the CLI
        with open("capture.pcapng", "wb") as out:
            await pcap.write_to_pcap(out, pcap.watch(packets_count=100, process="MobileSafari"))


asyncio.run(main())
```

See the [`PcapdService` reference](../api/capture.md) for every field of a captured packet.
