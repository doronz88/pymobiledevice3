# Async, dependency-light mDNS browser returning dataclasses with per-address interface names.
# Works for any DNS-SD type, e.g. "_remoted._tcp.local."
# - Uses ifaddr (optional) to map IPs -> local interfaces; otherwise iface will be None.

import asyncio
import contextlib
import ipaddress
import socket
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import ifaddr  # pip install ifaddr

from pymobiledevice3.osu.os_utils import get_os_utils

REMOTEPAIRING_SERVICE_NAME = "_remotepairing._tcp.local."
REMOTEPAIRING_MANUAL_PAIRING_SERVICE_NAME = "_remotepairing-manual-pairing._tcp.local."
MOBDEV2_SERVICE_NAME = "_apple-mobdev2._tcp.local."
REMOTED_SERVICE_NAME = "_remoted._tcp.local."
OSUTILS = get_os_utils()
DEFAULT_BONJOUR_TIMEOUT = OSUTILS.bonjour_timeout

MDNS_PORT = 5353
MDNS_MCAST_V4 = "224.0.0.251"
MDNS_MCAST_V6 = "ff02::fb"

QTYPE_A = 1
QTYPE_PTR = 12
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_SRV = 33

CLASS_IN = 0x0001
CLASS_QU = 0x8000  # unicast-response bit (we use multicast queries)


# ---------------- Dataclasses ----------------


# --- Dataclass decorator shim (adds slots only on 3.10+)
def dataclass_compat(*d_args, **d_kwargs):
    if sys.version_info < (3, 10):
        d_kwargs.pop("slots", None)  # ignore on 3.9
    return dataclass(*d_args, **d_kwargs)


@dataclass_compat(slots=True)
class Address:
    ip: str
    iface: str  # local interface name (e.g., "en0"), or None if unknown

    @property
    def full_ip(self) -> str:
        if self.iface and self.ip.lower().startswith("fe80:"):
            return f"{self.ip}%{self.iface}"
        return self.ip


@dataclass_compat(slots=True)
class ServiceInstance:
    instance: str  # "<Instance Name>._type._proto.local."
    host: Optional[str]  # "host.local" (without trailing dot), or None if unresolved
    port: Optional[int]  # SRV port
    addresses: list[Address] = field(default_factory=list)  # IPs with interface names
    properties: dict[str, str] = field(default_factory=dict)  # TXT key/values


# ---------------- DNS helpers ----------------


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    out = bytearray()
    for label in name.split(".") if name else []:
        b = label.encode("utf-8")
        if len(b) > 63:
            raise ValueError("label too long")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, off: int) -> tuple[str, int]:
    labels = []
    jumped = False
    orig_end = off
    for _ in range(128):  # loop guard
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("truncated name pointer")
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if ptr >= len(data):
                raise ValueError("bad name pointer")
            if not jumped:
                orig_end = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        end = off + length
        if end > len(data):
            raise ValueError("truncated label")
        labels.append(data[off:end].decode("utf-8", errors="replace"))
        off = end
    return ".".join(labels) + ".", (orig_end if jumped else off)


def build_query(name: str, qtype: int, unicast: bool = False) -> bytes:
    hdr = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)  # TXID=0, flags=0, 1 question
    qclass = CLASS_IN | (CLASS_QU if unicast else 0)
    return hdr + encode_name(name) + struct.pack("!HH", qtype, qclass)


def parse_rr(data: bytes, off: int):
    name, off = decode_name(data, off)
    if off + 10 > len(data):
        raise ValueError("truncated RR header")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off : off + 10])
    off += 10
    rdata = data[off : off + rdlen]
    off += rdlen

    rr = {"name": name, "type": rtype, "class": rclass & 0x7FFF, "ttl": ttl}
    if rtype == QTYPE_PTR:
        target, _ = decode_name(data, off - rdlen)
        rr["ptrdname"] = target
    elif rtype == QTYPE_SRV and rdlen >= 6:
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = decode_name(data, off - rdlen + 6)
        rr.update({"priority": priority, "weight": weight, "port": port, "target": target})
    elif rtype == QTYPE_TXT:
        kv = {}
        i = 0
        while i < rdlen:
            b = rdata[i]
            i += 1
            seg = rdata[i : i + b]
            i += b
            if not seg:
                continue
            if b"=" in seg:
                k, v = seg.split(b"=", 1)
                kv[k.decode()] = v.decode(errors="replace")
            else:
                kv[seg.decode()] = ""
        rr["txt"] = kv
    elif rtype == QTYPE_A and rdlen == 4:
        rr["address"] = socket.inet_ntop(socket.AF_INET, rdata)
    elif rtype == QTYPE_AAAA and rdlen == 16:
        rr["address"] = socket.inet_ntop(socket.AF_INET6, rdata)
    else:
        rr["raw"] = rdata
    return rr, off


def parse_mdns_message(data: bytes):
    if len(data) < 12:
        return []
    _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = decode_name(data, off)
        off += 4
    rrs = []
    for _ in range(an + ns + ar):
        rr, off = parse_rr(data, off)
        rrs.append(rr)
    return rrs


# ---------------- Interface mapping helpers ----------------


class _Adapters:
    def __init__(self):
        self.adapters = ifaddr.get_adapters() if ifaddr is not None else []

    def pick_iface_for_ip(self, ip_str: str, family: int, v6_scopeid: Optional[int]) -> Optional[str]:
        # Prefer scope id for IPv6 link-local
        if family == socket.AF_INET6 and ip_str.lower().startswith("fe80:") and v6_scopeid:
            try:
                return socket.if_indextoname(v6_scopeid)
            except OSError:
                pass

        # Otherwise, try to match destination ip to local subnet via ifaddr
        if not self.adapters:
            return None
        ip = ipaddress.ip_address(ip_str)
        best = (None, -1)  # (name, prefix_len)
        for ad in self.adapters:
            for ipn in ad.ips:
                if isinstance(ipn.ip, str):
                    # IPv4
                    fam = socket.AF_INET
                    ipn_ip = ipn.ip
                else:
                    # IPv6
                    fam = socket.AF_INET6
                    ipn_ip = ipn.ip[0]
                if fam != family:
                    continue
                net = ipaddress.ip_network(f"{ipn_ip}/{ipn.network_prefix}", strict=False)
                if ip in net and ipn.network_prefix > best[1]:
                    best = (ad.nice_name or ad.name, ipn.network_prefix)
        return best[0]


# ---------------- async sockets ----------------


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    def datagram_received(self, data, addr):
        # addr: IPv4 -> (host, port); IPv6 -> (host, port, flowinfo, scopeid)
        self.queue.put_nowait((data, addr))


async def _bind_ipv4(queue: asyncio.Queue):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        with contextlib.suppress(OSError):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("0.0.0.0", MDNS_PORT))
    try:
        mreq = struct.pack("=4s4s", socket.inet_aton(MDNS_MCAST_V4), socket.inet_aton("0.0.0.0"))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: _DatagramProtocol(queue), sock=s)
    return transport, s


async def _bind_ipv6_all_ifaces(queue: asyncio.Queue):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        with contextlib.suppress(OSError):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("::", MDNS_PORT))
    grp = socket.inet_pton(socket.AF_INET6, MDNS_MCAST_V6)
    for ifindex, _ in socket.if_nameindex():
        mreq6 = grp + struct.pack("@I", ifindex)
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq6)
        except OSError:
            continue
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: _DatagramProtocol(queue), sock=s)
    return transport, s


async def _open_mdns_sockets():
    queue = asyncio.Queue()
    transports: list[tuple[asyncio.BaseTransport, socket.socket]] = []
    t4, s4 = await _bind_ipv4(queue)
    transports.append((t4, s4))
    t6, s6 = await _bind_ipv6_all_ifaces(queue)
    transports.append((t6, s6))
    if not transports:
        raise RuntimeError("Failed to open mDNS sockets (UDP/5353)")
    return transports, queue


async def _send_query_all(transports, pkt: bytes):
    for transport, sock in transports:
        if sock.family == socket.AF_INET:
            transport.sendto(pkt, (MDNS_MCAST_V4, MDNS_PORT))
        else:
            # Send once per iface index for better reachability
            for ifindex, _ in socket.if_nameindex():
                transport.sendto(pkt, (MDNS_MCAST_V6, MDNS_PORT, 0, ifindex))


# ---------------- Public API ----------------


async def browse_service(service_type: str, timeout: float = 4.0) -> list[ServiceInstance]:
    """
    Discover a DNS-SD/mDNS service type (e.g. "_remoted._tcp.local.") on the local network.

    Returns: List[ServiceInstance] with Address(ip, iface) entries.
    """
    if not service_type.endswith("."):
        service_type += "."

    transports, queue = await _open_mdns_sockets()
    adapters = _Adapters()

    ptr_targets: set[str] = set()
    srv_map: dict[str, dict] = {}
    txt_map: dict[str, dict] = {}
    # host -> list[(ip, iface)]
    host_addrs: dict[str, list[Address]] = defaultdict(list)

    def _record_addr(rr_name: str, ip_str: str, pkt_addr):
        # Determine family and possible scopeid from the packet that delivered this RR
        family = socket.AF_INET6 if ":" in ip_str else socket.AF_INET
        scopeid = None
        if isinstance(pkt_addr, tuple) and len(pkt_addr) == 4:  # IPv6 remote tuple
            scopeid = pkt_addr[3]
        iface = adapters.pick_iface_for_ip(ip_str, family, scopeid)
        if iface is None:
            return
        # avoid duplicates for the same host/ip
        existing = host_addrs[rr_name]
        if not any(a.ip == ip_str for a in existing):
            existing.append(Address(ip=ip_str, iface=iface))

    try:
        await _send_query_all(transports, build_query(service_type, QTYPE_PTR, unicast=False))
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            try:
                data, pkt_addr = await asyncio.wait_for(queue.get(), timeout=end - loop.time())
            except asyncio.TimeoutError:
                break
            for rr in parse_mdns_message(data):
                t = rr.get("type")
                if t == QTYPE_PTR and rr.get("name") == service_type:
                    ptr_targets.add(rr.get("ptrdname"))
                elif t == QTYPE_SRV:
                    srv_map[rr["name"]] = {
                        "target": rr.get("target"),
                        "port": rr.get("port"),
                    }
                elif t == QTYPE_TXT:
                    txt_map[rr["name"]] = rr.get("txt", {})
                elif (t == QTYPE_A and rr.get("address")) or (t == QTYPE_AAAA and rr.get("address")):
                    _record_addr(rr["name"], rr["address"], pkt_addr)
    finally:
        for transport, _ in transports:
            transport.close()

    # Assemble dataclasses
    results: list[ServiceInstance] = []
    for inst in sorted(ptr_targets):
        srv = srv_map.get(inst, {})
        target = srv.get("target")
        host = (target[:-1] if target and target.endswith(".") else target) or None
        addrs = host_addrs.get(target, []) if target else []
        props = txt_map.get(inst, {})
        results.append(
            ServiceInstance(
                instance=inst,
                host=host,
                port=srv.get("port"),
                addresses=addrs,
                properties=props,
            )
        )
    return results


async def browse_remoted(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[ServiceInstance]:
    return await browse_service(REMOTED_SERVICE_NAME, timeout=timeout)


async def browse_mobdev2(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[ServiceInstance]:
    return await browse_service(MOBDEV2_SERVICE_NAME, timeout=timeout)


async def browse_remotepairing(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[ServiceInstance]:
    return await browse_service(REMOTEPAIRING_SERVICE_NAME, timeout=timeout)


async def browse_remotepairing_manual_pairing(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[ServiceInstance]:
    return await browse_service(REMOTEPAIRING_MANUAL_PAIRING_SERVICE_NAME, timeout=timeout)
