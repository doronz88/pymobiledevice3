import asyncio
import base64
import binascii
import dataclasses
import hashlib
import json
import logging
import os
import platform
import plistlib
import secrets
import select
import ssl
import struct
import sys
from abc import ABC, abstractmethod
from asyncio import CancelledError, StreamReader, StreamWriter
from collections import namedtuple
from collections.abc import AsyncGenerator, Awaitable
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from socket import create_connection
from ssl import VerifyMode
from typing import Callable, Optional, TextIO, Union, cast

from construct import Const, Container, GreedyBytes, GreedyRange, Int8ul, Int16ub, Int64ul, Prefixed, Struct
from construct import Enum as ConstructEnum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from opack2 import dumps
from opack2 import loads as opack_loads
from packaging.version import Version
from pytun_pmd3 import TunTapDevice
from qh3.asyncio import QuicConnectionProtocol
from qh3.asyncio.client import connect as aioquic_connect
from qh3.asyncio.protocol import QuicStreamHandler
from qh3.quic import packet_builder
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.connection import QuicConnection
from qh3.quic.events import ConnectionTerminated, DatagramFrameReceived, QuicEvent, StreamDataReceived
from srptools import SRPClientSession, SRPContext, SRPServerSession
from srptools.constants import PRIME_3072, PRIME_3072_GEN
from srptools.utils import hex_from

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils

try:
    from sslpsk_pmd3.sslpsk import SSLPSKContext
except ImportError:
    SSLPSKContext = None

from pymobiledevice3.bonjour import (
    DEFAULT_BONJOUR_TIMEOUT,
    REMOTEPAIRING_PAIRABLE_HOST_SERVICE_NAME,
    MDNSResponder,
    browse_remotepairing,
)
from pymobiledevice3.ca import make_cert
from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    InvalidServiceError,
    PairingError,
    PyMobileDevice3Exception,
    QuicProtocolNotSupportedError,
    RemotePairingCompletedError,
    UserDeniedPairingError,
)
from pymobiledevice3.pair_records import (
    PAIRING_RECORD_EXT,
    create_pairing_records_cache_folder,
    generate_host_id,
    get_remote_pairing_record_filename,
    iter_remote_paired_identifiers,
)
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.siphash import compute_auth_tag
from pymobiledevice3.remote.utils import get_rsds, resume_remoted_if_required, stop_remoted_if_required
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.utils import asyncio_print_traceback

DEFAULT_INTERFACE_NAME = "pymobiledevice3-tunnel"
TIMEOUT = 1

OSUTIL = get_os_utils()
LOOPBACK_HEADER = OSUTIL.loopback_header
logger = logging.getLogger(__name__)

IPV6_HEADER_SIZE = 40
UDP_HEADER_SIZE = 8

# The iOS device uses an MTU of 1500, so we'll have to increase the default QUIC MTU
IOS_DEVICE_MTU_SIZE = 1500
packet_builder.PACKET_MAX_SIZE = IOS_DEVICE_MTU_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE

PairingDataComponentType = ConstructEnum(
    Int8ul,
    METHOD=0x00,
    IDENTIFIER=0x01,
    SALT=0x02,
    PUBLIC_KEY=0x03,
    PROOF=0x04,
    ENCRYPTED_DATA=0x05,
    STATE=0x06,
    ERROR=0x07,
    RETRY_DELAY=0x08,
    CERTIFICATE=0x09,
    SIGNATURE=0x0A,
    PERMISSIONS=0x0B,
    FRAGMENT_DATA=0x0C,
    FRAGMENT_LAST=0x0D,
    SESSION_ID=0x0E,
    TTL=0x0F,
    EXTRA_DATA=0x10,
    INFO=0x11,
    ACL=0x12,
    FLAGS=0x13,
    VALIDATION_DATA=0x14,
    MFI_AUTH_TOKEN=0x15,
    MFI_PRODUCT_TYPE=0x16,
    SERIAL_NUMBER=0x17,
    MFI_AUTH_TOKEN_UUID=0x18,
    APP_FLAGS=0x19,
    OWNERSHIP_PROOF=0x1A,
    SETUP_CODE_TYPE=0x1B,
    PRODUCTION_DATA=0x1C,
    APP_INFO=0x1D,
    SEPARATOR=0xFF,
)

PairingDataComponentTLV8 = Struct(
    "type" / PairingDataComponentType,
    "data" / Prefixed(Int8ul, GreedyBytes),
)

PairingDataComponentTLVBuf = GreedyRange(PairingDataComponentTLV8)

PairConsentResult = namedtuple("PairConsentResult", "public_key salt pin")

CDTunnelPacket = Struct(
    "magic" / Const(b"CDTunnel"),
    "body" / Prefixed(Int16ub, GreedyBytes),
)

REPAIRING_PACKET_MAGIC = b"RPPairing"

RPPairingPacket = Struct(
    "magic" / Const(REPAIRING_PACKET_MAGIC),
    "body" / Prefixed(Int16ub, GreedyBytes),
)

#: When True, :func:`create_tun_device` builds the tunnel's interface as a pure-Python
#: userspace stack (``UserspaceTun``, no root) instead of a kernel ``utun`` (needs root/admin).
#: The no-root establishment flow flips this on. Kept as a module-level flag so the tunnel
#: device is selected by an explicit factory call rather than by monkeypatching a class.
USE_USERSPACE_TUNNEL = False


def create_tun_device(interface_name: str = DEFAULT_INTERFACE_NAME):
    """Create the tunnel's link-layer device, consulting the user's kernel-vs-userspace choice.

    Default: a kernel :class:`pytun_pmd3.TunTapDevice` (requires root/admin). When
    :data:`USE_USERSPACE_TUNNEL` is set, a no-root userspace PyTCP stack. The userspace import
    is deferred so the optional PyTCP dependency is pulled in only when actually requested.
    """
    if USE_USERSPACE_TUNNEL:
        from pymobiledevice3.remote.userspace_tunnel import UserspaceTun

        return UserspaceTun(interface_name)
    if sys.platform == "win32":
        # Only the win32 TunTapDevice implementation accepts an interface name.
        return TunTapDevice(interface_name)
    return TunTapDevice()


class RemotePairingTunnel(ABC):
    def __init__(self):
        self._queue = asyncio.Queue()
        self._tun_read_task = None
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.tun = None

    @abstractmethod
    async def send_packet_to_device(self, packet: bytes) -> None:
        pass

    @abstractmethod
    async def request_tunnel_establish(self) -> dict:
        pass

    @abstractmethod
    async def wait_closed(self) -> None:
        pass

    @asyncio_print_traceback
    async def tun_read_task(self) -> None:
        read_size = self.tun.mtu + len(LOOPBACK_HEADER)
        try:
            if sys.platform == "win32":
                while True:
                    packet = await self.tun.async_read()
                    if packet:
                        if (packet[0] >> 4) != 6:
                            # Make sure to output only IPv6 packets
                            continue
                        await self.send_packet_to_device(packet)
            elif hasattr(self.tun, "fileno"):
                # Kernel tun (pytun): read via the event loop's readable callback rather than
                # a per-packet ``asyncio.to_thread`` hop. The thread-pool round-trip posts each
                # read result back through the loop's ready queue, so under a busy loop (e.g.
                # tunneld, which also runs the usb/wifi/usbmux/mobdev2 monitors and the HTTP
                # server) every packet's read completion queues behind those callbacks and the
                # upload collapses to a few MB/s. ``add_reader`` runs the read inline in the
                # loop with no cross-thread handoff. The fd is left blocking — the callback
                # only fires when it is readable, so a single ``os.read`` returns one queued
                # packet without blocking, and the reverse ``self.tun.write`` path (which shares
                # the fd) keeps its blocking semantics.
                await self._tun_read_loop_via_reader(read_size)
            else:
                # Userspace tun (no pollable fd): blocking read off the loop via a worker thread.
                while True:
                    packet = await asyncio.to_thread(self.tun.read, read_size)
                    assert packet.startswith(LOOPBACK_HEADER)
                    packet = packet[len(LOOPBACK_HEADER) :]
                    await self.send_packet_to_device(packet)
        except ConnectionResetError:
            self._logger.warning(f"got connection reset in {asyncio.current_task().get_name()}")
        except OSError:
            self._logger.warning(f"got oserror in {asyncio.current_task().get_name()}")

    async def _tun_read_loop_via_reader(self, read_size: int) -> None:
        loop = asyncio.get_running_loop()
        fd = self.tun.fileno()
        queue: asyncio.Queue = asyncio.Queue()

        def on_readable() -> None:
            # Drain every packet currently buffered on the fd in this one callback rather than
            # one per loop iteration. Under a busy loop (tunneld) the iteration rate is only a
            # few hundred/s, which would otherwise cap the relay regardless of link speed. The
            # fd stays blocking (the reverse self.tun.write path shares it); select(timeout=0)
            # reports whether another packet is ready so a read never blocks the loop.
            while True:
                try:
                    packet = os.read(fd, read_size)
                except (BlockingIOError, InterruptedError):
                    return
                except OSError:
                    queue.put_nowait(None)
                    return
                if not packet:
                    return
                queue.put_nowait(packet)
                if not select.select((fd,), (), (), 0)[0]:
                    return

        loop.add_reader(fd, on_readable)
        try:
            while True:
                # Block only when the queue is empty; once a packet arrives, drain the whole
                # backlog with get_nowait() before yielding again. ``await queue.get()`` yields
                # to the loop, and under a busy loop (tunneld) a reschedule costs milliseconds —
                # paying that per packet caps the relay at a few hundred packets/s. The reader
                # callback keeps filling the queue while we are suspended, so draining it in one
                # go amortises the reschedule across the whole burst.
                packet = await queue.get()
                while True:
                    if packet is None:
                        return
                    if packet.startswith(LOOPBACK_HEADER):
                        packet = packet[len(LOOPBACK_HEADER) :]
                    await self.send_packet_to_device(packet)
                    try:
                        packet = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
        finally:
            loop.remove_reader(fd)

    def start_tunnel(self, address: str, mtu: int, interface_name=DEFAULT_INTERFACE_NAME) -> None:
        self.tun = create_tun_device(interface_name)
        self.tun.addr = address
        self.tun.mtu = mtu
        self.tun.up()
        self._tun_read_task = asyncio.create_task(self.tun_read_task(), name=f"tun-read-{address}")

    async def stop_tunnel(self) -> None:
        self._logger.debug(f"[{asyncio.current_task().get_name()}] stopping tunnel")
        if self._tun_read_task is not None:
            self._tun_read_task.cancel()
            with suppress(CancelledError):
                await self._tun_read_task
        self._tun_read_task = None
        if self.tun is not None:
            self.tun.close()
        self.tun = None

    @staticmethod
    def _encode_cdtunnel_packet(data: dict) -> bytes:
        return CDTunnelPacket.build({"body": json.dumps(data).encode()})


class RemotePairingQuicTunnel(RemotePairingTunnel, QuicConnectionProtocol):
    MAX_QUIC_DATAGRAM = 14000
    MAX_IDLE_TIMEOUT = 30.0
    REQUESTED_MTU = 1420

    def __init__(self, quic: QuicConnection, stream_handler: Optional[QuicStreamHandler] = None):
        RemotePairingTunnel.__init__(self)
        QuicConnectionProtocol.__init__(self, quic, stream_handler)
        self._keep_alive_task = None

    async def wait_closed(self) -> None:
        with suppress(asyncio.CancelledError):
            await QuicConnectionProtocol.wait_closed(self)

    async def send_packet_to_device(self, packet: bytes) -> None:
        self._quic.send_datagram_frame(packet)
        self.transmit()

        # Allow other tasks to run
        await asyncio.sleep(0)

    async def request_tunnel_establish(self) -> dict:
        stream_id = self._quic.get_next_available_stream_id()
        # pad the data with random data to force the MTU size correctly
        self._quic.send_datagram_frame(b"x" * 1024)
        self._quic.send_stream_data(
            stream_id, self._encode_cdtunnel_packet({"type": "clientHandshakeRequest", "mtu": self.REQUESTED_MTU})
        )
        self.transmit()
        return await self._queue.get()

    @asyncio_print_traceback
    async def keep_alive_task(self) -> None:
        while True:
            await self.ping()
            await asyncio.sleep(self._quic.configuration.idle_timeout / 2)

    def start_tunnel(self, address: str, mtu: int, interface_name=DEFAULT_INTERFACE_NAME) -> None:
        super().start_tunnel(address, mtu, interface_name=interface_name)
        self._keep_alive_task = asyncio.create_task(self.keep_alive_task())

    async def stop_tunnel(self) -> None:
        self._keep_alive_task.cancel()
        with suppress(CancelledError):
            await self._keep_alive_task
        await super().stop_tunnel()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.close()
        elif isinstance(event, StreamDataReceived):
            self._queue.put_nowait(json.loads(CDTunnelPacket.parse(event.data).body))
        elif isinstance(event, DatagramFrameReceived):
            self.tun.write(LOOPBACK_HEADER + event.data)

    @staticmethod
    def _encode_cdtunnel_packet(data: dict) -> bytes:
        return CDTunnelPacket.build({"body": json.dumps(data).encode()})


class RemotePairingTcpTunnel(RemotePairingTunnel):
    REQUESTED_MTU = 16000

    def __init__(
        self,
        reader: Optional[StreamReader] = None,
        writer: Optional[StreamWriter] = None,
        service: Optional[ServiceConnection] = None,
    ):
        RemotePairingTunnel.__init__(self)
        self._reader = reader
        self._writer = writer
        self._service = service
        self._sock_read_task = None

    async def send_packet_to_device(self, packet: bytes) -> None:
        if self._writer is not None:
            self._writer.write(packet)
            await self._writer.drain()
            return
        if self._service is None:
            raise ConnectionError("missing writer/service for tcp tunnel")
        await self._service.sendall(packet)

    @asyncio_print_traceback
    async def sock_read_task(self) -> None:
        try:
            while True:
                try:
                    if self._reader is not None:
                        ipv6_header = await self._reader.readexactly(IPV6_HEADER_SIZE)
                        ipv6_length = struct.unpack(">H", ipv6_header[4:6])[0]
                        ipv6_body = await self._reader.readexactly(ipv6_length)
                    else:
                        ipv6_header = await self._service.recvall(IPV6_HEADER_SIZE)
                        ipv6_length = struct.unpack(">H", ipv6_header[4:6])[0]
                        ipv6_body = await self._service.recvall(ipv6_length)
                    self.tun.write(LOOPBACK_HEADER + ipv6_header + ipv6_body)
                except (asyncio.exceptions.IncompleteReadError, ConnectionTerminatedError):
                    return
        except OSError as e:
            self._logger.warning(f"got {e.__class__.__name__} in {asyncio.current_task().get_name()}")
            return

    async def wait_closed(self) -> None:
        if self._sock_read_task is asyncio.current_task():
            return
        if self._sock_read_task is not None:
            with suppress(asyncio.CancelledError):
                await self._sock_read_task
            return
        if self._writer is not None:
            with suppress(OSError):
                await self._writer.wait_closed()

    async def _recv_cdtunnel_packet_from_service(self) -> bytes:
        header = await self._service.recvall(10)
        payload_length = struct.unpack(">H", header[8:10])[0]
        return header + await self._service.recvall(payload_length)

    async def request_tunnel_establish(self) -> dict:
        payload = self._encode_cdtunnel_packet({"type": "clientHandshakeRequest", "mtu": self.REQUESTED_MTU})
        if self._writer is not None and self._reader is not None:
            self._writer.write(payload)
            await self._writer.drain()
            return json.loads(CDTunnelPacket.parse(await self._reader.read(self.REQUESTED_MTU)).body)
        if self._service is None:
            raise ConnectionError("missing writer/service for tcp tunnel")
        await self._service.sendall(payload)
        return json.loads(CDTunnelPacket.parse(await self._recv_cdtunnel_packet_from_service()).body)

    def start_tunnel(self, address: str, mtu: int, interface_name=DEFAULT_INTERFACE_NAME) -> None:
        super().start_tunnel(address, mtu, interface_name=interface_name)
        self._sock_read_task = asyncio.create_task(self.sock_read_task(), name=f"sock-read-task-{address}")

    async def stop_tunnel(self) -> None:
        if self._sock_read_task is not None and self._sock_read_task is not asyncio.current_task():
            self._sock_read_task.cancel()
            with suppress(CancelledError):
                await self._sock_read_task
        await super().stop_tunnel()
        if self._writer is None:
            if self._service is not None:
                with suppress(OSError):
                    await self._service.close()
            return
        if not self._writer.is_closing():
            self._writer.close()
            with suppress(OSError):
                await self._writer.wait_closed()


@dataclasses.dataclass
class TunnelResult:
    interface: str
    address: str
    port: int
    protocol: TunnelProtocol
    client: RemotePairingTunnel


class StartTcpTunnel(ABC):
    REQUESTED_MTU = 16000

    @property
    @abstractmethod
    def remote_identifier(self) -> str:
        pass

    @abstractmethod
    async def start_tcp_tunnel(self) -> AsyncGenerator[TunnelResult, None]:
        pass


class RemotePairingProtocol(StartTcpTunnel):
    WIRE_PROTOCOL_VERSION = 19

    def __init__(self):
        self.hostname: Optional[str] = None
        self._sequence_number = 0
        self._encrypted_sequence_number = 0
        self.version = None
        self.handshake_info = None
        self.x25519_private_key = X25519PrivateKey.generate()
        self.ed25519_private_key = Ed25519PrivateKey.generate()
        self.identifier = generate_host_id()
        self.srp_context = None
        self.encryption_key = None
        self.signature = None
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def close(self) -> None:
        pass

    @abstractmethod
    async def receive_response(self) -> dict:
        pass

    @abstractmethod
    async def send_request(self, data: dict) -> None:
        pass

    async def send_receive_request(self, data: dict) -> dict:
        await self.send_request(data)
        return await self.receive_response()

    async def connect(self, autopair: bool = True) -> None:
        await self._attempt_pair_verify()

        if await self._validate_pairing():
            # Pairing record validation succeeded, so we can just initiate the relevant session keys
            self._init_client_server_main_encryption_keys()
            return

        if autopair:
            await self._pair()
            await self.close()

            # Once pairing is completed, the remote endpoint closes the connection, so it must be re-established
            raise RemotePairingCompletedError()

    async def create_quic_listener(self, private_key: RSAPrivateKey) -> dict:
        request = {
            "request": {
                "_0": {
                    "createListener": {
                        "key": base64.b64encode(
                            private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                        ).decode(),
                        "peerConnectionsInfo": [{"owningPID": os.getpid(), "owningProcessName": "CoreDeviceService"}],
                        "transportProtocolType": "quic",
                    }
                }
            }
        }

        response = await self._send_receive_encrypted_request(request)
        return response["createListener"]

    async def create_tcp_listener(self) -> dict:
        request = {
            "request": {
                "_0": {
                    "createListener": {
                        "key": base64.b64encode(self.encryption_key).decode(),
                        "peerConnectionsInfo": [{"owningPID": os.getpid(), "owningProcessName": "CoreDeviceService"}],
                        "transportProtocolType": "tcp",
                    }
                }
            }
        }
        response = await self._send_receive_encrypted_request(request)
        return response["createListener"]

    @asynccontextmanager
    async def start_quic_tunnel(
        self,
        secrets_log_file: Optional[TextIO] = None,
        max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT,
    ) -> AsyncGenerator[TunnelResult, None]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        parameters = await self.create_quic_listener(private_key)
        cert = make_cert(private_key, private_key.public_key())
        configuration = QuicConfiguration(
            alpn_protocols=["RemotePairingTunnelProtocol"],
            is_client=True,
            verify_mode=VerifyMode.CERT_NONE,
            verify_hostname=False,
            max_datagram_frame_size=RemotePairingQuicTunnel.MAX_QUIC_DATAGRAM,
            idle_timeout=max_idle_timeout,
        )
        configuration.load_cert_chain(
            cert.public_bytes(Encoding.PEM),
            private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode(),
        )
        configuration.secrets_log_file = secrets_log_file

        host = self.hostname
        port = parameters["port"]

        self.logger.debug(f"Connecting to {host}:{port}")
        try:
            async with aioquic_connect(
                host,
                port,
                configuration=configuration,
                create_protocol=RemotePairingQuicTunnel,
            ) as client:
                self.logger.debug("quic connected")
                client = cast(RemotePairingQuicTunnel, client)
                await client.wait_connected()
                handshake_response = await client.request_tunnel_establish()
                client.start_tunnel(
                    handshake_response["clientParameters"]["address"],
                    handshake_response["clientParameters"]["mtu"],
                    interface_name=f"{DEFAULT_INTERFACE_NAME}-{self.remote_identifier}",
                )
                try:
                    yield TunnelResult(
                        client.tun.name,
                        handshake_response["serverAddress"],
                        handshake_response["serverRSDPort"],
                        TunnelProtocol.QUIC,
                        client,
                    )
                finally:
                    await client.stop_tunnel()
        except ConnectionError as e:
            raise QuicProtocolNotSupportedError(
                "iOS 18.2+ removed QUIC protocol support. Use TCP instead (requires python3.13+)"
            ) from e

    @asynccontextmanager
    async def start_tcp_tunnel(self) -> AsyncGenerator[TunnelResult, None]:
        parameters = await self.create_tcp_listener()
        host = self.hostname
        port = parameters["port"]
        sock = create_connection((host, port))
        OSUTIL.set_keepalive(sock)
        if sys.version_info >= (3, 13):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("PSK")
            ctx.set_psk_client_callback(lambda hint: (None, self.encryption_key))
        else:
            # TODO: remove this when python3.12 becomes deprecated
            ctx = SSLPSKContext(ssl.PROTOCOL_TLSv1_2)
            ctx.psk = self.encryption_key
            ctx.set_ciphers("PSK")
        try:
            reader, writer = await asyncio.open_connection(sock=sock, ssl=ctx, server_hostname="")
        except Exception:
            sock.close()
            raise
        tunnel = RemotePairingTcpTunnel(reader, writer)
        try:
            handshake_response = await tunnel.request_tunnel_establish()
            tunnel.start_tunnel(
                handshake_response["clientParameters"]["address"],
                handshake_response["clientParameters"]["mtu"],
                interface_name=f"{DEFAULT_INTERFACE_NAME}-{self.remote_identifier}",
            )
        except Exception:
            with suppress(Exception):
                await tunnel.stop_tunnel()
            raise

        try:
            yield TunnelResult(
                tunnel.tun.name,
                handshake_response["serverAddress"],
                handshake_response["serverRSDPort"],
                TunnelProtocol.TCP,
                tunnel,
            )
        finally:
            await tunnel.stop_tunnel()

    def save_pair_record(self) -> None:
        self.pair_record_path.write_bytes(
            plistlib.dumps({
                "public_key": self.ed25519_private_key.public_key().public_bytes_raw(),
                "private_key": self.ed25519_private_key.private_bytes_raw(),
                "remote_unlock_host_key": self.remote_unlock_host_key,
            })
        )
        OSUTIL.chown_to_non_sudo_if_needed(self.pair_record_path)

    @property
    def pair_record(self) -> Optional[dict]:
        if self.pair_record_path.exists():
            return plistlib.loads(self.pair_record_path.read_bytes())
        return None

    @property
    def remote_identifier(self) -> str:
        return self.handshake_info["peerDeviceInfo"]["identifier"]

    @property
    def remote_device_model(self) -> str:
        return self.handshake_info["peerDeviceInfo"]["model"]

    @property
    def pair_record_path(self) -> Path:
        pair_records_cache_directory = create_pairing_records_cache_folder()
        return (
            pair_records_cache_directory
            / f"{get_remote_pairing_record_filename(self.remote_identifier)}.{PAIRING_RECORD_EXT}"
        )

    async def _pair(self) -> None:
        pairing_consent_result = await self._request_pair_consent()
        self._init_srp_context(pairing_consent_result)
        await self._verify_proof()
        await self._save_pair_record_on_peer()
        self._init_client_server_main_encryption_keys()
        await self._create_remote_unlock()
        self.save_pair_record()

    async def _request_pair_consent(self) -> PairConsentResult:
        """Display a Trust / Don't Trust dialog"""

        tlv = PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.METHOD, "data": b"\x00"},
            {"type": PairingDataComponentType.STATE, "data": b"\x01"},
        ])

        await self._send_pairing_data({
            "data": tlv,
            "kind": "setupManualPairing",
            "sendingHost": platform.node(),
            "startNewSession": True,
        })
        self.logger.info("Waiting user pairing consent")
        response = await self._receive_plain_response()
        response = response["event"]["_0"]

        pin = None
        if "pairingRejectedWithError" in response:
            raise PairingError(
                response["pairingRejectedWithError"]["wrappedError"]["userInfo"]["NSLocalizedDescription"]
            )
        elif "awaitingUserConsent" in response:
            pairing_data = await self._receive_pairing_data()
        else:
            # On tvOS no consent is needed and pairing data is returned immediately.
            pairing_data = self._decode_bytes_if_needed(response["pairingData"]["_0"]["data"])
            # On tvOS we need pin to setup pairing.
            if "AppleTV" in self.remote_device_model:
                pin = input("Enter PIN: ")

        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(pairing_data))
        return PairConsentResult(
            public_key=data[PairingDataComponentType.PUBLIC_KEY], salt=data[PairingDataComponentType.SALT], pin=pin
        )

    def _init_srp_context(self, pairing_consent_result: PairConsentResult) -> None:
        # Receive server public and salt and process them.
        pin = pairing_consent_result.pin or "000000"
        client_session = SRPClientSession(
            SRPContext("Pair-Setup", password=pin, prime=PRIME_3072, generator=PRIME_3072_GEN, hash_func=hashlib.sha512)
        )
        client_session.process(pairing_consent_result.public_key.hex(), pairing_consent_result.salt.hex())
        self.srp_context = client_session
        self.encryption_key = binascii.unhexlify(self.srp_context.key)

    async def _verify_proof(self) -> None:
        client_public = binascii.unhexlify(self.srp_context.public)
        client_session_key_proof = binascii.unhexlify(self.srp_context.key_proof)

        tlv = PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.STATE, "data": b"\x03"},
            {"type": PairingDataComponentType.PUBLIC_KEY, "data": client_public[:255]},
            {"type": PairingDataComponentType.PUBLIC_KEY, "data": client_public[255:]},
            {"type": PairingDataComponentType.PROOF, "data": client_session_key_proof},
        ])

        response = await self._send_receive_pairing_data({
            "data": tlv,
            "kind": "setupManualPairing",
            "sendingHost": platform.node(),
            "startNewSession": False,
        })
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))
        assert self.srp_context.verify_proof(data[PairingDataComponentType.PROOF].hex().encode())

    async def _save_pair_record_on_peer(self) -> dict:
        # HKDF with above computed key (SRP_compute_key) + Pair-Setup-Encrypt-Salt + Pair-Setup-Encrypt-Info
        # result used as key for chacha20-poly1305
        setup_encryption_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Setup-Encrypt-Salt",
            info=b"Pair-Setup-Encrypt-Info",
        ).derive(self.encryption_key)

        self.ed25519_private_key = Ed25519PrivateKey.generate()

        # HKDF with above computed key:
        #   (SRP_compute_key) + Pair-Setup-Controller-Sign-Salt + Pair-Setup-Controller-Sign-Info
        signbuf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Setup-Controller-Sign-Salt",
            info=b"Pair-Setup-Controller-Sign-Info",
        ).derive(self.encryption_key)

        signbuf += self.identifier.encode()
        signbuf += self.ed25519_private_key.public_key().public_bytes_raw()

        self.signature = self.ed25519_private_key.sign(signbuf)

        device_info = dumps({
            "altIRK": b"\xe9\xe8-\xc0jIykVoT\x00\x19\xb1\xc7{",
            "btAddr": "11:22:33:44:55:66",
            "mac": b"\x11\x22\x33\x44\x55\x66",
            "remotepairing_serial_number": "AAAAAAAAAAAA",
            "accountID": self.identifier,
            "model": "computer-model",
            "name": platform.node(),
        })

        tlv = PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.IDENTIFIER, "data": self.identifier.encode()},
            {
                "type": PairingDataComponentType.PUBLIC_KEY,
                "data": self.ed25519_private_key.public_key().public_bytes_raw(),
            },
            {"type": PairingDataComponentType.SIGNATURE, "data": self.signature},
            {"type": PairingDataComponentType.INFO, "data": device_info},
        ])

        cip = ChaCha20Poly1305(setup_encryption_key)
        encrypted_data = cip.encrypt(b"\x00\x00\x00\x00PS-Msg05", tlv, b"")

        tlv = PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.ENCRYPTED_DATA, "data": encrypted_data[:255]},
            {"type": PairingDataComponentType.ENCRYPTED_DATA, "data": encrypted_data[255:]},
            {"type": PairingDataComponentType.STATE, "data": b"\x05"},
        ])

        response = await self._send_receive_pairing_data({
            "data": tlv,
            "kind": "setupManualPairing",
            "sendingHost": platform.node(),
            "startNewSession": False,
        })
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        tlv = PairingDataComponentTLVBuf.parse(
            cip.decrypt(b"\x00\x00\x00\x00PS-Msg06", data[PairingDataComponentType.ENCRYPTED_DATA], b"")
        )

        return tlv

    def _init_client_server_main_encryption_keys(self) -> None:
        client_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b"ClientEncrypt-main",
        ).derive(self.encryption_key)
        self.client_cip = ChaCha20Poly1305(client_key)

        server_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b"ServerEncrypt-main",
        ).derive(self.encryption_key)
        self.server_cip = ChaCha20Poly1305(server_key)

    async def _create_remote_unlock(self) -> None:
        try:
            response = await self._send_receive_encrypted_request({"request": {"_0": {"createRemoteUnlockKey": {}}}})
            self.remote_unlock_host_key = response["createRemoteUnlockKey"]["hostKey"]
        except PyMobileDevice3Exception:
            # tvOS does not support remote unlock.
            self.remote_unlock_host_key = ""

    async def _attempt_pair_verify(self) -> None:
        self.handshake_info = await self._send_receive_handshake({
            "hostOptions": {"attemptPairVerify": True},
            "wireProtocolVersion": XpcInt64Type(self.WIRE_PROTOCOL_VERSION),
        })

    @staticmethod
    def _decode_bytes_if_needed(data: bytes) -> bytes:
        return data

    async def _validate_pairing(self) -> bool:
        pairing_data = PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.STATE, "data": b"\x01"},
            {
                "type": PairingDataComponentType.PUBLIC_KEY,
                "data": self.x25519_private_key.public_key().public_bytes_raw(),
            },
        ])
        response = await self._send_receive_pairing_data({
            "data": pairing_data,
            "kind": "verifyManualPairing",
            "startNewSession": True,
        })
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        if PairingDataComponentType.ERROR in data:
            await self._send_pair_verify_failed()
            return False

        peer_public_key = X25519PublicKey.from_public_bytes(data[PairingDataComponentType.PUBLIC_KEY])
        self.encryption_key = self.x25519_private_key.exchange(peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Verify-Encrypt-Salt",
            info=b"Pair-Verify-Encrypt-Info",
        ).derive(self.encryption_key)
        cip = ChaCha20Poly1305(derived_key)

        # TODO:
        #   we should be able to verify from the received encrypted data, but from some reason we failed to
        #   do so. instead, we verify using the next stage

        if self.pair_record is None:
            private_key = Ed25519PrivateKey.from_private_bytes(b"\x00" * 0x20)
        else:
            private_key = Ed25519PrivateKey.from_private_bytes(self.pair_record["private_key"])
            # A device-initiated pairing record stores the identifier the host registered
            # itself under; present that same identifier during pair-verify so the device
            # recognizes us instead of re-prompting.
            host_identifier = self.pair_record.get("host_identifier")
            if host_identifier:
                self.identifier = host_identifier

        signbuf = b""
        signbuf += self.x25519_private_key.public_key().public_bytes_raw()
        signbuf += self.identifier.encode()
        signbuf += peer_public_key.public_bytes_raw()

        signature = private_key.sign(signbuf)

        encrypted_data = cip.encrypt(
            b"\x00\x00\x00\x00PV-Msg03",
            PairingDataComponentTLVBuf.build([
                {"type": PairingDataComponentType.IDENTIFIER, "data": self.identifier.encode()},
                {"type": PairingDataComponentType.SIGNATURE, "data": signature},
            ]),
            b"",
        )

        pairing_data = PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.STATE, "data": b"\x03"},
            {"type": PairingDataComponentType.ENCRYPTED_DATA, "data": encrypted_data},
        ])

        response = await self._send_receive_pairing_data({
            "data": pairing_data,
            "kind": "verifyManualPairing",
            "startNewSession": False,
        })
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        if PairingDataComponentType.ERROR in data:
            await self._send_pair_verify_failed()
            return False

        return True

    async def _send_pair_verify_failed(self) -> None:
        await self._send_plain_request({"event": {"_0": {"pairVerifyFailed": {}}}})

    async def _send_receive_encrypted_request(self, request: dict) -> dict:
        nonce = Int64ul.build(self._encrypted_sequence_number) + b"\x00" * 4
        encrypted_data = self.client_cip.encrypt(nonce, json.dumps(request).encode(), b"")

        response = await self.send_receive_request({
            "message": {"streamEncrypted": {"_0": encrypted_data}},
            "originatedBy": "host",
            "sequenceNumber": XpcUInt64Type(self._sequence_number),
        })
        self._encrypted_sequence_number += 1

        encrypted_data = self._decode_bytes_if_needed(response["message"]["streamEncrypted"]["_0"])
        plaintext = self.server_cip.decrypt(nonce, encrypted_data, None)
        response = json.loads(plaintext)["response"]["_1"]

        if "errorExtended" in response:
            raise PyMobileDevice3Exception(response["errorExtended"]["_0"]["userInfo"]["NSLocalizedDescription"])

        return response

    async def _send_receive_handshake(self, handshake_data: dict) -> dict:
        response = await self._send_receive_plain_request({"request": {"_0": {"handshake": {"_0": handshake_data}}}})
        return response["response"]["_1"]["handshake"]["_0"]

    async def _send_receive_pairing_data(self, pairing_data: dict) -> bytes:
        await self._send_pairing_data(pairing_data)
        return await self._receive_pairing_data()

    async def _send_pairing_data(self, pairing_data: dict) -> None:
        await self._send_plain_request({"event": {"_0": {"pairingData": {"_0": pairing_data}}}})

    async def _receive_pairing_data(self) -> bytes:
        response = await self._receive_plain_response()
        response = response["event"]["_0"]
        if "pairingData" in response:
            return self._decode_bytes_if_needed(response["pairingData"]["_0"]["data"])
        if "pairingRejectedWithError" in response:
            raise UserDeniedPairingError(
                response["pairingRejectedWithError"]
                .get("wrappedError", {})
                .get("userInfo", {})
                .get("NSLocalizedDescription")
            )
        raise PyMobileDevice3Exception(f"Got an unknown state message: {response}")

    async def _send_receive_plain_request(self, plain_request: dict):
        await self._send_plain_request(plain_request)
        return await self._receive_plain_response()

    async def _send_plain_request(self, plain_request: dict) -> None:
        await self.send_request({
            "message": {"plain": {"_0": plain_request}},
            "originatedBy": "host",
            "sequenceNumber": XpcUInt64Type(self._sequence_number),
        })
        self._sequence_number += 1

    async def _receive_plain_response(self) -> dict:
        response = await self.receive_response()
        return response["message"]["plain"]["_0"]

    @staticmethod
    def decode_tlv(tlv_list: list[Container]) -> dict:
        result = {}
        for tlv in tlv_list:
            if tlv.type in result:
                result[tlv.type] += tlv.data
            else:
                result[tlv.type] = tlv.data
        return result

    async def __aenter__(self) -> "CoreDeviceTunnelService":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


class CoreDeviceTunnelService(RemotePairingProtocol, RemoteService):
    SERVICE_NAME = "com.apple.internal.dt.coredevice.untrusted.tunnelservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        RemoteService.__init__(self, rsd, self.SERVICE_NAME)
        RemotePairingProtocol.__init__(self)
        self.version: Optional[int] = None

    async def connect(self, autopair: bool = True) -> None:
        # Establish RemoteXPC connection to `SERVICE_NAME`
        await RemoteService.connect(self)
        try:
            response = await self.service.receive_response()
            self.version = response["ServiceVersion"]

            # Perform pairing if necessary and start a trusted RemoteXPC connection
            await RemotePairingProtocol.connect(self, autopair=autopair)
            self.hostname = self.service.address[0]
        except Exception:
            await self.service.close()
            raise

    async def close(self) -> None:
        await self.rsd.close()
        if self.service is not None:
            await self.service.close()

    async def receive_response(self) -> dict:
        response = await self.service.receive_response()
        return response["value"]

    async def send_request(self, data: dict) -> None:
        return await self.service.send_request({
            "mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope",
            "value": data,
        })


class RemotePairingTunnelService(RemotePairingProtocol):
    def __init__(self, remote_identifier: str, hostname: str, port: int) -> None:
        RemotePairingProtocol.__init__(self)
        self._remote_identifier = remote_identifier
        self.hostname = hostname
        self.port = port
        self._reader: Optional[StreamReader] = None
        self._writer: Optional[StreamWriter] = None

    @property
    def remote_identifier(self) -> str:
        return self._remote_identifier

    async def connect(self, autopair: bool = True) -> None:
        connect_task = asyncio.create_task(asyncio.open_connection(self.hostname, self.port))
        try:
            self._reader, self._writer = await asyncio.wait_for(connect_task, timeout=TIMEOUT)
        except BaseException:
            if not connect_task.done():
                connect_task.cancel()
                with suppress(asyncio.CancelledError):
                    await connect_task
            await self.close()
            raise

        try:
            await self._attempt_pair_verify()
            if not await self._validate_pairing():
                raise ConnectionTerminatedError()
            self._init_client_server_main_encryption_keys()
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        if self._writer is None:
            return
        self._writer.close()
        with suppress(ssl.SSLError):
            await self._writer.wait_closed()
        self._writer = None
        self._reader = None

    async def receive_response(self) -> dict:
        await self._reader.readexactly(len(REPAIRING_PACKET_MAGIC))
        size = struct.unpack(">H", await self._reader.readexactly(2))[0]
        return json.loads(await self._reader.readexactly(size))

    async def send_request(self, data: dict) -> None:
        self._writer.write(
            RPPairingPacket.build({"body": json.dumps(data, default=self._default_json_encoder).encode()})
        )
        await self._writer.drain()

    @staticmethod
    def _default_json_encoder(obj) -> str:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        raise TypeError()

    @staticmethod
    def _decode_bytes_if_needed(data: bytes) -> bytes:
        return base64.b64decode(data)

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} IDENTIFIER:{self.remote_identifier} HOSTNAME:{self.hostname} PORT:{self.port}>"
        )


class RemotePairingManualPairingService(RemotePairingTunnelService):
    async def connect(self, autopair: bool = True) -> None:
        fut = asyncio.open_connection(self.hostname, self.port)
        self._reader, self._writer = await asyncio.wait_for(fut, timeout=TIMEOUT)
        await RemotePairingProtocol.connect(self, autopair=autopair)


class CoreDeviceTunnelProxy(StartTcpTunnel):
    SERVICE_NAME = "com.apple.internal.devicecompute.CoreDeviceProxy"

    @classmethod
    async def create(cls, lockdown: LockdownServiceProvider) -> "CoreDeviceTunnelProxy":
        return cls(await lockdown.start_lockdown_service(cls.SERVICE_NAME), lockdown.udid)

    def __init__(self, service: ServiceConnection, remote_identifier: str) -> None:
        self._service: ServiceConnection = service
        self._remote_identifier: str = remote_identifier

    @property
    def remote_identifier(self) -> str:
        return self._remote_identifier

    @asynccontextmanager
    async def start_tcp_tunnel(self) -> AsyncGenerator["TunnelResult", None]:
        assert self._service is not None, "service must be connected first"
        tunnel = RemotePairingTcpTunnel(service=self._service)
        try:
            handshake_response = await tunnel.request_tunnel_establish()
            tunnel.start_tunnel(
                handshake_response["clientParameters"]["address"],
                handshake_response["clientParameters"]["mtu"],
                interface_name=f"{DEFAULT_INTERFACE_NAME}-{self.remote_identifier}",
            )
        except Exception:
            with suppress(Exception):
                await tunnel.stop_tunnel()
            raise
        try:
            yield TunnelResult(
                tunnel.tun.name,
                handshake_response["serverAddress"],
                handshake_response["serverRSDPort"],
                TunnelProtocol.TCP,
                tunnel,
            )
        finally:
            await tunnel.stop_tunnel()

    async def close(self) -> None:
        if self._service is not None:
            await self._service.close()


async def create_core_device_tunnel_service_using_rsd(
    rsd: RemoteServiceDiscoveryService, autopair: bool = True
) -> CoreDeviceTunnelService:
    service = CoreDeviceTunnelService(rsd)
    try:
        await service.connect(autopair=autopair)
    except RemotePairingCompletedError:
        # The connection must be reestablished upon pairing is completed
        await service.close()
        service = CoreDeviceTunnelService(rsd)
        await service.connect(autopair=autopair)
    except Exception:
        await service.close()
        raise
    return service


async def create_core_device_tunnel_service_using_remotepairing(
    remote_identifier: str, hostname: str, port: int, autopair: bool = True
) -> RemotePairingTunnelService:
    service = RemotePairingTunnelService(remote_identifier, hostname, port)
    try:
        await service.connect(autopair=autopair)
    except Exception:
        await service.close()
        raise
    return service


async def create_core_device_service_using_remotepairing_manual_pairing(
    remote_identifier: str, hostname: str, port: int, autopair: bool = True
) -> RemotePairingTunnelService:
    service = RemotePairingManualPairingService(remote_identifier, hostname, port)
    await service.connect(autopair=autopair)
    return service


@asynccontextmanager
async def start_tunnel_over_remotepairing(
    remote_pairing: RemotePairingTunnelService,
    secrets: Optional[TextIO] = None,
    max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT,
    protocol: TunnelProtocol = TunnelProtocol.QUIC,
) -> AsyncGenerator[TunnelResult, None]:
    async with remote_pairing:
        if protocol == TunnelProtocol.QUIC:
            async with remote_pairing.start_quic_tunnel(
                secrets_log_file=secrets, max_idle_timeout=max_idle_timeout
            ) as tunnel_result:
                yield tunnel_result
        elif protocol == TunnelProtocol.TCP:
            async with remote_pairing.start_tcp_tunnel() as tunnel_result:
                yield tunnel_result


@asynccontextmanager
async def start_tunnel_over_core_device(
    service_provider: CoreDeviceTunnelService,
    secrets: Optional[TextIO] = None,
    max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT,
    protocol: TunnelProtocol = TunnelProtocol.QUIC,
) -> AsyncGenerator[TunnelResult, None]:
    stop_remoted_if_required()
    async with service_provider:
        if protocol == TunnelProtocol.QUIC:
            async with service_provider.start_quic_tunnel(
                secrets_log_file=secrets, max_idle_timeout=max_idle_timeout
            ) as tunnel_result:
                resume_remoted_if_required()
                yield tunnel_result
        elif protocol == TunnelProtocol.TCP:
            async with service_provider.start_tcp_tunnel() as tunnel_result:
                resume_remoted_if_required()
                yield tunnel_result


@asynccontextmanager
async def start_tunnel(
    protocol_handler: RemotePairingProtocol,
    secrets: Optional[TextIO] = None,
    max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT,
    protocol: TunnelProtocol = TunnelProtocol.DEFAULT,
) -> AsyncGenerator[TunnelResult, None]:
    if isinstance(protocol_handler, CoreDeviceTunnelService):
        async with start_tunnel_over_core_device(
            protocol_handler, secrets=secrets, max_idle_timeout=max_idle_timeout, protocol=protocol
        ) as service:
            yield service
    elif isinstance(protocol_handler, RemotePairingTunnelService):
        async with start_tunnel_over_remotepairing(
            protocol_handler, secrets=secrets, max_idle_timeout=max_idle_timeout, protocol=protocol
        ) as service:
            yield service
    elif isinstance(protocol_handler, CoreDeviceTunnelProxy):
        if protocol != TunnelProtocol.TCP:
            raise ValueError("CoreDeviceTunnelProxy protocol can only be TCP")
        async with protocol_handler.start_tcp_tunnel() as service:
            yield service
    else:
        raise TypeError(f"Bad value for protocol_handler: {protocol_handler}")


async def get_core_device_tunnel_services(
    bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT, udid: Optional[str] = None
) -> list[CoreDeviceTunnelService]:
    result = []
    for rsd in await get_rsds(bonjour_timeout=bonjour_timeout, udid=udid):
        if udid is None and (
            (Version(rsd.product_version) < Version("17.0")) and not rsd.product_type.startswith("RealityDevice")
        ):
            logger.debug(f"Skipping {rsd.udid}:, iOS {rsd.product_version} < 17.0")
            await rsd.close()
            continue
        try:
            result.append(await create_core_device_tunnel_service_using_rsd(rsd))
        except InvalidServiceError as e:
            logger.debug(f"Skipping {rsd.udid}: {e}")
            await rsd.close()
            continue
        except (
            ConnectionTerminatedError,
            asyncio.IncompleteReadError,
            ConnectionResetError,
            asyncio.TimeoutError,
            OSError,
        ) as e:
            logger.debug("Skipping CoreDevice tunnel service %s: %r", rsd.udid, e)
            await rsd.close()
            continue
        except Exception:
            logger.exception(f"Failed to start service: {rsd}")
            await rsd.close()
            raise
    return result


async def get_remote_pairing_tunnel_services(
    bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT, udid: Optional[str] = None
) -> list[RemotePairingTunnelService]:
    result = []
    for answer in await browse_remotepairing(timeout=bonjour_timeout):
        for address in answer.addresses:
            for identifier in iter_remote_paired_identifiers():
                if udid is not None and identifier != udid:
                    continue
                conn = None
                try:
                    conn = await create_core_device_tunnel_service_using_remotepairing(
                        identifier, address.full_ip, answer.port
                    )
                    result.append(conn)
                    break
                except (
                    ConnectionTerminatedError,
                    asyncio.IncompleteReadError,
                    ConnectionResetError,
                    asyncio.TimeoutError,
                ) as e:
                    if conn is not None:
                        await conn.close()
                    logger.debug(
                        "Skipping remote pairing service %s@%s:%s: %r",
                        identifier,
                        address.full_ip,
                        answer.port,
                        e,
                    )
                    continue
                except OSError:
                    if conn is not None:
                        await conn.close()
                    continue
    return result


# ---------------- Device-initiated pairing (pairable host / responder) ----------------

# SRP password username used by Apple's Pair-Setup. Both sides hash with it.
SRP_USERNAME = "Pair-Setup"
# 3072-bit SRP -> public values are 384 bytes
SRP_PUBLIC_KEY_SIZE = 384
# TLV component data is length-prefixed with a single byte
TLV_MAX_FRAGMENT_SIZE = 0xFF

PinCallback = Callable[[str], Union[None, Awaitable[None]]]


@dataclasses.dataclass
class PairableHostResult:
    """Outcome of a successful device-initiated pairing accepted by :func:`serve_pairable_host`."""

    peer_device: "PeerDeviceInfo"
    record_path: Path


@dataclasses.dataclass
class PeerDeviceInfo:
    """Identity of a device that paired into us, parsed from the M5 identity payload."""

    account_id: str
    alt_irk: bytes
    model: str
    name: str
    udid: str

    @classmethod
    def from_info_dict(cls, info: dict) -> "PeerDeviceInfo":
        alt_irk = info.get("altIRK")
        if not isinstance(alt_irk, bytes) or len(alt_irk) != 16:
            raise PairingError(f"invalid altIRK in peer device info: {alt_irk!r}")
        try:
            return cls(
                account_id=info["accountID"],
                alt_irk=alt_irk,
                model=info["model"],
                name=info["name"],
                udid=info.get("remotepairing_udid", ""),
            )
        except KeyError as e:
            raise PairingError(f"missing field {e} in peer device info") from e


@dataclasses.dataclass
class PairableHostInfo:
    """
    Static information a pairable host advertises over mDNS and presents to a
    connecting device.

    ``name`` and ``model`` are what the device shows to the user. iOS treats the
    host as a computer, so keep ``model`` a Mac identifier (e.g. ``Mac17,7``).
    ``alt_irk`` is the 16-byte mDNS identity key; it is sent to the device during
    pairing (M6) and is used to derive the ``authTag`` advertised over mDNS so an
    already-paired device can recognize this host. Persist it (alongside the
    pairing record) so reconnecting devices keep working.

    ``identifier`` defaults to the deterministic :func:`generate_host_id` (this
    host's stable id, same one the host-initiated flow uses). Note the device keys
    its known peers by this identifier: a device that has *already* paired with
    this host recognizes the id and reconnects silently (pair-*verify*) instead of
    prompting for a new pairing. To deliberately pair as a brand-new host, pass a
    fresh random ``identifier`` (e.g. ``str(uuid.uuid4()).upper()``).
    """

    name: str
    model: str = "Mac17,7"
    udid: str = ""
    identifier: str = dataclasses.field(default_factory=generate_host_id)
    wire_protocol_version: int = 26
    alt_irk: bytes = dataclasses.field(default_factory=lambda: secrets.token_bytes(16))

    def mdns_txt_records(self) -> dict[str, str]:
        """Build the TXT records to publish for the pairable-host mDNS service."""
        auth_tag = base64.b64encode(compute_auth_tag(self.alt_irk, self.identifier)).decode()
        return {
            "name": self.name,
            "identifier": self.identifier,
            "authTag": auth_tag,
            "model": self.model,
            "flags": "1",
            "ver": str(self.wire_protocol_version),
            "minVer": "17",
        }


class PairableHost:
    """
    The responder side of rppairing: accepts a device-initiated pairing.

    The device plays the rppairing "host" (it initiates the handshake and SRP
    pair-setup and sends ``originatedBy: "host"``); this class plays the
    accessory/responder (``originatedBy: "device"``). We generate and display the
    6-digit setup code; the user types it into the device.
    """

    def __init__(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        host_info: PairableHostInfo,
        ed25519_private_key: Optional[Ed25519PrivateKey] = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.host_info = host_info
        self.ed25519_private_key = ed25519_private_key or Ed25519PrivateKey.generate()
        self._sequence_number = 0
        self.encryption_key: Optional[bytes] = None
        self.peer_device: Optional[PeerDeviceInfo] = None
        self.logger = logging.getLogger(self.__class__.__name__)

    async def accept(self, pin_callback: Optional[PinCallback] = None) -> PeerDeviceInfo:
        """Perform the handshake and the full SRP pair-setup (M1 - M6)."""
        await self._handshake()
        return await self._pair_setup(pin_callback)

    async def _handshake(self) -> None:
        self.logger.debug("Waiting for device handshake request")
        request = await self._receive_plain()
        try:
            handshake = request["request"]["_0"]["handshake"]["_0"]
        except (KeyError, TypeError) as e:
            raise PairingError(f"missing request._0.handshake._0 in device handshake: {request}") from e

        if handshake.get("hostOptions", {}).get("attemptPairVerify"):
            raise PairingError("device requested pair-verify; only device-initiated pair-setup is supported")

        peer_device_info = {
            "udid": self.host_info.udid,
            "deviceKVSIncludesSensitiveInfo": False,
            "identifier": self.host_info.identifier,
            "name": self.host_info.name,
            "model": self.host_info.model,
        }
        await self._send_plain({
            "response": {
                "forRequestIdentifier": 0,
                "_1": {
                    "handshake": {
                        "_0": {
                            "wireProtocolVersion": XpcInt64Type(self.host_info.wire_protocol_version),
                            "minimumSupportedWireProtocolVersion": XpcInt64Type(8),
                            "deviceOptions": {
                                "allowsPairSetup": True,
                                "allowsPinlessPairing": False,
                                "allowsIncomingTunnelConnections": False,
                                "allowsUpgradeOfLockdownPairings": False,
                                "allowsSharingSensitiveInfo": False,
                            },
                            "peerDeviceInfo": peer_device_info,
                        }
                    }
                },
            }
        })

    async def _pair_setup(self, pin_callback: Optional[PinCallback]) -> PeerDeviceInfo:
        # M1: device starts pair-setup
        self.logger.debug("Waiting for pair-setup M1")
        m1 = self.decode_tlv(PairingDataComponentTLVBuf.parse(await self._receive_pairing_data()))
        self._expect_state(m1, 1)

        # M2: send salt + server public (B)
        salt = bytearray(secrets.token_bytes(16))
        salt[0] |= 0x80  # keep a stable 16-byte / even-hex representation
        salt = bytes(salt)
        salt_hex = salt.hex()

        pin = f"{secrets.randbelow(1_000_000):06d}"
        context = SRPContext(
            SRP_USERNAME, password=pin, prime=PRIME_3072, generator=PRIME_3072_GEN, hash_func=hashlib.sha512
        )
        verifier = hex_from(context.get_common_password_verifier(context.get_common_password_hash(int(salt_hex, 16))))

        # B is computed from a fresh random server private; regenerate on the rare short value
        while True:
            srp_server = SRPServerSession(context, verifier)
            server_public = binascii.unhexlify(srp_server.public)
            if len(server_public) == SRP_PUBLIC_KEY_SIZE:
                break

        await self._display_pin(pin, pin_callback)

        tlv = [
            {"type": PairingDataComponentType.STATE, "data": b"\x02"},
            {"type": PairingDataComponentType.SALT, "data": salt},
        ]
        tlv += self._chunk_component(PairingDataComponentType.PUBLIC_KEY, server_public)
        self.logger.debug("Sending pair-setup M2 (salt + B)")
        await self._send_pairing_data(PairingDataComponentTLVBuf.build(tlv))

        # M3: device sends its public (A) and proof (M1)
        self.logger.debug("Waiting for pair-setup M3")
        m3 = self.decode_tlv(PairingDataComponentTLVBuf.parse(await self._receive_pairing_data()))
        self._ensure_no_error(m3)
        self._expect_state(m3, 3)
        client_public = m3.get(PairingDataComponentType.PUBLIC_KEY)
        client_proof = m3.get(PairingDataComponentType.PROOF)
        if not client_public or not client_proof:
            raise PairingError("pair-setup M3 missing public key or proof")

        srp_server.process(client_public.hex(), salt_hex)
        # srptools compares against value_encode() output (a hex *bytes* object), so the proof
        # must be passed as hexlify() bytes rather than a str.
        if not srp_server.verify_proof(binascii.hexlify(client_proof)):
            self.logger.warning("SRP client proof verification failed (wrong PIN?)")
            await self._send_pairing_data(
                PairingDataComponentTLVBuf.build([
                    {"type": PairingDataComponentType.STATE, "data": b"\x04"},
                    {"type": PairingDataComponentType.ERROR, "data": b"\x02"},  # kTLVError_Authentication
                ])
            )
            raise PairingError("SRP authentication failed (wrong PIN?)")

        session_key = binascii.unhexlify(srp_server.key)

        # M4: send server proof
        self.logger.debug("Sending pair-setup M4 (server proof)")
        await self._send_pairing_data(
            PairingDataComponentTLVBuf.build([
                {"type": PairingDataComponentType.STATE, "data": b"\x04"},
                {"type": PairingDataComponentType.PROOF, "data": binascii.unhexlify(srp_server.key_proof_hash)},
            ])
        )

        setup_encryption_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Setup-Encrypt-Salt",
            info=b"Pair-Setup-Encrypt-Info",
        ).derive(session_key)
        cip = ChaCha20Poly1305(setup_encryption_key)

        # M5: device sends its encrypted identity
        self.logger.debug("Waiting for pair-setup M5 (device identity)")
        m5 = self.decode_tlv(PairingDataComponentTLVBuf.parse(await self._receive_pairing_data()))
        self._ensure_no_error(m5)
        self._expect_state(m5, 5)
        plaintext = cip.decrypt(b"\x00\x00\x00\x00PS-Msg05", m5[PairingDataComponentType.ENCRYPTED_DATA], b"")
        device_tlv = self.decode_tlv(PairingDataComponentTLVBuf.parse(plaintext))
        peer_device = PeerDeviceInfo.from_info_dict(opack_loads(device_tlv[PairingDataComponentType.INFO]))

        # M6: send our (accessory) encrypted identity
        self.logger.debug("Sending pair-setup M6 (our identity)")
        m6_plain = self._build_accessory_identity_tlv(session_key)
        m6_cipher = cip.encrypt(b"\x00\x00\x00\x00PS-Msg06", m6_plain, b"")
        tlv = self._chunk_component(PairingDataComponentType.ENCRYPTED_DATA, m6_cipher)
        tlv.append({"type": PairingDataComponentType.STATE, "data": b"\x06"})
        await self._send_pairing_data(PairingDataComponentTLVBuf.build(tlv))

        self.encryption_key = session_key
        self.peer_device = peer_device
        return peer_device

    def _build_accessory_identity_tlv(self, session_key: bytes) -> bytes:
        # Accessory signature: Ed25519 over (AccessoryX || identifier || LTPK)
        accessory_x = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Setup-Accessory-Sign-Salt",
            info=b"Pair-Setup-Accessory-Sign-Info",
        ).derive(session_key)
        ltpk = self.ed25519_private_key.public_key().public_bytes_raw()
        signbuf = accessory_x + self.host_info.identifier.encode() + ltpk
        signature = self.ed25519_private_key.sign(signbuf)

        info = dumps({
            "altIRK": self.host_info.alt_irk,
            "btAddr": "11:22:33:44:55:66",
            "mac": b"\x11\x22\x33\x44\x55\x66",
            "remotepairing_serial_number": "AAAAAAAAAAAA",
            "accountID": self.host_info.identifier,
            "remotepairing_udid": self.host_info.udid,
            "model": self.host_info.model,
            "name": self.host_info.name,
        })

        return PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.IDENTIFIER, "data": self.host_info.identifier.encode()},
            {"type": PairingDataComponentType.PUBLIC_KEY, "data": ltpk},
            {"type": PairingDataComponentType.SIGNATURE, "data": signature},
            {"type": PairingDataComponentType.INFO, "data": info},
        ])

    @property
    def pair_record_path(self) -> Path:
        pair_records_cache_directory = create_pairing_records_cache_folder()
        # Key by the device's UDID: that is the identifier the device reports as
        # `peerDeviceInfo.identifier` over RSD, which the host-initiated tunnel path
        # (CoreDeviceTunnelService / RemotePairingTunnelService) uses to find the
        # record for pair-verify. Keying by accountID would hide the record from it.
        identifier = self.peer_device.udid or self.peer_device.account_id
        return pair_records_cache_directory / f"{get_remote_pairing_record_filename(identifier)}.{PAIRING_RECORD_EXT}"

    def save_pair_record(self) -> Path:
        """Persist a remote pairing record compatible with the host-initiated tooling."""
        if self.peer_device is None:
            raise PairingError("cannot save pair record before a successful pairing")
        path = self.pair_record_path
        path.write_bytes(
            plistlib.dumps({
                "public_key": self.ed25519_private_key.public_key().public_bytes_raw(),
                "private_key": self.ed25519_private_key.private_bytes_raw(),
                "remote_unlock_host_key": "",
                "host_identifier": self.host_info.identifier,
                "host_alt_irk": self.host_info.alt_irk,
                "peer_alt_irk": self.peer_device.alt_irk,
                "peer_udid": self.peer_device.udid,
                "peer_model": self.peer_device.model,
                "peer_name": self.peer_device.name,
            })
        )
        OSUTIL.chown_to_non_sudo_if_needed(path)
        return path

    async def _display_pin(self, pin: str, pin_callback: Optional[PinCallback]) -> None:
        if pin_callback is None:
            self.logger.info("Enter this code on your device: %s", pin)
            return
        result = pin_callback(pin)
        if asyncio.iscoroutine(result):
            await result

    @staticmethod
    def _chunk_component(component_type: int, data: bytes) -> list[dict]:
        return [
            {"type": component_type, "data": data[i : i + TLV_MAX_FRAGMENT_SIZE]}
            for i in range(0, len(data), TLV_MAX_FRAGMENT_SIZE)
        ]

    @staticmethod
    def _expect_state(tlv: dict, expected: int) -> None:
        state = tlv.get(PairingDataComponentType.STATE)
        if not state or state[0] != expected:
            raise PairingError(f"unexpected pair-setup state: expected {expected}, got {state!r}")

    @staticmethod
    def _ensure_no_error(tlv: dict) -> None:
        if PairingDataComponentType.ERROR in tlv:
            raise PairingError(f"device returned pairing error: {tlv[PairingDataComponentType.ERROR]!r}")

    @staticmethod
    def decode_tlv(tlv_list: list[Container]) -> dict:
        result = {}
        for tlv in tlv_list:
            if tlv.type in result:
                result[tlv.type] += tlv.data
            else:
                result[tlv.type] = tlv.data
        return result

    async def _send_pairing_data(self, data: bytes) -> None:
        await self._send_plain({
            "event": {
                "_0": {
                    "pairingData": {
                        "_0": {
                            "data": base64.b64encode(data).decode(),
                            "startNewSession": False,
                            "kind": "setupManualPairing",
                        }
                    }
                }
            }
        })

    async def _receive_pairing_data(self) -> bytes:
        response = await self._receive_plain()
        event = response.get("event", {}).get("_0", {})
        if "pairingData" in event:
            return base64.b64decode(event["pairingData"]["_0"]["data"])
        if "pairingRejectedWithError" in event:
            raise UserDeniedPairingError(
                event["pairingRejectedWithError"]
                .get("wrappedError", {})
                .get("userInfo", {})
                .get("NSLocalizedDescription")
            )
        raise PyMobileDevice3Exception(f"Got an unknown state message: {response}")

    async def _send_plain(self, value: dict) -> None:
        envelope = {
            "message": {"plain": {"_0": value}},
            "originatedBy": "device",
            "sequenceNumber": XpcUInt64Type(self._sequence_number),
        }
        self._writer.write(RPPairingPacket.build({"body": json.dumps(envelope, default=self._json_default).encode()}))
        await self._writer.drain()
        self._sequence_number += 1

    async def _receive_plain(self) -> dict:
        await self._reader.readexactly(len(REPAIRING_PACKET_MAGIC))
        size = struct.unpack(">H", await self._reader.readexactly(2))[0]
        envelope = json.loads(await self._reader.readexactly(size))
        return envelope["message"]["plain"]["_0"]

    @staticmethod
    def _json_default(obj) -> str:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    async def close(self) -> None:
        self._writer.close()
        with suppress(ssl.SSLError, ConnectionError):
            await self._writer.wait_closed()


async def serve_pairable_host(
    host_info: PairableHostInfo,
    port: int = 0,
    pin_callback: Optional[PinCallback] = None,
    ed25519_private_key: Optional[Ed25519PrivateKey] = None,
    timeout: Optional[float] = None,
    heartbeat_interval: float = 15.0,
    waiting_callback: Optional[Callable[[float], Union[None, Awaitable[None]]]] = None,
) -> PairableHostResult:
    """
    Advertise a ``_remotepairing-pairable-host._tcp`` service and accept a single
    device-initiated pairing.

    Binds a TCP listener (``port=0`` picks a free port), advertises it over mDNS,
    waits for a device to connect and drive pair-setup, persists the resulting
    pairing record and returns the paired device's info and the record path.

    While waiting, ``waiting_callback`` (if given) is invoked every
    ``heartbeat_interval`` seconds with the elapsed wait time so callers can show
    progress instead of blocking silently. ``timeout`` (seconds) raises
    :class:`asyncio.TimeoutError` if no pairing completes in time. Note a device
    that has already paired with this host will *not* connect at all (it
    recognizes ``host_info.identifier`` and reconnects silently), so a timeout
    firing usually means either no device tried or the device already knows us.
    """
    paired: asyncio.Future = asyncio.get_running_loop().create_future()

    async def handle(reader: StreamReader, writer: StreamWriter) -> None:
        if paired.done():
            writer.close()
            return
        peer = writer.get_extra_info("peername")
        logger.info("Device connected from %s", peer)
        host = PairableHost(reader, writer, host_info, ed25519_private_key=ed25519_private_key)
        try:
            peer_device = await host.accept(pin_callback)
            record_path = host.save_pair_record()
            if not paired.done():
                paired.set_result(PairableHostResult(peer_device=peer_device, record_path=record_path))
        except Exception as e:
            logger.warning("Pairing attempt from %s failed: %r", peer, e)
            if not paired.done():
                paired.set_exception(e)
        finally:
            await host.close()

    async def heartbeat() -> None:
        loop = asyncio.get_running_loop()
        start = loop.time()
        while True:
            await asyncio.sleep(heartbeat_interval)
            elapsed = loop.time() - start
            if waiting_callback is not None:
                result = waiting_callback(elapsed)
                if asyncio.iscoroutine(result):
                    await result
            else:
                logger.info("Still advertising, waiting for a device to start pairing (%ds elapsed)", int(elapsed))

    server = await asyncio.start_server(handle, host="0.0.0.0", port=port)
    bound_port = server.sockets[0].getsockname()[1]
    txt = host_info.mdns_txt_records()
    async with server, MDNSResponder(REMOTEPAIRING_PAIRABLE_HOST_SERVICE_NAME, host_info.identifier, bound_port, txt):
        logger.info(
            'Advertising %s as "%s" (%s) identifier=%s port=%d',
            REMOTEPAIRING_PAIRABLE_HOST_SERVICE_NAME,
            host_info.name,
            host_info.model,
            host_info.identifier,
            bound_port,
        )
        heartbeat_task = asyncio.create_task(heartbeat())
        try:
            if timeout is not None:
                return await asyncio.wait_for(asyncio.shield(paired), timeout)
            return await paired
        finally:
            heartbeat_task.cancel()
            with suppress(CancelledError):
                await heartbeat_task
