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
import ssl
import struct
import sys
from abc import ABC, abstractmethod
from asyncio import CancelledError, StreamReader, StreamWriter
from collections import namedtuple
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from socket import create_connection
from ssl import VerifyMode
from typing import AsyncGenerator, List, Mapping, Optional, TextIO, cast

import aiofiles
from construct import Const, Container
from construct import Enum as ConstructEnum
from construct import GreedyBytes, GreedyRange, Int8ul, Int16ub, Int64ul, Prefixed, Struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from opack import dumps
from packaging.version import Version
from pytun_pmd3 import TunTapDevice
from qh3.asyncio import QuicConnectionProtocol
from qh3.asyncio.client import connect as aioquic_connect
from qh3.asyncio.protocol import QuicStreamHandler
from qh3.quic import packet_builder
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.connection import QuicConnection
from qh3.quic.events import ConnectionTerminated, DatagramFrameReceived, QuicEvent, StreamDataReceived
from srptools import SRPClientSession, SRPContext
from srptools.constants import PRIME_3072, PRIME_3072_GEN

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.services.lockdown_service import LockdownService

try:
    from sslpsk_pmd3.sslpsk import SSLPSKContext
except ImportError:
    SSLPSKContext = None

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remotepairing
from pymobiledevice3.ca import make_cert
from pymobiledevice3.exceptions import PairingError, PyMobileDevice3Exception, UserDeniedPairingError
from pymobiledevice3.pair_records import PAIRING_RECORD_EXT, create_pairing_records_cache_folder, generate_host_id, \
    get_remote_pairing_record_filename, iter_remote_paired_identifiers
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.utils import get_rsds, resume_remoted_if_required, stop_remoted_if_required
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.utils import asyncio_print_traceback

OSUTIL = get_os_utils()
LOOPBACK_HEADER = OSUTIL.loopback_header
logger = logging.getLogger(__name__)

IPV6_HEADER_SIZE = 40
UDP_HEADER_SIZE = 8

# The iOS device uses an MTU of 1500, so we'll have to increase the default QUIC MTU
IOS_DEVICE_MTU_SIZE = 1500
packet_builder.PACKET_MAX_SIZE = IOS_DEVICE_MTU_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE

PairingDataComponentType = ConstructEnum(Int8ul,
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
                                         SIGNATURE=0x0a,
                                         PERMISSIONS=0x0b,
                                         FRAGMENT_DATA=0x0c,
                                         FRAGMENT_LAST=0x0d,
                                         SESSION_ID=0x0e,
                                         TTL=0x0f,
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
                                         OWNERSHIP_PROOF=0x1a,
                                         SETUP_CODE_TYPE=0x1b,
                                         PRODUCTION_DATA=0x1c,
                                         APP_INFO=0x1d,
                                         SEPARATOR=0xff)

PairingDataComponentTLV8 = Struct(
    'type' / PairingDataComponentType,
    'data' / Prefixed(Int8ul, GreedyBytes),
)

PairingDataComponentTLVBuf = GreedyRange(PairingDataComponentTLV8)

PairConsentResult = namedtuple('PairConsentResult', 'public_key salt')

CDTunnelPacket = Struct(
    'magic' / Const(b'CDTunnel'),
    'body' / Prefixed(Int16ub, GreedyBytes),
)

REPAIRING_PACKET_MAGIC = b'RPPairing'

RPPairingPacket = Struct(
    'magic' / Const(REPAIRING_PACKET_MAGIC),
    'body' / Prefixed(Int16ub, GreedyBytes),
)


class RemotePairingTunnel(ABC):
    def __init__(self):
        self._queue = asyncio.Queue()
        self._tun_read_task = None
        self._logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.tun = None

    @abstractmethod
    async def send_packet_to_device(self, packet: bytes) -> None:
        pass

    @abstractmethod
    async def request_tunnel_establish(self) -> Mapping:
        pass

    @abstractmethod
    async def wait_closed(self) -> None:
        pass

    @asyncio_print_traceback
    async def tun_read_task(self) -> None:
        read_size = self.tun.mtu + len(LOOPBACK_HEADER)
        try:
            if sys.platform != 'win32':
                async with aiofiles.open(self.tun.fileno(), 'rb', opener=lambda path, flags: path, buffering=0) as f:
                    while True:
                        packet = await f.read(read_size)
                        assert packet.startswith(LOOPBACK_HEADER)
                        packet = packet[len(LOOPBACK_HEADER):]
                        await self.send_packet_to_device(packet)
            else:
                while True:
                    packet = await asyncio.get_running_loop().run_in_executor(None, self.tun.read)
                    if packet:
                        await self.send_packet_to_device(packet)
        except ConnectionResetError:
            self._logger.warning(f'got connection reset in {asyncio.current_task().get_name()}')
        except OSError:
            self._logger.warning(f'got oserror in {asyncio.current_task().get_name()}')

    def start_tunnel(self, address: str, mtu: int) -> None:
        self.tun = TunTapDevice()
        self.tun.addr = address
        self.tun.mtu = mtu
        self.tun.up()
        self._tun_read_task = asyncio.create_task(self.tun_read_task(), name=f'tun-read-{address}')

    async def stop_tunnel(self) -> None:
        self._logger.debug('stopping tunnel')
        self._tun_read_task.cancel()
        with suppress(CancelledError):
            await self._tun_read_task
        self.tun.close()
        self.tun = None

    @staticmethod
    def _encode_cdtunnel_packet(data: Mapping) -> bytes:
        return CDTunnelPacket.build({'body': json.dumps(data).encode()})


class RemotePairingQuicTunnel(RemotePairingTunnel, QuicConnectionProtocol):
    MAX_QUIC_DATAGRAM = 14000
    MAX_IDLE_TIMEOUT = 30.0
    REQUESTED_MTU = 1420

    def __init__(self, quic: QuicConnection, stream_handler: Optional[QuicStreamHandler] = None):
        RemotePairingTunnel.__init__(self)
        QuicConnectionProtocol.__init__(self, quic, stream_handler)
        self._keep_alive_task = None

    async def wait_closed(self) -> None:
        try:
            await QuicConnectionProtocol.wait_closed(self)
        except asyncio.CancelledError:
            pass

    async def send_packet_to_device(self, packet: bytes) -> None:
        self._quic.send_datagram_frame(packet)
        self.transmit()

    async def request_tunnel_establish(self) -> Mapping:
        stream_id = self._quic.get_next_available_stream_id()
        # pad the data with random data to force the MTU size correctly
        self._quic.send_datagram_frame(b'x' * 1024)
        self._quic.send_stream_data(stream_id, self._encode_cdtunnel_packet(
            {'type': 'clientHandshakeRequest', 'mtu': self.REQUESTED_MTU}))
        self.transmit()
        return await self._queue.get()

    @asyncio_print_traceback
    async def keep_alive_task(self) -> None:
        while True:
            await self.ping()
            await asyncio.sleep(self._quic.configuration.idle_timeout / 2)

    def start_tunnel(self, address: str, mtu: int) -> None:
        super().start_tunnel(address, mtu)
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
    def _encode_cdtunnel_packet(data: Mapping) -> bytes:
        return CDTunnelPacket.build({'body': json.dumps(data).encode()})


class RemotePairingTcpTunnel(RemotePairingTunnel):
    REQUESTED_MTU = 16000

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        RemotePairingTunnel.__init__(self)
        self._reader = reader
        self._writer = writer
        self._sock_read_task = None

    async def send_packet_to_device(self, packet: bytes) -> None:
        self._writer.write(packet)
        await self._writer.drain()

    @asyncio_print_traceback
    async def sock_read_task(self) -> None:
        try:
            while True:
                try:
                    ipv6_header = await self._reader.readexactly(IPV6_HEADER_SIZE)
                    ipv6_length = struct.unpack('>H', ipv6_header[4:6])[0]
                    ipv6_body = await self._reader.readexactly(ipv6_length)
                    self.tun.write(LOOPBACK_HEADER + ipv6_header + ipv6_body)
                except asyncio.exceptions.IncompleteReadError:
                    await asyncio.sleep(1)
        except OSError as e:
            self._logger.warning(f'got {e.__class__.__name__} in {asyncio.current_task().get_name()}')
            await self.wait_closed()

    async def wait_closed(self) -> None:
        try:
            await self._writer.wait_closed()
        except OSError:
            pass

    async def request_tunnel_establish(self) -> Mapping:
        self._writer.write(self._encode_cdtunnel_packet(
            {'type': 'clientHandshakeRequest', 'mtu': self.REQUESTED_MTU}))
        await self._writer.drain()
        return json.loads(CDTunnelPacket.parse(await self._reader.read(self.REQUESTED_MTU)).body)

    def start_tunnel(self, address: str, mtu: int) -> None:
        super().start_tunnel(address, mtu)
        self._sock_read_task = asyncio.create_task(self.sock_read_task(), name=f'sock-read-task-{address}')

    async def stop_tunnel(self) -> None:
        self._sock_read_task.cancel()
        with suppress(CancelledError):
            await self._sock_read_task
        if not self._writer.is_closing():
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except OSError:
                pass
        await super().stop_tunnel()


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
    async def receive_response(self) -> Mapping:
        pass

    @abstractmethod
    async def send_request(self, data: Mapping) -> None:
        pass

    async def send_receive_request(self, data: Mapping) -> Mapping:
        await self.send_request(data)
        return await self.receive_response()

    async def connect(self, autopair: bool = True) -> None:
        await self._attempt_pair_verify()

        if not await self._validate_pairing():
            if autopair:
                await self._pair()
        self._init_client_server_main_encryption_keys()

    async def create_quic_listener(self, private_key: RSAPrivateKey) -> Mapping:
        request = {'request': {'_0': {'createListener': {
            'key': base64.b64encode(
                private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            ).decode(),
            'peerConnectionsInfo': [{'owningPID': os.getpid(), 'owningProcessName': 'CoreDeviceService'}],
            'transportProtocolType': 'quic'}}}}

        response = await self._send_receive_encrypted_request(request)
        return response['createListener']

    async def create_tcp_listener(self) -> Mapping:
        request = {'request': {'_0': {'createListener': {
            'key': base64.b64encode(self.encryption_key).decode(),
            'peerConnectionsInfo': [{'owningPID': os.getpid(), 'owningProcessName': 'CoreDeviceService'}],
            'transportProtocolType': 'tcp'}}}}
        response = await self._send_receive_encrypted_request(request)
        return response['createListener']

    @asynccontextmanager
    async def start_quic_tunnel(
            self, secrets_log_file: Optional[TextIO] = None,
            max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT) -> AsyncGenerator[TunnelResult, None]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        parameters = await self.create_quic_listener(private_key)
        cert = make_cert(private_key, private_key.public_key())
        configuration = QuicConfiguration(
            alpn_protocols=['RemotePairingTunnelProtocol'],
            is_client=True,
            verify_mode=VerifyMode.CERT_NONE,
            verify_hostname=False,
            max_datagram_frame_size=RemotePairingQuicTunnel.MAX_QUIC_DATAGRAM,
            idle_timeout=max_idle_timeout
        )
        configuration.load_cert_chain(cert.public_bytes(Encoding.PEM),
                                      private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL,
                                                                NoEncryption()).decode())
        configuration.secrets_log_file = secrets_log_file

        host = self.hostname
        port = parameters['port']

        self.logger.debug(f'Connecting to {host}:{port}')
        async with aioquic_connect(
                host,
                port,
                configuration=configuration,
                create_protocol=RemotePairingQuicTunnel,
        ) as client:
            self.logger.debug('quic connected')
            client = cast(RemotePairingQuicTunnel, client)
            await client.wait_connected()
            handshake_response = await client.request_tunnel_establish()
            client.start_tunnel(handshake_response['clientParameters']['address'],
                                handshake_response['clientParameters']['mtu'])
            try:
                yield TunnelResult(
                    client.tun.name, handshake_response['serverAddress'], handshake_response['serverRSDPort'],
                    TunnelProtocol.QUIC, client)
            finally:
                await client.stop_tunnel()

    @asynccontextmanager
    async def start_tcp_tunnel(self) -> AsyncGenerator[TunnelResult, None]:
        parameters = await self.create_tcp_listener()
        host = self.hostname
        port = parameters['port']
        sock = create_connection((host, port))
        OSUTIL.set_keepalive(sock)
        ctx = SSLPSKContext(ssl.PROTOCOL_TLSv1_2)
        ctx.psk = self.encryption_key
        ctx.set_ciphers('PSK')
        reader, writer = await asyncio.open_connection(sock=sock, ssl=ctx, server_hostname='')
        tunnel = RemotePairingTcpTunnel(reader, writer)
        handshake_response = await tunnel.request_tunnel_establish()

        tunnel.start_tunnel(handshake_response['clientParameters']['address'],
                            handshake_response['clientParameters']['mtu'])

        try:
            yield TunnelResult(
                tunnel.tun.name, handshake_response['serverAddress'], handshake_response['serverRSDPort'],
                TunnelProtocol.TCP, tunnel)
        finally:
            await tunnel.stop_tunnel()

    def save_pair_record(self) -> None:
        self.pair_record_path.write_bytes(
            plistlib.dumps({
                'public_key': self.ed25519_private_key.public_key().public_bytes_raw(),
                'private_key': self.ed25519_private_key.private_bytes_raw(),
                'remote_unlock_host_key': self.remote_unlock_host_key
            }))
        OSUTIL.chown_to_non_sudo_if_needed(self.pair_record_path)

    @property
    def pair_record(self) -> Optional[Mapping]:
        if self.pair_record_path.exists():
            return plistlib.loads(self.pair_record_path.read_bytes())
        return None

    @property
    def remote_identifier(self) -> str:
        return self.handshake_info['peerDeviceInfo']['identifier']

    @property
    def pair_record_path(self) -> Path:
        pair_records_cache_directory = create_pairing_records_cache_folder()
        return (pair_records_cache_directory /
                f'{get_remote_pairing_record_filename(self.remote_identifier)}.{PAIRING_RECORD_EXT}')

    async def _pair(self) -> None:
        pairing_consent_result = await self._request_pair_consent()
        self._init_srp_context(pairing_consent_result)
        await self._verify_proof()
        await self._save_pair_record_on_peer()
        self._init_client_server_main_encryption_keys()
        await self._create_remote_unlock()
        self.save_pair_record()

    async def _request_pair_consent(self) -> PairConsentResult:
        """ Display a Trust / Don't Trust dialog """

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.METHOD, 'data': b'\x00'},
            {'type': PairingDataComponentType.STATE, 'data': b'\x01'},
        ])

        await self._send_pairing_data({'data': tlv,
                                       'kind': 'setupManualPairing',
                                       'sendingHost': platform.node(),
                                       'startNewSession': True})
        self.logger.info('Waiting user pairing consent')
        response = await self._receive_plain_response()
        response = response['event']['_0']

        if 'pairingRejectedWithError' in response:
            raise PairingError(
                response['pairingRejectedWithError']['wrappedError']['userInfo']['NSLocalizedDescription'])
        elif 'awaitingUserConsent' in response:
            pairing_data = await self._receive_pairing_data()
        else:
            # On tvOS no consent is needed and pairing data is returned immediately.
            pairing_data = self._decode_bytes_if_needed(response['pairingData']['_0']['data'])

        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(pairing_data))
        return PairConsentResult(public_key=data[PairingDataComponentType.PUBLIC_KEY],
                                 salt=data[PairingDataComponentType.SALT])

    def _init_srp_context(self, pairing_consent_result: PairConsentResult) -> None:
        # Receive server public and salt and process them.
        client_session = SRPClientSession(
            SRPContext('Pair-Setup', password='000000', prime=PRIME_3072, generator=PRIME_3072_GEN,
                       hash_func=hashlib.sha512))
        client_session.process(pairing_consent_result.public_key.hex(),
                               pairing_consent_result.salt.hex())
        self.srp_context = client_session
        self.encryption_key = binascii.unhexlify(self.srp_context.key)

    async def _verify_proof(self) -> None:
        client_public = binascii.unhexlify(self.srp_context.public)
        client_session_key_proof = binascii.unhexlify(self.srp_context.key_proof)

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.STATE, 'data': b'\x03'},
            {'type': PairingDataComponentType.PUBLIC_KEY, 'data': client_public[:255]},
            {'type': PairingDataComponentType.PUBLIC_KEY, 'data': client_public[255:]},
            {'type': PairingDataComponentType.PROOF, 'data': client_session_key_proof},
        ])

        response = await self._send_receive_pairing_data({
            'data': tlv,
            'kind': 'setupManualPairing',
            'sendingHost': platform.node(),
            'startNewSession': False})
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))
        assert self.srp_context.verify_proof(data[PairingDataComponentType.PROOF].hex().encode())

    async def _save_pair_record_on_peer(self) -> Mapping:
        # HKDF with above computed key (SRP_compute_key) + Pair-Setup-Encrypt-Salt + Pair-Setup-Encrypt-Info
        # result used as key for chacha20-poly1305
        setup_encryption_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b'Pair-Setup-Encrypt-Salt',
            info=b'Pair-Setup-Encrypt-Info',
        ).derive(self.encryption_key)

        self.ed25519_private_key = Ed25519PrivateKey.generate()

        # HKDF with above computed key:
        #   (SRP_compute_key) + Pair-Setup-Controller-Sign-Salt + Pair-Setup-Controller-Sign-Info
        signbuf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b'Pair-Setup-Controller-Sign-Salt',
            info=b'Pair-Setup-Controller-Sign-Info',
        ).derive(self.encryption_key)

        signbuf += self.identifier.encode()
        signbuf += self.ed25519_private_key.public_key().public_bytes_raw()

        self.signature = self.ed25519_private_key.sign(signbuf)

        device_info = dumps({
            'altIRK': b'\xe9\xe8-\xc0jIykVoT\x00\x19\xb1\xc7{',
            'btAddr': '11:22:33:44:55:66',
            'mac': b'\x11\x22\x33\x44\x55\x66',
            'remotepairing_serial_number': 'AAAAAAAAAAAA',
            'accountID': self.identifier,
            'model': 'computer-model',
            'name': platform.node()
        })

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.IDENTIFIER, 'data': self.identifier.encode()},
            {'type': PairingDataComponentType.PUBLIC_KEY,
             'data': self.ed25519_private_key.public_key().public_bytes_raw()},
            {'type': PairingDataComponentType.SIGNATURE, 'data': self.signature},
            {'type': PairingDataComponentType.INFO, 'data': device_info},
        ])

        cip = ChaCha20Poly1305(setup_encryption_key)
        encrypted_data = cip.encrypt(b'\x00\x00\x00\x00PS-Msg05', tlv, b'')

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.ENCRYPTED_DATA, 'data': encrypted_data[:255]},
            {'type': PairingDataComponentType.ENCRYPTED_DATA, 'data': encrypted_data[255:]},
            {'type': PairingDataComponentType.STATE, 'data': b'\x05'},
        ])

        response = await self._send_receive_pairing_data({
            'data': tlv,
            'kind': 'setupManualPairing',
            'sendingHost': platform.node(),
            'startNewSession': False})
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        tlv = PairingDataComponentTLVBuf.parse(cip.decrypt(
            b'\x00\x00\x00\x00PS-Msg06', data[PairingDataComponentType.ENCRYPTED_DATA], b''))

        return tlv

    def _init_client_server_main_encryption_keys(self) -> None:
        client_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b'ClientEncrypt-main',
        ).derive(self.encryption_key)
        self.client_cip = ChaCha20Poly1305(client_key)

        server_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b'ServerEncrypt-main',
        ).derive(self.encryption_key)
        self.server_cip = ChaCha20Poly1305(server_key)

    async def _create_remote_unlock(self) -> None:
        response = await self._send_receive_encrypted_request({'request': {'_0': {'createRemoteUnlockKey': {}}}})
        if 'errorExtended' in response:
            self.remote_unlock_host_key = None
        else:
            self.remote_unlock_host_key = response['createRemoteUnlockKey']['hostKey']

    async def _attempt_pair_verify(self) -> None:
        self.handshake_info = await self._send_receive_handshake({
            'hostOptions': {'attemptPairVerify': True},
            'wireProtocolVersion': XpcInt64Type(self.WIRE_PROTOCOL_VERSION)})

    @staticmethod
    def _decode_bytes_if_needed(data: bytes) -> bytes:
        return data

    async def _validate_pairing(self) -> bool:
        pairing_data = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.STATE, 'data': b'\x01'},
            {'type': PairingDataComponentType.PUBLIC_KEY,
             'data': self.x25519_private_key.public_key().public_bytes_raw()},
        ])
        response = await self._send_receive_pairing_data({'data': pairing_data,
                                                          'kind': 'verifyManualPairing',
                                                          'startNewSession': True})

        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        if PairingDataComponentType.ERROR in data:
            await self._send_pair_verify_failed()
            return False

        peer_public_key = X25519PublicKey.from_public_bytes(data[PairingDataComponentType.PUBLIC_KEY])
        self.encryption_key = self.x25519_private_key.exchange(peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b'Pair-Verify-Encrypt-Salt',
            info=b'Pair-Verify-Encrypt-Info',
        ).derive(self.encryption_key)
        cip = ChaCha20Poly1305(derived_key)

        # TODO:
        #   we should be able to verify from the received encrypted data, but from some reason we failed to
        #   do so. instead, we verify using the next stage

        if self.pair_record is None:
            private_key = Ed25519PrivateKey.from_private_bytes(b'\x00' * 0x20)
        else:
            private_key = Ed25519PrivateKey.from_private_bytes(self.pair_record['private_key'])

        signbuf = b''
        signbuf += self.x25519_private_key.public_key().public_bytes_raw()
        signbuf += self.identifier.encode()
        signbuf += peer_public_key.public_bytes_raw()

        signature = private_key.sign(signbuf)

        encrypted_data = cip.encrypt(b'\x00\x00\x00\x00PV-Msg03', PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.IDENTIFIER, 'data': self.identifier.encode()},
            {'type': PairingDataComponentType.SIGNATURE, 'data': signature},
        ]), b'')

        pairing_data = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.STATE, 'data': b'\x03'},
            {'type': PairingDataComponentType.ENCRYPTED_DATA, 'data': encrypted_data},
        ])

        response = await self._send_receive_pairing_data({
            'data': pairing_data,
            'kind': 'verifyManualPairing',
            'startNewSession': False})
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        if PairingDataComponentType.ERROR in data:
            await self._send_pair_verify_failed()
            return False

        return True

    async def _send_pair_verify_failed(self) -> None:
        await self._send_plain_request({'event': {'_0': {'pairVerifyFailed': {}}}})

    async def _send_receive_encrypted_request(self, request: Mapping) -> Mapping:
        nonce = Int64ul.build(self._encrypted_sequence_number) + b'\x00' * 4
        encrypted_data = self.client_cip.encrypt(
            nonce,
            json.dumps(request).encode(),
            b'')

        response = await self.send_receive_request({'message': {
            'streamEncrypted': {'_0': encrypted_data}},
            'originatedBy': 'host',
            'sequenceNumber': XpcUInt64Type(self._sequence_number)})
        self._encrypted_sequence_number += 1

        encrypted_data = self._decode_bytes_if_needed(response['message']['streamEncrypted']['_0'])
        plaintext = self.server_cip.decrypt(nonce, encrypted_data, None)
        response = json.loads(plaintext)['response']['_1']

        if 'errorExtended' in response:
            raise PyMobileDevice3Exception(response['errorExtended']['_0']['userInfo']['NSLocalizedDescription'])

        return response

    async def _send_receive_handshake(self, handshake_data: Mapping) -> Mapping:
        response = await self._send_receive_plain_request({'request': {'_0': {'handshake': {'_0': handshake_data}}}})
        return response['response']['_1']['handshake']['_0']

    async def _send_receive_pairing_data(self, pairing_data: Mapping) -> bytes:
        await self._send_pairing_data(pairing_data)
        return await self._receive_pairing_data()

    async def _send_pairing_data(self, pairing_data: Mapping) -> None:
        await self._send_plain_request({'event': {'_0': {'pairingData': {'_0': pairing_data}}}})

    async def _receive_pairing_data(self) -> bytes:
        response = await self._receive_plain_response()
        response = response['event']['_0']
        if 'pairingData' in response:
            return self._decode_bytes_if_needed(response['pairingData']['_0']['data'])
        if 'pairingRejectedWithError' in response:
            raise UserDeniedPairingError(response['pairingRejectedWithError']
                                         .get('wrappedError', {})
                                         .get('userInfo', {})
                                         .get('NSLocalizedDescription'))
        raise PyMobileDevice3Exception(f'Got an unknown state message: {response}')

    async def _send_receive_plain_request(self, plain_request: Mapping):
        await self._send_plain_request(plain_request)
        return await self._receive_plain_response()

    async def _send_plain_request(self, plain_request: Mapping) -> None:
        await self.send_request({'message': {'plain': {'_0': plain_request}},
                                 'originatedBy': 'host',
                                 'sequenceNumber': XpcUInt64Type(self._sequence_number)})
        self._sequence_number += 1

    async def _receive_plain_response(self) -> Mapping:
        response = await self.receive_response()
        return response['message']['plain']['_0']

    @staticmethod
    def decode_tlv(tlv_list: List[Container]) -> Mapping:
        result = {}
        for tlv in tlv_list:
            if tlv.type in result:
                result[tlv.type] += tlv.data
            else:
                result[tlv.type] = tlv.data
        return result

    async def __aenter__(self) -> 'CoreDeviceTunnelService':
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


class CoreDeviceTunnelService(RemotePairingProtocol, RemoteService):
    SERVICE_NAME = 'com.apple.internal.dt.coredevice.untrusted.tunnelservice'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        RemoteService.__init__(self, rsd, self.SERVICE_NAME)
        RemotePairingProtocol.__init__(self)
        self.version: Optional[int] = None

    async def connect(self, autopair: bool = True) -> None:
        await RemoteService.connect(self)
        try:
            response = await self.service.receive_response()
            self.version = response['ServiceVersion']
            await RemotePairingProtocol.connect(self, autopair=autopair)
            self.hostname = self.service.address[0]
        except:  # noqa: E722
            await self.service.close()

    async def close(self) -> None:
        await self.rsd.close()
        await self.service.close()

    async def receive_response(self) -> Mapping:
        response = await self.service.receive_response()
        return response['value']

    async def send_request(self, data: Mapping) -> None:
        return await self.service.send_request({
            'mangledTypeName': 'RemotePairing.ControlChannelMessageEnvelope', 'value': data})


class RemotePairingTunnelService(RemotePairingProtocol):
    def __init__(self, remote_identifier: str, hostname: str, port: int) -> None:
        RemotePairingProtocol.__init__(self)
        self._remote_identifier = remote_identifier
        self.hostname = hostname
        self.port = port
        self._connection: Optional[ServiceConnection] = None

    @property
    def remote_identifier(self) -> str:
        return self._remote_identifier

    async def connect(self, autopair: bool = True) -> None:
        self._connection = ServiceConnection.create_using_tcp(self.hostname, self.port)
        await self._connection.aio_start()

        try:
            await self._attempt_pair_verify()
            if not await self._validate_pairing():
                raise ConnectionAbortedError()
            self._init_client_server_main_encryption_keys()
        except:  # noqa: E722
            self._connection.close()
            raise

    async def close(self) -> None:
        await self._connection.aio_close()

    async def receive_response(self) -> Mapping:
        await self._connection.aio_recvall(len(REPAIRING_PACKET_MAGIC))
        size = struct.unpack('>H', await self._connection.aio_recvall(2))[0]
        return json.loads(await self._connection.aio_recvall(size))

    async def send_request(self, data: Mapping) -> None:
        return await self._connection.aio_sendall(
            RPPairingPacket.build({'body': json.dumps(data, default=self._default_json_encoder).encode()}))

    @staticmethod
    def _default_json_encoder(obj) -> str:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        raise TypeError()

    @staticmethod
    def _decode_bytes_if_needed(data: bytes) -> bytes:
        return base64.b64decode(data)

    def __repr__(self) -> str:
        return (f'<{self.__class__.__name__} IDENTIFIER:{self.remote_identifier} HOSTNAME:{self.hostname} '
                f'PORT:{self.port}>')


class RemotePairingManualPairingService(RemotePairingTunnelService):
    async def connect(self, autopair: bool = True) -> None:
        self._connection = ServiceConnection.create_using_tcp(self.hostname, self.port)
        await self._connection.aio_start()
        await RemotePairingProtocol.connect(self, autopair=autopair)


class CoreDeviceTunnelProxy(StartTcpTunnel, LockdownService):
    SERVICE_NAME = 'com.apple.internal.devicecompute.CoreDeviceProxy'

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        LockdownService.__init__(self, lockdown, self.SERVICE_NAME)
        self._lockdown = lockdown
        self._service: Optional[ServiceConnection] = None

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self._loop = loop

    @property
    def remote_identifier(self) -> str:
        return self._lockdown.udid

    @asynccontextmanager
    async def start_tcp_tunnel(self) -> AsyncGenerator['TunnelResult', None]:
        self._service = await self._lockdown.aio_start_lockdown_service(self.SERVICE_NAME)
        tunnel = RemotePairingTcpTunnel(self._service.reader, self._service.writer)
        handshake_response = await tunnel.request_tunnel_establish()
        tunnel.start_tunnel(handshake_response['clientParameters']['address'],
                            handshake_response['clientParameters']['mtu'])
        try:
            yield TunnelResult(
                tunnel.tun.name, handshake_response['serverAddress'], handshake_response['serverRSDPort'],
                TunnelProtocol.TCP, tunnel)
        finally:
            await tunnel.stop_tunnel()

    async def close(self) -> None:
        if self._service is not None:
            await self._service.aio_close()


async def create_core_device_tunnel_service_using_rsd(
        rsd: RemoteServiceDiscoveryService, autopair: bool = True) -> CoreDeviceTunnelService:
    service = CoreDeviceTunnelService(rsd)
    await service.connect(autopair=autopair)
    return service


async def create_core_device_tunnel_service_using_remotepairing(
        remote_identifier: str, hostname: str, port: int, autopair: bool = True) -> RemotePairingTunnelService:
    service = RemotePairingTunnelService(remote_identifier, hostname, port)
    await service.connect(autopair=autopair)
    return service


async def create_core_device_service_using_remotepairing_manual_pairing(
        remote_identifier: str, hostname: str, port: int, autopair: bool = True) -> RemotePairingTunnelService:
    service = RemotePairingManualPairingService(remote_identifier, hostname, port)
    await service.connect(autopair=autopair)
    return service


@asynccontextmanager
async def start_tunnel_over_remotepairing(
        remote_pairing: RemotePairingTunnelService, secrets: Optional[TextIO] = None,
        max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT,
        protocol: TunnelProtocol = TunnelProtocol.QUIC) \
        -> AsyncGenerator[TunnelResult, None]:
    async with remote_pairing:
        if protocol == TunnelProtocol.QUIC:
            async with remote_pairing.start_quic_tunnel(
                    secrets_log_file=secrets, max_idle_timeout=max_idle_timeout) as tunnel_result:
                yield tunnel_result
        elif protocol == TunnelProtocol.TCP:
            async with remote_pairing.start_tcp_tunnel() as tunnel_result:
                yield tunnel_result


@asynccontextmanager
async def start_tunnel_over_core_device(
        service_provider: CoreDeviceTunnelService, secrets: Optional[TextIO] = None,
        max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT,
        protocol: TunnelProtocol = TunnelProtocol.QUIC) \
        -> AsyncGenerator[TunnelResult, None]:
    stop_remoted_if_required()
    async with service_provider:
        if protocol == TunnelProtocol.QUIC:
            async with service_provider.start_quic_tunnel(
                    secrets_log_file=secrets, max_idle_timeout=max_idle_timeout) as tunnel_result:
                resume_remoted_if_required()
                yield tunnel_result
        elif protocol == TunnelProtocol.TCP:
            async with service_provider.start_tcp_tunnel() as tunnel_result:
                resume_remoted_if_required()
                yield tunnel_result


@asynccontextmanager
async def start_tunnel(
        protocol_handler: RemotePairingProtocol, secrets: Optional[TextIO] = None,
        max_idle_timeout: float = RemotePairingQuicTunnel.MAX_IDLE_TIMEOUT,
        protocol: TunnelProtocol = TunnelProtocol.QUIC) -> AsyncGenerator[TunnelResult, None]:
    if isinstance(protocol_handler, CoreDeviceTunnelService):
        async with start_tunnel_over_core_device(
                protocol_handler, secrets=secrets, max_idle_timeout=max_idle_timeout, protocol=protocol) as service:
            yield service
    elif isinstance(protocol_handler, RemotePairingTunnelService):
        async with start_tunnel_over_remotepairing(
                protocol_handler, secrets=secrets, max_idle_timeout=max_idle_timeout, protocol=protocol) as service:
            yield service
    elif isinstance(protocol_handler, CoreDeviceTunnelProxy):
        if protocol != TunnelProtocol.TCP:
            raise ValueError('CoreDeviceTunnelProxy protocol can only be TCP')
        async with protocol_handler.start_tcp_tunnel() as service:
            yield service
    else:
        raise Exception(f'Bad value for protocol_handler: {protocol_handler}')


async def get_core_device_tunnel_services(
        bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT,
        udid: Optional[str] = None) -> List[CoreDeviceTunnelService]:
    result = []
    for rsd in await get_rsds(bonjour_timeout=bonjour_timeout, udid=udid):
        if udid is None and Version(rsd.product_version) < Version('17.0'):
            logger.debug(f'Skipping {rsd.udid}:, iOS {rsd.product_version} < 17.0')
            await rsd.close()
            continue
        try:
            result.append(await create_core_device_tunnel_service_using_rsd(rsd))
        except Exception as e:
            logger.error(f'Failed to start service: {rsd}: {e}')
            await rsd.close()
            raise
    return result


async def get_remote_pairing_tunnel_services(
        bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT,
        udid: Optional[str] = None) -> List[RemotePairingTunnelService]:
    result = []
    for answer in await browse_remotepairing(timeout=bonjour_timeout):
        for ip in answer.ips:
            for identifier in iter_remote_paired_identifiers():
                if udid is not None and identifier != udid:
                    continue
                conn = None
                try:
                    conn = await create_core_device_tunnel_service_using_remotepairing(identifier, ip, answer.port)
                    result.append(conn)
                    break
                except ConnectionAbortedError:
                    if conn is not None:
                        await conn.close()
                except OSError:
                    if conn is not None:
                        await conn.close()
                    continue
    return result
