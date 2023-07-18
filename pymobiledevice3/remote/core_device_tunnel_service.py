import asyncio
import base64
import binascii
import hashlib
import json
import logging
import platform
import plistlib
from collections import namedtuple
from pathlib import Path
from ssl import VerifyMode
from typing import List, Mapping, Optional, TextIO

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect as aioquic_connect
from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent, StreamDataReceived
from construct import Const, Container, Enum, GreedyBytes, GreedyRange, Int8ul, Int16ub, Int64ul, Prefixed, Struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from opack import dumps
from srptools import SRPClientSession, SRPContext
from srptools.constants import PRIME_3072, PRIME_3072_GEN

from pymobiledevice3.ca import make_cert
from pymobiledevice3.pair_records import create_pairing_records_cache_folder, generate_host_id
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type

PairingDataComponentType = Enum(Int8ul,
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


class RemotePairingTunnel(QuicConnectionProtocol):
    MTU = 1420

    def __init__(self, quic: QuicConnection, stream_handler: Optional[QuicStreamHandler] = None):
        super().__init__(quic, stream_handler)
        self._queue = asyncio.Queue()

    async def request_tunnel_establish(self) -> Mapping:
        stream_id = self._quic.get_next_available_stream_id()
        # TODO: understand what this buffer should actually do
        self._quic.send_datagram_frame(b'x' * 1024)
        self._quic.send_stream_data(stream_id, self._encode_cdtunnel_packet(
            {'type': 'clientHandshakeRequest', 'mtu': self.MTU}))
        self.transmit()
        return await self._queue.get()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            self._queue.put_nowait(json.loads(CDTunnelPacket.parse(event.data).body))

    @staticmethod
    def _encode_cdtunnel_packet(data: Mapping) -> bytes:
        return CDTunnelPacket.build({'body': json.dumps(data).encode()})


class CoreDeviceTunnelService:
    WIRE_PROTOCOL_VERSION = 19

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        self._logger = logging.getLogger(__name__)
        self._sequence_number = 0
        self._encrypted_sequence_number = 0
        self.rsd = rsd
        self.service = None
        self.version = None
        self.handshake_info = None
        self.x25519_private_key = X25519PrivateKey.generate()
        self.ed25519_private_key = Ed25519PrivateKey.generate()
        self.identifier = generate_host_id()
        self.srp_context = None
        self.encryption_key = None
        self.signature = None

    def connect(self, autopair: bool = True) -> None:
        self.service = self.rsd.start_remote_service('com.apple.internal.dt.coredevice.untrusted.tunnelservice')
        self.version = self.service.receive_response()['ServiceVersion']

        self._attempt_pair_verify()
        if not self._validate_pairing():
            if autopair:
                self._pair()
        self._init_client_server_main_encryption_keys()

    def create_listener(self, private_key: RSAPrivateKey, protocol: str = 'quic') -> Mapping:
        request = {'request': {'_0': {'createListener': {
            'key': base64.b64encode(
                private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            ).decode(),
            'transportProtocolType': protocol}}}}

        response = self._send_receive_encrypted_request(request)
        return response['createListener']

    async def start_quic_tunnel(self, private_key: RSAPrivateKey, secrets_log_file: Optional[TextIO] = None) -> Mapping:
        parameters = self.create_listener(private_key, protocol='quic')
        cert = make_cert(private_key, private_key.public_key())
        configuration = QuicConfiguration(alpn_protocols=['RemotePairingTunnelProtocol'],
                                          is_client=True,
                                          certificate=cert,
                                          private_key=private_key,
                                          verify_mode=VerifyMode.CERT_NONE)
        configuration.secrets_log_file = secrets_log_file

        host = self.service.address[0]
        port = parameters['port']

        self._logger.debug(f'Connecting to {host}:{port}')
        async with aioquic_connect(
                host,
                port,
                configuration=configuration,
                create_protocol=RemotePairingTunnel,
        ) as client:
            self._logger.debug('quic connected')
            return await client.request_tunnel_establish()

    def save_pair_record(self) -> None:
        self.pair_record_path.write_bytes(
            plistlib.dumps({
                'public_key': self.ed25519_private_key.public_key().public_bytes_raw(),
                'private_key': self.ed25519_private_key.private_bytes_raw(),
            }))

    @property
    def pair_record(self) -> Optional[Mapping]:
        if self.pair_record_path.exists():
            return plistlib.loads(self.pair_record_path.read_bytes())
        return None

    @property
    def pair_record_path(self) -> Path:
        pair_records_cache_directory = create_pairing_records_cache_folder()
        return pair_records_cache_directory / f'remote_{self.handshake_info["peerDeviceInfo"]["identifier"]}.plist'

    def _pair(self) -> None:
        pairing_consent_result = self._request_pair_consent()
        self._init_srp_context(pairing_consent_result)
        self._verify_proof()
        self._save_pair_record_on_peer()
        self._init_client_server_main_encryption_keys()
        self._create_remote_unlock()
        self.save_pair_record()

    def _request_pair_consent(self) -> PairConsentResult:
        """ Display a Trust / Don't Trust dialog """

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.METHOD, 'data': b'\x00'},
            {'type': PairingDataComponentType.STATE, 'data': b'\x01'},
        ])

        self._send_pairing_data({'data': tlv,
                                 'kind': 'setupManualPairing',
                                 'sendingHost': platform.node(),
                                 'startNewSession': True})
        assert 'awaitingUserConsent' in self._receive_plain_response()['event']['_0']
        response = self._receive_pairing_data()
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(
            response))
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

    def _verify_proof(self) -> None:
        client_public = binascii.unhexlify(self.srp_context.public)
        client_session_key_proof = binascii.unhexlify(self.srp_context.key_proof)

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.STATE, 'data': b'\x03'},
            {'type': PairingDataComponentType.PUBLIC_KEY, 'data': client_public[:255]},
            {'type': PairingDataComponentType.PUBLIC_KEY, 'data': client_public[255:]},
            {'type': PairingDataComponentType.PROOF, 'data': client_session_key_proof},
        ])

        response = self._send_receive_pairing_data({
            'data': tlv,
            'kind': 'setupManualPairing',
            'sendingHost': platform.node(),
            'startNewSession': False})
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))
        assert self.srp_context.verify_proof(data[PairingDataComponentType.PROOF].hex().encode())

    def _save_pair_record_on_peer(self) -> Mapping:
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

        response = self._send_receive_pairing_data({
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

    def _create_remote_unlock(self) -> None:
        response = self._send_receive_encrypted_request({'request': {'_0': {'createRemoteUnlockKey': {}}}})
        self.remote_unlock_host_key = response['createRemoteUnlockKey']['hostKey']

    def _attempt_pair_verify(self) -> None:
        self.handshake_info = self._send_receive_handshake({
            'hostOptions': {'attemptPairVerify': True},
            'wireProtocolVersion': XpcInt64Type(self.WIRE_PROTOCOL_VERSION)})

    def _validate_pairing(self) -> bool:
        pairing_data = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.STATE, 'data': b'\x01'},
            {'type': PairingDataComponentType.PUBLIC_KEY,
             'data': self.x25519_private_key.public_key().public_bytes_raw()},
        ])
        response = self._send_receive_pairing_data({'data': pairing_data,
                                                    'kind': 'verifyManualPairing',
                                                    'startNewSession': True})

        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))
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

        response = self._send_receive_pairing_data({
            'data': pairing_data,
            'kind': 'verifyManualPairing',
            'startNewSession': False})
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        if PairingDataComponentType.ERROR in data:
            self._send_pair_verify_failed()
            return False

        return True

    def _send_pair_verify_failed(self) -> None:
        self._send_plain_request({'event': {'_0': {'pairVerifyFailed': {}}}})

    def _send_receive_encrypted_request(self, request: Mapping) -> Mapping:
        nonce = Int64ul.build(self._encrypted_sequence_number) + b'\x00' * 4
        encrypted_data = self.client_cip.encrypt(
            nonce,
            json.dumps(request).encode(),
            b'')

        response = self.service.send_receive_request({
            'mangledTypeName': 'RemotePairing.ControlChannelMessageEnvelope',
            'value': {'message': {
                'streamEncrypted': {'_0': encrypted_data}},
                'originatedBy': 'host',
                'sequenceNumber': XpcUInt64Type(self._sequence_number)}})
        self._encrypted_sequence_number += 1

        encrypted_data = response['value']['message']['streamEncrypted']['_0']
        plaintext = self.server_cip.decrypt(nonce, encrypted_data, None)
        return json.loads(plaintext)['response']['_1']

    def _send_receive_handshake(self, handshake_data: Mapping) -> Mapping:
        response = self._send_receive_plain_request({'request': {'_0': {'handshake': {'_0': handshake_data}}}})
        return response['response']['_1']['handshake']['_0']

    def _send_receive_pairing_data(self, pairing_data: Mapping) -> Mapping:
        self._send_pairing_data(pairing_data)
        return self._receive_pairing_data()

    def _send_pairing_data(self, pairing_data: Mapping) -> None:
        self._send_plain_request({'event': {'_0': {'pairingData': {'_0': pairing_data}}}})

    def _receive_pairing_data(self) -> Mapping:
        return self._receive_plain_response()['event']['_0']['pairingData']['_0']['data']

    def _send_receive_plain_request(self, plain_request: Mapping):
        self._send_plain_request(plain_request)
        return self._receive_plain_response()

    def _send_plain_request(self, plain_request: Mapping) -> None:
        self.service.send_request({
            'mangledTypeName': 'RemotePairing.ControlChannelMessageEnvelope',
            'value': {'message': {'plain': {'_0': plain_request}},
                      'originatedBy': 'host',
                      'sequenceNumber': XpcUInt64Type(self._sequence_number)}})
        self._sequence_number += 1

    def _receive_plain_response(self) -> Mapping:
        response = self.service.receive_response()
        return response['value']['message']['plain']['_0']

    @staticmethod
    def decode_tlv(tlv_list: List[Container]) -> Mapping:
        result = {}
        for tlv in tlv_list:
            if tlv.type in result:
                result[tlv.type] += tlv.data
            else:
                result[tlv.type] = tlv.data
        return result

    def __enter__(self) -> 'CoreDeviceTunnelService':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.service.close()


def create_core_device_tunnel_service(rsd: RemoteServiceDiscoveryService, autopair: bool = True):
    service = CoreDeviceTunnelService(rsd)
    service.connect(autopair=autopair)
    return service
