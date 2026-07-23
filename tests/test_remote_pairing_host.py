"""Tests for device-initiated pairing (the "pairable host" / responder side)."""

import asyncio
import base64
import binascii
import hashlib
import json
import socket
import struct
from contextlib import suppress
from typing import Any, Optional

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from opack2 import dumps, loads
from srptools import SRPClientSession, SRPContext
from srptools.constants import PRIME_3072, PRIME_3072_GEN

from pymobiledevice3.remote.siphash import compute_auth_tag, siphash24, validate_auth_tag
from pymobiledevice3.remote.tunnel_service import (
    REPAIRING_PACKET_MAGIC,
    PairableHost,
    PairableHostInfo,
    PairingDataComponentTLVBuf,
    PairingDataComponentType,
    RPPairingPacket,
    RPPairingPacketData,
)

T = PairingDataComponentType

# (altIRK, service_identifier, base64-encoded authTag) taken from the idevice test vector
AUTH_TAG_VECTOR = ("Mgp6ZGPzXM2ku9br46vsiw==", "2BE6E510-0325-4365-923E-B14C6F57DB3A", "kXjlTr2l")


def _decode_tlv(parsed) -> dict[str, Any]:
    result = {}
    for tlv in parsed:
        result[tlv.type] = result.get(tlv.type, b"") + tlv.data
    return result


def test_siphash_known_vectors():
    # Canonical SipHash-2-4 reference vectors (Aumasson & Bernstein), key = 00 01 .. 0f
    key = bytes(range(16))
    assert siphash24(key, b"") == 0x726FDB47DD0E0E31
    assert siphash24(key, bytes([0])) == 0x74F839C593DC67FD
    assert siphash24(key, bytes(range(7))) == 0xAB0200F58B01D137


def test_compute_auth_tag_matches_idevice_vector():
    alt_irk, identifier, expected = AUTH_TAG_VECTOR
    tag = compute_auth_tag(base64.b64decode(alt_irk), identifier)
    assert base64.b64encode(tag).decode() == expected


def test_validate_auth_tag():
    alt_irk, identifier, expected = AUTH_TAG_VECTOR
    raw_irk = base64.b64decode(alt_irk)
    assert validate_auth_tag(raw_irk, identifier, expected)
    assert not validate_auth_tag(raw_irk, identifier, "AAAAAAAA")
    assert not validate_auth_tag(raw_irk, "different-identifier", expected)
    assert not validate_auth_tag(raw_irk, identifier, "not-base64!!")


def test_mdns_txt_records():
    info = PairableHostInfo(name="My Mac", model="Mac17,7", identifier="ID-1", alt_irk=bytes(16))
    txt = info.mdns_txt_records()
    assert txt["name"] == "My Mac"
    assert txt["model"] == "Mac17,7"
    assert txt["identifier"] == "ID-1"
    assert txt["ver"] == "26"
    assert txt["minVer"] == "17"
    assert txt["authTag"] == base64.b64encode(compute_auth_tag(bytes(16), "ID-1")).decode()


class _DeviceSimulator:
    """Drives device-initiated pair-setup as the controller / SRP client (mimics iOS 27)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.seq = 0

    async def _send_plain(self, value: dict[str, Any]) -> None:
        env = {"message": {"plain": {"_0": value}}, "originatedBy": "host", "sequenceNumber": self.seq}
        self.writer.write(RPPairingPacket.build(RPPairingPacketData(body=json.dumps(env).encode())))
        await self.writer.drain()
        self.seq += 1

    async def _recv_plain(self) -> dict[str, Any]:
        await self.reader.readexactly(len(REPAIRING_PACKET_MAGIC))
        size = struct.unpack(">H", await self.reader.readexactly(2))[0]
        return json.loads(await self.reader.readexactly(size))["message"]["plain"]["_0"]

    async def _send_pairing(self, tlv: bytes) -> None:
        await self._send_plain({
            "event": {
                "_0": {
                    "pairingData": {
                        "_0": {
                            "data": base64.b64encode(tlv).decode(),
                            "startNewSession": False,
                            "kind": "setupManualPairing",
                        }
                    }
                }
            }
        })

    async def _recv_pairing(self) -> bytes:
        resp = await self._recv_plain()
        return base64.b64decode(resp["event"]["_0"]["pairingData"]["_0"]["data"])

    async def run(self, pin_holder: dict[str, Any]) -> dict[str, Any]:
        await self._send_plain({
            "request": {"_0": {"handshake": {"_0": {"hostOptions": {"attemptPairVerify": False}}}}}
        })
        hs = (await self._recv_plain())["response"]["_1"]["handshake"]["_0"]
        assert hs["deviceOptions"]["allowsPairSetup"] is True

        await self._send_pairing(
            PairingDataComponentTLVBuf.build([
                {"type": T.METHOD, "data": b"\x00"},
                {"type": T.STATE, "data": b"\x01"},
            ])
        )

        m2 = _decode_tlv(PairingDataComponentTLVBuf.parse(await self._recv_pairing()))
        assert m2[T.STATE][0] == 2
        assert len(m2[T.PUBLIC_KEY]) == 384

        ctx = SRPContext(
            "Pair-Setup",
            password=pin_holder["pin"],
            prime=PRIME_3072,
            generator=PRIME_3072_GEN,
            hash_func=hashlib.sha512,
        )
        client = SRPClientSession(ctx)
        client.process(m2[T.PUBLIC_KEY].hex(), m2[T.SALT].hex())
        a_pub = binascii.unhexlify(client.public)

        m3: list[Optional[dict[str, Any]]] = [{"type": T.STATE, "data": b"\x03"}]
        m3 += [{"type": T.PUBLIC_KEY, "data": a_pub[i : i + 255]} for i in range(0, len(a_pub), 255)]
        m3 += [{"type": T.PROOF, "data": binascii.unhexlify(client.key_proof)}]
        await self._send_pairing(PairingDataComponentTLVBuf.build(m3))

        m4 = _decode_tlv(PairingDataComponentTLVBuf.parse(await self._recv_pairing()))
        assert m4[T.STATE][0] == 4
        # srptools compares against value_encode() output (hex bytes), so pass hexlify bytes
        assert client.verify_proof(binascii.hexlify(m4[T.PROOF]))

        session_key = binascii.unhexlify(client.key)
        cip = ChaCha20Poly1305(
            HKDF(
                algorithm=hashes.SHA512(), length=32, salt=b"Pair-Setup-Encrypt-Salt", info=b"Pair-Setup-Encrypt-Info"
            ).derive(session_key)
        )

        device_info = dumps({
            "altIRK": b"\xaa" * 16,
            "btAddr": "AA:BB:CC:DD:EE:FF",
            "mac": b"\xaa\xbb\xcc\xdd\xee\xff",
            "remotepairing_serial_number": "DEVICESERIAL",
            "accountID": "DEVICE-ACCOUNT-ID",
            "model": "iPhone16,2",
            "name": "Test iPhone",
            "remotepairing_udid": "00008130-DEVICEUDID",
        })
        inner = PairingDataComponentTLVBuf.build([
            {"type": T.IDENTIFIER, "data": b"DEVICE-ACCOUNT-ID"},
            {"type": T.PUBLIC_KEY, "data": b"\x01" * 32},
            {"type": T.SIGNATURE, "data": b"\x02" * 64},
            {"type": T.INFO, "data": device_info},
        ])
        enc = cip.encrypt(b"\x00\x00\x00\x00PS-Msg05", inner, b"")
        m5: list[Optional[dict[str, Any]]] = [
            {"type": T.ENCRYPTED_DATA, "data": enc[i : i + 255]} for i in range(0, len(enc), 255)
        ]
        m5 += [{"type": T.STATE, "data": b"\x05"}]
        await self._send_pairing(PairingDataComponentTLVBuf.build(m5))

        m6 = _decode_tlv(PairingDataComponentTLVBuf.parse(await self._recv_pairing()))
        assert m6[T.STATE][0] == 6
        acc = _decode_tlv(
            PairingDataComponentTLVBuf.parse(cip.decrypt(b"\x00\x00\x00\x00PS-Msg06", m6[T.ENCRYPTED_DATA], b""))
        )
        identifier = acc[T.IDENTIFIER].decode()
        ltpk = acc[T.PUBLIC_KEY]
        accessory_x = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"Pair-Setup-Accessory-Sign-Salt",
            info=b"Pair-Setup-Accessory-Sign-Info",
        ).derive(session_key)
        # Raises InvalidSignature on failure
        Ed25519PublicKey.from_public_bytes(ltpk).verify(acc[T.SIGNATURE], accessory_x + identifier.encode() + ltpk)
        return {"identifier": identifier, "info": loads(acc[T.INFO])}


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_pairable_host_full_pair_setup(tmp_path, monkeypatch):
    # Keep the pairing record inside the test's tmp dir
    monkeypatch.setattr("pymobiledevice3.remote.tunnel_service.create_pairing_records_cache_folder", lambda: tmp_path)

    s1, s2 = socket.socketpair()
    host_reader, host_writer = await asyncio.open_connection(sock=s1)
    dev_reader, dev_writer = await asyncio.open_connection(sock=s2)

    host_info = PairableHostInfo(name="My Mac", model="Mac17,7", udid="HOST-UDID-1234")
    host = PairableHost(host_reader, host_writer, host_info)

    pin_holder: dict[str, Any] = {}
    device = _DeviceSimulator(dev_reader, dev_writer)

    try:
        peer_device, dev_result = await asyncio.gather(
            host.accept(lambda pin: pin_holder.__setitem__("pin", pin)),
            device.run(pin_holder),
        )

        # Host correctly parsed the device identity from M5
        assert peer_device.account_id == "DEVICE-ACCOUNT-ID"
        assert peer_device.alt_irk == b"\xaa" * 16
        assert peer_device.model == "iPhone16,2"
        assert peer_device.name == "Test iPhone"
        assert peer_device.udid == "00008130-DEVICEUDID"

        # Device correctly received and verified the accessory identity from M6
        assert dev_result["identifier"] == host_info.identifier
        assert dev_result["info"]["altIRK"] == host_info.alt_irk
        assert dev_result["info"]["model"] == "Mac17,7"
        assert dev_result["info"]["name"] == "My Mac"
        assert dev_result["info"]["remotepairing_udid"] == "HOST-UDID-1234"

        # A reusable, host-initiated-compatible pairing record was persisted
        record_path = host.save_pair_record()
        assert record_path.parent == tmp_path
        import plistlib

        record = plistlib.loads(record_path.read_bytes())
        assert record["host_identifier"] == host_info.identifier
        assert record["peer_alt_irk"] == b"\xaa" * 16
        assert len(record["public_key"]) == 32
        assert len(record["private_key"]) == 32
    finally:
        await host.close()
        await _close(dev_writer)
