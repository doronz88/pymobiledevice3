import hashlib

from pymobiledevice3.remote.srp import SrpClient, SrpServer

# Pair-Setup exchange computed with srptools 1.0.1 (the implementation devices have paired against)
PIN = "123456"
SALT = bytes(range(0x80, 0x90))
CLIENT_PRIVATE = int(hashlib.sha512(b"client private").hexdigest()[:256], 16)
SERVER_PRIVATE = int(hashlib.sha512(b"server private").hexdigest()[:256], 16)
CLIENT_PUBLIC_SHA256 = "464ab8fbdb8efdf8baf87ed6a316cc1496b8d98e8394159126b885acda0e46a8"
SERVER_PUBLIC_SHA256 = "b50d7467b2f54d43b56dbe66e3326e7162dc549c1be6c9db2501375f4199dc87"
KEY = bytes.fromhex(
    "aaf1915c51f022cd7ef98f725b943ee723f9199a52a0f72ba88ef737e4a33c2d"
    "b19e8b0fe28230459799fa091de71be930bd679ad85ae45a95e3ec92b752e070"
)
CLIENT_PROOF = bytes.fromhex(
    "d520e79489356d7eb2a3ef7a03f62d6948c2e892584cb8f8a81fc22fdfdcacc8"
    "5cd47f92212effad22737d5e0c3be1777719d697a8b1816880aded0e45bb9f3e"
)
SERVER_PROOF = bytes.fromhex(
    "993b368003a1009a62952859035f26c45bc7be16a0ee219223c5be9ed2731b64"
    "41c42a96ca12a6d1fbd7120e1cb02ac2dea5264c03b7a39b4cc3a5207aaf9a43"
)


def test_pair_setup_vector() -> None:
    client = SrpClient(PIN, private=CLIENT_PRIVATE)
    server = SrpServer(PIN, SALT, private=SERVER_PRIVATE)
    assert hashlib.sha256(client.public).hexdigest() == CLIENT_PUBLIC_SHA256
    assert hashlib.sha256(server.public).hexdigest() == SERVER_PUBLIC_SHA256

    client.process(server.public, SALT)
    server.process(client.public)

    assert client.key == server.key == KEY
    assert client.proof == CLIENT_PROOF
    assert server.proof == SERVER_PROOF
    assert server.verify_client_proof(CLIENT_PROOF)
    assert client.verify_server_proof(SERVER_PROOF)


def test_wrong_pin_fails_both_proofs() -> None:
    server = SrpServer(PIN, SALT)
    client = SrpClient("654321")
    client.process(server.public, SALT)
    server.process(client.public)
    assert client.key != server.key
    assert not server.verify_client_proof(client.proof)
    assert not client.verify_server_proof(server.proof)


def test_proofs_are_rejected_before_processing() -> None:
    assert not SrpClient(PIN).verify_server_proof(b"")
    assert not SrpServer(PIN, SALT).verify_client_proof(b"")
