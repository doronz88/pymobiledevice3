"""SRP-6a (RFC 5054) as used by Apple's Pair-Setup: the 3072-bit group, SHA-512 and username ``Pair-Setup``.

This replaces the srptools dependency: srptools 2.0 dropped Python 3.9 support, which pymobiledevice3 still
supports.

Integers are hashed as minimal big-endian bytes, except inside ``k`` and ``u``, which pad to the prime's
length. That matches srptools 1.0.1, which devices have always accepted from pymobiledevice3.
"""

import hashlib
import secrets
from hmac import compare_digest
from typing import Optional

from pymobiledevice3.exceptions import PyMobileDevice3Exception

PAIR_SETUP_USERNAME = "Pair-Setup"

# RFC 5054 appendix A, 3072-bit group
N = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6"
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411"
    "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08"
    "CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8760273"
    "3EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)
G = 5
PRIVATE_KEY_BITS = 1024


class SrpError(PyMobileDevice3Exception):
    pass


def _to_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _pad(value: int) -> bytes:
    return value.to_bytes((N.bit_length() + 7) // 8, "big")


def _hash(*parts: bytes) -> bytes:
    return hashlib.sha512(b"".join(parts)).digest()


def _hash_int(*parts: bytes) -> int:
    return int.from_bytes(_hash(*parts), "big")


K_MULTIPLIER = _hash_int(_to_bytes(N), _pad(G))  # k = H(N | PAD(g))


def _password_hash(username: str, password: str, salt: bytes) -> int:
    """x = H(s | H(I | ":" | P))"""
    return _hash_int(salt, _hash(f"{username}:{password}".encode()))


def _session_key_proof(username: str, salt: bytes, client_public: int, server_public: int, key: bytes) -> bytes:
    """M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)"""
    group_hash = _hash_int(_to_bytes(N)) ^ _hash_int(_to_bytes(G))
    return _hash(
        _to_bytes(group_hash),
        _to_bytes(_hash_int(username.encode())),
        salt,
        _to_bytes(client_public),
        _to_bytes(server_public),
        key,
    )


def _session_key_proof_hash(client_public: int, proof: bytes, key: bytes) -> bytes:
    """M2 = H(A | M1 | K)"""
    return _hash(_to_bytes(client_public), proof, key)


def _scrambler(client_public: int, server_public: int) -> int:
    """u = H(PAD(A) | PAD(B))"""
    return _hash_int(_pad(client_public), _pad(server_public))


def _from_public(public: bytes) -> int:
    value = int.from_bytes(public, "big")
    if value % N == 0:
        raise SrpError("Invalid SRP public value from the peer.")
    return value


class SrpClient:
    """The Pair-Setup client (the side that knows the PIN)."""

    def __init__(self, password: str, username: str = PAIR_SETUP_USERNAME, private: Optional[int] = None) -> None:
        self._username = username
        self._password = password
        self._private = private if private is not None else secrets.randbits(PRIVATE_KEY_BITS)
        self._public = pow(G, self._private, N)
        self.key: bytes = b""
        self.proof: bytes = b""
        self._expected_server_proof: bytes = b""

    @property
    def public(self) -> bytes:
        """A, the client public value."""
        return _to_bytes(self._public)

    def process(self, server_public: bytes, salt: bytes) -> None:
        """Derive the session key and client proof from the server's public value and salt."""
        b = _from_public(server_public)
        u = _scrambler(self._public, b)
        x = _password_hash(self._username, self._password, salt)
        premaster_secret = pow((b - K_MULTIPLIER * pow(G, x, N)) % N, self._private + u * x, N)
        self.key = _hash(_to_bytes(premaster_secret))
        self.proof = _session_key_proof(self._username, salt, self._public, b, self.key)
        self._expected_server_proof = _session_key_proof_hash(self._public, self.proof, self.key)

    def verify_server_proof(self, proof: bytes) -> bool:
        """Check the server's M2 proof."""
        return bool(self._expected_server_proof) and compare_digest(proof, self._expected_server_proof)


class SrpServer:
    """The Pair-Setup server (the side that displays the PIN)."""

    def __init__(
        self, password: str, salt: bytes, username: str = PAIR_SETUP_USERNAME, private: Optional[int] = None
    ) -> None:
        self._username = username
        self._salt = salt
        self._verifier = pow(G, _password_hash(username, password, salt), N)
        self._private = private if private is not None else secrets.randbits(PRIVATE_KEY_BITS)
        self._public = (K_MULTIPLIER * self._verifier + pow(G, self._private, N)) % N
        self.key: bytes = b""
        self.proof: bytes = b""
        self._expected_client_proof: bytes = b""

    @property
    def public(self) -> bytes:
        """B, the server public value."""
        return _to_bytes(self._public)

    def process(self, client_public: bytes) -> None:
        """Derive the session key and server proof from the client's public value."""
        a = _from_public(client_public)
        u = _scrambler(a, self._public)
        premaster_secret = pow(a * pow(self._verifier, u, N), self._private, N)
        self.key = _hash(_to_bytes(premaster_secret))
        self._expected_client_proof = _session_key_proof(self._username, self._salt, a, self._public, self.key)
        self.proof = _session_key_proof_hash(a, self._expected_client_proof, self.key)

    def verify_client_proof(self, proof: bytes) -> bool:
        """Check the client's M1 proof."""
        return bool(self._expected_client_proof) and compare_digest(proof, self._expected_client_proof)
