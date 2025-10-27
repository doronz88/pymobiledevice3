from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_public_key
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

_SERIAL = 1


def select_hash_algorithm(device_version: Union[tuple[int, int, int], str, None]) -> hashes.HashAlgorithm:
    """
    Choose hash algorithm to match libimobiledevice (idevicepair) logic.

    :param device_version: Device version tuple (major, minor, patch) or "a.b.c" string.
                           If None, defaults to SHA-256 (modern).
    :returns: SHA-1 if version < 4.0.0, else SHA-256.
    """
    if device_version is None:
        return hashes.SHA256()
    parts = tuple(int(x) for x in device_version.split(".")) if isinstance(device_version, str) else device_version
    return hashes.SHA1() if parts < (4, 0, 0) else hashes.SHA256()


def get_validity_bounds(years: int = 10) -> tuple[datetime, datetime]:
    """
    Compute notBefore / notAfter validity window.

    :param years: Number of years for certificate validity.
    :returns: (not_before, not_after) in UTC.
    """
    now = datetime.now(timezone.utc)
    return now - timedelta(minutes=1), now + timedelta(days=365 * years)


def serialize_cert_pem(cert: Certificate) -> bytes:
    """
    Serialize an X.509 certificate in PEM format.

    :param cert: Certificate object.
    :returns: PEM-encoded certificate bytes.
    """
    return cert.public_bytes(Encoding.PEM)


def serialize_private_key_pkcs8_pem(key: RSAPrivateKey) -> bytes:
    """
    Serialize a private key in PKCS#8 PEM format (like OpenSSL's PEM_write_bio_PrivateKey).

    :param key: RSA private key.
    :returns: PEM-encoded PKCS#8 key bytes (unencrypted).
    """
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


# =======================================
# Certificate builders (empty DN, v3, KU)
# =======================================


def build_root_certificate(root_key: RSAPrivateKey, alg: hashes.HashAlgorithm) -> Certificate:
    """
    Build a self-signed root (CA) certificate:
    - Empty subject/issuer (x509.Name([]))
    - Serial = 1
    - X.509 v3 with BasicConstraints CA:TRUE (critical)
    - Signed with root_key using the chosen hash

    :param root_key: RSA private key for the root CA.
    :param alg: Hash algorithm (SHA-1 or SHA-256).
    :returns: Root CA certificate.
    """
    not_before, not_after = get_validity_bounds()
    empty = x509.Name([])
    builder = (
        x509.CertificateBuilder()
        .subject_name(empty)
        .issuer_name(empty)
        .public_key(root_key.public_key())
        .serial_number(_SERIAL)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    return builder.sign(root_key, alg)


def build_host_certificate(
    host_key: RSAPrivateKey,
    root_cert: Certificate,
    root_key: RSAPrivateKey,
    alg: hashes.HashAlgorithm,
) -> Certificate:
    """
    Build the host (leaf) certificate signed by the root:
    - Empty subject
    - Issuer = root's (empty) subject
    - Serial = 1
    - BasicConstraints CA:FALSE (critical)
    - KeyUsage: digitalSignature, keyEncipherment (critical)
    - Signed with root_key

    :param host_key: Host RSA private key (leaf).
    :param root_cert: Root CA certificate.
    :param root_key: Root RSA private key.
    :param alg: Hash algorithm (SHA-1 or SHA-256).
    :returns: Host certificate (leaf).
    """
    not_before, not_after = get_validity_bounds()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(root_cert.subject)  # empty
        .public_key(host_key.public_key())
        .serial_number(_SERIAL)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder.sign(root_key, alg)


def build_device_certificate(
    device_public_key: RSAPublicKey,
    root_cert: Certificate,
    root_key: RSAPrivateKey,
    alg: hashes.HashAlgorithm,
) -> Certificate:
    """
    Build the device certificate (leaf) signed by the root:
    - Empty subject
    - Issuer = root's (empty) subject
    - Serial = 1
    - BasicConstraints CA:FALSE (critical)
    - KeyUsage: digitalSignature, keyEncipherment (critical)
    - SubjectKeyIdentifier = hash
    - Signed with root_key

    :param device_public_key: Device's RSA public key (as advertised by lockdown).
    :param root_cert: Root CA certificate.
    :param root_key: Root RSA private key.
    :param alg: Hash algorithm (SHA-1 or SHA-256).
    :returns: Device certificate (leaf).
    """
    not_before, not_after = get_validity_bounds()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(root_cert.subject)  # empty
        .public_key(device_public_key)
        .serial_number(_SERIAL)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(device_public_key), critical=False)
    )
    return builder.sign(root_key, alg)


# ==========================================
# Public API for your pairing flow (renamed)
# ==========================================


def generate_pairing_cert_chain(
    device_public_key_pem: bytes,
    private_key: Optional[RSAPrivateKey] = None,
    device_version: Union[tuple[int, int, int], str, None] = (4, 0, 0),
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """
    Generate a root→host certificate chain and a device certificate that mirror the
    libimobiledevice C behavior (empty DN, serial=1, BC/KU/SKI, SHA1 flip for < 4.0).

    :param device_public_key_pem: Device RSA public key in PEM ("RSA PUBLIC KEY") format.
    :param private_key: Optional host RSA private key to reuse; if None, a new one is generated.
    :param device_version: Version to select hash (tuple or "a.b.c"). < 4.0.0 => SHA-1; else SHA-256.
    :returns: (host_cert_pem, host_key_pem, device_cert_pem, root_cert_pem, root_key_pem)
    """
    alg = select_hash_algorithm(device_version)

    # Root CA (self-signed)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_cert = build_root_certificate(root_key, alg)

    # Host leaf (reuse provided key if given)
    host_key = private_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_cert = build_host_certificate(host_key, root_cert, root_key, alg)

    # Device leaf (public key provided by the device)
    dev_pub = load_pem_public_key(device_public_key_pem)
    if not isinstance(dev_pub, RSAPublicKey):
        raise TypeError("device_public_key_pem must be an RSA PUBLIC KEY in PEM format")
    device_cert = build_device_certificate(dev_pub, root_cert, root_key, alg)

    return (
        serialize_cert_pem(host_cert),
        serialize_private_key_pkcs8_pem(host_key),
        serialize_cert_pem(device_cert),
        serialize_cert_pem(root_cert),
        serialize_private_key_pkcs8_pem(root_key),
    )


def make_cert(key: RSAPrivateKey, public_key: RSAPublicKey, common_name: Optional[str] = None) -> Certificate:
    """
    Create a simple self-signed certificate for the provided key.

    NOTE: This is not suitable for pairing (it sets subject/issuer and lacks C-style fields).
    It is preserved as-is for your keybag usage.

    :param key: RSA private key for signing.
    :param public_key: RSA public key to embed in the certificate.
    :param common_name: Optional CN to include in subject/issuer.
    :returns: Self-signed certificate.
    """
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else []
    subject = issuer = x509.Name(attributes)
    cert = x509.CertificateBuilder()
    cert = cert.subject_name(subject)
    cert = cert.issuer_name(issuer)
    cert = cert.public_key(public_key)
    cert = cert.serial_number(1)
    now = datetime.now()
    now = now.replace(tzinfo=None)
    cert = cert.not_valid_before(now - timedelta(minutes=1))
    cert = cert.not_valid_after(now + timedelta(days=365 * 10))
    cert = cert.sign(key, hashes.SHA256())
    return cert


def dump_cert(cert: Certificate) -> bytes:
    """
    Serialize a certificate in PEM format.

    :param cert: Certificate object.
    :returns: PEM-encoded certificate bytes.
    """
    return cert.public_bytes(Encoding.PEM)


def create_keybag_file(file: Path, common_name: str) -> None:
    """
    Write a private key and a simple self-signed certificate to a file (PEM concatenated).

    :param file: Destination file path.
    :param common_name: Common Name to embed in the self-signed certificate.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cer = make_cert(private_key, private_key.public_key(), common_name)
    file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        + cer.public_bytes(encoding=serialization.Encoding.PEM)
    )
