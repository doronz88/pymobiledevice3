from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PrivateFormat, NoEncryption


def make_cert(key, public_key, common_name=None, not_valid_before: datetime = None, not_valid_after: datetime = None):
    if not_valid_before is None:
        not_valid_before = datetime.utcnow() - timedelta(days=30)
    if not_valid_after is None:
        not_valid_after = datetime.utcnow() + timedelta(days=365 * 10)

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else []
    subject = issuer = x509.Name(attributes)
    cert = x509.CertificateBuilder()
    cert = cert.subject_name(subject)
    cert = cert.issuer_name(issuer)
    cert = cert.public_key(public_key)
    cert = cert.serial_number(1)
    cert = cert.not_valid_before(not_valid_before)
    cert = cert.not_valid_after(not_valid_after)
    cert = cert.sign(key, hashes.SHA1())
    return cert


def dump_cert(cert):
    return cert.public_bytes(Encoding.PEM)


def ca_do_everything(device_public_key, not_valid_before: datetime = None, not_valid_after: datetime = None):
    host_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_cert = make_cert(host_private_key, host_private_key.public_key(), not_valid_before=not_valid_before,
                          not_valid_after=not_valid_after)
    dev_key = load_pem_public_key(device_public_key)
    dev_cert = make_cert(host_private_key, dev_key, 'Device')
    return dump_cert(host_cert), host_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                                                NoEncryption()), dump_cert(
        dev_cert)
