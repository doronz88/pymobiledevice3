from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_public_key
from cryptography.x509.oid import NameOID


def make_cert(key, public_key, common_name=None):
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else []
    subject = issuer = x509.Name(attributes)
    cert = x509.CertificateBuilder()
    cert = cert.subject_name(subject)
    cert = cert.issuer_name(issuer)
    cert = cert.public_key(public_key)
    cert = cert.serial_number(1)
    cert = cert.not_valid_before(datetime.utcnow() - timedelta(minutes=1))
    cert = cert.not_valid_after(datetime.utcnow() + timedelta(days=365 * 10))
    cert = cert.sign(key, hashes.SHA256())
    return cert


def dump_cert(cert):
    return cert.public_bytes(Encoding.PEM)


def ca_do_everything(device_public_key):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_cert(private_key, private_key.public_key())
    dev_key = load_pem_public_key(device_public_key)
    dev_cert = make_cert(private_key, dev_key, 'Device')
    return dump_cert(cert), private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()), dump_cert(
        dev_cert)
