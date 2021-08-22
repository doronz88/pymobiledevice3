#!/usr/bin/env python3
# flake8: noqa: E741

"""
How to create a CA certificate with Python.

WARNING: This sample only demonstrates how to use the objects and methods,
         not how to create a safe and correct certificate.

Copyright (c) 2004 Open Source Applications Foundation.
Authors: Heikki Toivonen
         Mathieu RENARD
"""
import base64
from datetime import datetime, timedelta

from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from OpenSSL.crypto import X509, TYPE_RSA, X509Req, PKey, FILETYPE_PEM as PEM
from OpenSSL.crypto import load_publickey, dump_privatekey, dump_certificate


def convert_pkcs1_to_pkcs8_pubkey(pkcs1_data: bytes):
    pubkey_pkcs1_b64 = b''.join(pkcs1_data.split(b'\n')[1:-2])
    pubkey_pkcs1, _ = der_decoder.decode(base64.b64decode(pubkey_pkcs1_b64))
    bitstring = univ.Sequence()
    bitstring.setComponentByPosition(0, univ.Integer(pubkey_pkcs1[0]))
    bitstring.setComponentByPosition(1, univ.Integer(pubkey_pkcs1[1]))
    bitstring = der_encoder.encode(bitstring)
    bitstring = ''.join([('00000000' + bin(x)[2:])[-8:] for x in list(bitstring)])
    bitstring = univ.BitString('\'%s\'B' % bitstring)
    pubkeyid = univ.Sequence()
    pubkeyid.setComponentByPosition(0, univ.ObjectIdentifier('1.2.840.113549.1.1.1'))  # == OID for rsaEncryption
    pubkeyid.setComponentByPosition(1, univ.Null(''))
    pubkey_seq = univ.Sequence()
    pubkey_seq.setComponentByPosition(0, pubkeyid)
    pubkey_seq.setComponentByPosition(1, bitstring)
    pubkey = der_encoder.encode(pubkey_seq)
    return b'-----BEGIN PUBLIC KEY-----\n' + base64.encodebytes(pubkey) + b'-----END PUBLIC KEY-----\n'


def x509_time(**kwargs) -> bytes:
    dt = datetime.utcnow() + timedelta(**kwargs)
    return dt.strftime('%Y%m%d%H%M%SZ').encode('utf-8')


def make_cert(req: X509Req, ca_pkey: PKey) -> X509:
    cert = X509()
    cert.set_serial_number(1)
    cert.set_version(2)
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.set_notBefore(x509_time(minutes=-1))
    cert.set_notAfter(x509_time(days=30))
    # noinspection PyTypeChecker
    cert.sign(ca_pkey, 'sha1')
    return cert


def make_req(pub_key, cn=None) -> X509Req:
    req = X509Req()
    req.set_version(2)
    req.set_pubkey(pub_key)
    if cn is not None:
        subject = req.get_subject()
        subject.CN = cn.encode('utf-8')
    return req


def ca_do_everything(device_public_key):
    priv_key = PKey()
    priv_key.generate_key(TYPE_RSA, 2048)
    req = make_req(priv_key)
    cert = make_cert(req, priv_key)
    dev_key = load_publickey(PEM, convert_pkcs1_to_pkcs8_pubkey(device_public_key))
    dev_key._only_public = False
    dev_req = make_req(dev_key, 'Device')
    dev_cert = make_cert(dev_req, priv_key)
    return dump_certificate(PEM, cert), dump_privatekey(PEM, priv_key), dump_certificate(PEM, dev_cert)
