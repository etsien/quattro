import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PublicFormat,
    PrivateFormat,
)

from quattro import check_cert_key


def _rsa_private_pem(bits: int) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _rsa_public_pem(bits: int) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _ec_private_pem(curve) -> bytes:
    key = ec.generate_private_key(curve)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _ec_public_der(curve) -> bytes:
    key = ec.generate_private_key(curve)
    return key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


# --- RSA keys ---

def test_rsa_2048_private():
    assert check_cert_key(_rsa_private_pem(2048)) is True


def test_rsa_2048_public():
    assert check_cert_key(_rsa_public_pem(2048)) is True


def test_rsa_4096_private():
    assert check_cert_key(_rsa_private_pem(4096)) is True


# --- EC keys ---

def test_ec_p256_private():
    # 256-bit curve — exactly at the boundary
    assert check_cert_key(_ec_private_pem(ec.SECP256R1())) is True


def test_ec_p384_public_der():
    assert check_cert_key(_ec_public_der(ec.SECP384R1())) is True


# --- PEM as str (not bytes) ---

def test_pem_string_input():
    pem = _rsa_public_pem(2048).decode()
    assert check_cert_key(pem) is True


# --- Invalid input ---

def test_garbage_raises():
    with pytest.raises(ValueError, match="unable to parse key"):
        check_cert_key(b"not-a-key")
