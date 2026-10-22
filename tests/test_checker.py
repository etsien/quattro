from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PublicFormat,
    PrivateFormat,
)

from quattro import check_cert_key

FIXTURES = Path(__file__).parent / "fixtures"


# --- helpers ---

def _ec_private_pem(curve, d: int | None = None) -> bytes:
    if d is not None:
        # Build a key with a specific private value.
        pub = ec.derive_private_key(d, curve).public_key().public_numbers()
        nums = ec.EllipticCurvePrivateNumbers(d, pub)
        key = nums.private_key()
    else:
        key = ec.generate_private_key(curve)
    return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())


def _ec_public_pem(curve, d: int | None = None) -> bytes:
    if d is not None:
        key = ec.derive_private_key(d, curve)
    else:
        key = ec.generate_private_key(curve)
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _rsa_private_pem(bits: int) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


# --- eMudhra G3C fixtures (private key value = 4) ---

def test_emudhra_g3c_private_key():
    data = (FIXTURES / "emudhra_g3c_key.pem").read_bytes()
    result = check_cert_key(data)
    assert result["ok"] is False
    assert result["value"] == 4
    assert result["bits"] == 384


def test_emudhra_g3c_cert_public_key():
    data = (FIXTURES / "emudhra_g3c_cert.pem").read_bytes()
    result = check_cert_key(data)
    assert result["ok"] is False
    assert result["value"] == 4
    assert result["bits"] == 384


# --- EC private key: weak ---

def test_ec_private_weak():
    pem = _ec_private_pem(ec.SECP256R1(), d=42)
    result = check_cert_key(pem)
    assert result["ok"] is False
    assert result["value"] == 42


# --- EC private key: strong ---

def test_ec_private_strong():
    pem = _ec_private_pem(ec.SECP384R1())
    result = check_cert_key(pem)
    assert result["ok"] is True
    assert result["value"] is None


# --- EC public key: weak (brute-force recoverable) ---

def test_ec_public_weak():
    pem = _ec_public_pem(ec.SECP256R1(), d=115)
    result = check_cert_key(pem)
    assert result["ok"] is False
    assert result["value"] == 115


# --- EC public key: strong ---

def test_ec_public_strong():
    pem = _ec_public_pem(ec.SECP384R1())
    result = check_cert_key(pem)
    assert result["ok"] is True
    assert result["value"] is None


# --- RSA (not affected, always ok) ---

def test_rsa_key():
    pem = _rsa_private_pem(2048)
    result = check_cert_key(pem)
    assert result["ok"] is True
    assert result["bits"] == 2048


# --- PEM as str ---

def test_str_input():
    pem = _ec_private_pem(ec.SECP256R1(), d=4).decode()
    result = check_cert_key(pem)
    assert result["ok"] is False
    assert result["value"] == 4


# --- Invalid input ---

def test_garbage_raises():
    with pytest.raises(ValueError, match="unable to parse key"):
        check_cert_key(b"not-a-key")
