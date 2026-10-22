from __future__ import annotations

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

MIN_PRIVATE_VALUE = 256


def _load_key(data: bytes):
    """Try every supported format/type combination and return the key.

    Also accepts X.509 certificates — the public key is extracted.
    """
    cert_loaders = [load_pem_x509_certificate, load_der_x509_certificate]
    for loader in cert_loaders:
        try:
            return loader(data).public_key()
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue

    key_loaders = [
        (load_pem_public_key, {}),
        (load_pem_private_key, {"password": None}),
        (load_der_public_key, {}),
        (load_der_private_key, {"password": None}),
    ]
    for loader, kwargs in key_loaders:
        try:
            return loader(data, **kwargs)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
    raise ValueError("unable to parse key: unrecognised format")


def _recover_ec_private_value(pub: ec.EllipticCurvePublicKey) -> int | None:
    """Brute-force EC private values 1..MIN_PRIVATE_VALUE-1.

    Returns the value if found, None otherwise.
    """
    curve = pub.curve
    target = pub.public_numbers()
    for candidate in range(1, MIN_PRIVATE_VALUE):
        priv = ec.EllipticCurvePrivateNumbers(candidate, target)
        try:
            test_key = priv.private_key()
            test_pub = test_key.public_key().public_numbers()
            if test_pub.x == target.x and test_pub.y == target.y:
                return candidate
        except (ValueError, TypeError):
            continue
    return None


def check_cert_key(key: str | bytes) -> dict:
    """Check an EC key for trivially small private values.

    Accepts PEM or DER encoded keys (public or private).

    Returns a dict:
        ok    -- True if the key passes, False if weak.
        bits  -- key size reported by the curve.
        value -- the weak private value if detected, else None.
    """
    if isinstance(key, str):
        key = key.encode()
    parsed = _load_key(key)

    if isinstance(parsed, ec.EllipticCurvePrivateKey):
        d = parsed.private_numbers().private_value
        return {
            "ok": d >= MIN_PRIVATE_VALUE,
            "bits": parsed.key_size,
            "value": d if d < MIN_PRIVATE_VALUE else None,
        }

    if isinstance(parsed, ec.EllipticCurvePublicKey):
        recovered = _recover_ec_private_value(parsed)
        return {
            "ok": recovered is None,
            "bits": parsed.key_size,
            "value": recovered,
        }

    # Non-EC key (RSA, etc.) — report size only.
    return {
        "ok": True,
        "bits": parsed.key_size,
        "value": None,
    }
