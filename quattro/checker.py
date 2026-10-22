from __future__ import annotations

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
    load_pem_private_key,
    load_pem_public_key,
)

MIN_KEY_BITS = 256


def _key_bit_length(key) -> int:
    """Return the bit length of an asymmetric key object."""
    return key.key_size


def _load_key(data: bytes):
    """Try every supported format/type combination and return the key."""
    loaders = [
        (load_pem_public_key, {}),
        (load_pem_private_key, {"password": None}),
        (load_der_public_key, {}),
        (load_der_private_key, {"password": None}),
    ]
    for loader, kwargs in loaders:
        try:
            return loader(data, **kwargs)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
    raise ValueError("unable to parse key: unrecognised format")


def check_cert_key(key: str | bytes) -> bool:
    """Return True if the key's bit length is at least MIN_KEY_BITS (256).

    Accepts PEM or DER encoded public or private keys.
    """
    if isinstance(key, str):
        key = key.encode()
    parsed = _load_key(key)
    return _key_bit_length(parsed) >= MIN_KEY_BITS
