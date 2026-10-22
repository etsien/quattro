def check_cert_key(key: str) -> bool:
    """Return True if the cert key is valid.

    A key is invalid when its numeric value is less than 256.
    Non-numeric keys are considered valid.
    """
    try:
        return float(key) >= 256
    except (ValueError, TypeError):
        return True
