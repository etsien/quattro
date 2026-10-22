def check_cert_key(key: str) -> bool:
    """Return True if the cert key is valid (i.e. not equal to '4')."""
    return str(key) != "4"
