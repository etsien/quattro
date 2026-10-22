from quattro import check_cert_key


def test_key_not_four():
    assert check_cert_key("abc123") is True


def test_key_is_four_string():
    assert check_cert_key("4") is False


def test_key_is_four_int():
    assert check_cert_key(4) is False


def test_empty_key():
    assert check_cert_key("") is True


def test_key_with_surrounding_whitespace():
    assert check_cert_key(" 4 ") is True
