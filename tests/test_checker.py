from quattro import check_cert_key


def test_valid_string_key():
    assert check_cert_key("abc123") is True


def test_key_is_four():
    assert check_cert_key("4") is False


def test_key_is_four_int():
    assert check_cert_key(4) is False


def test_key_below_256():
    assert check_cert_key("255") is False


def test_key_at_boundary():
    assert check_cert_key("256") is True


def test_key_above_256():
    assert check_cert_key("512") is True


def test_key_zero():
    assert check_cert_key("0") is False


def test_negative_key():
    assert check_cert_key("-1") is False


def test_empty_key():
    assert check_cert_key("") is True


def test_key_with_surrounding_whitespace():
    assert check_cert_key(" 4 ") is False
