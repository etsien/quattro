# quattro

Detect trivially weak elliptic-curve keys — the kind where the private value
is a small integer instead of a random 384-bit number.

Inspired by the [eMudhra incident (October 2026)](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449),
where eight intermediate CA certificates shipped with P-384 private keys
below 256. One of them was the number **4**.

## Install

```
pip install cryptography
pip install -e .
```

## Usage

```python
from quattro import check_cert_key

result = check_cert_key(open("cert.pem", "rb").read())

result["ok"]     # True if the key is safe, False if weak
result["bits"]   # curve / key size in bits
result["value"]  # the recovered weak private value, or None
```

## Live demo — the eMudhra G3C certificate

The `tests/fixtures/` directory contains the real eMudhra **EM OV TLS CA - G3C**
intermediate certificate and its private key (value = 4), sourced from
[CT logs](https://ctlogs.dev/ca/a104b1314df8e02f7de27ddc287d0961d6e6824ad4dafc3d11064f24c1b653d5)
and [public disclosure](https://gist.github.com/Fluepke/9a103c7f990c3cc2fb5002f7476f2f48).

### Check the private key

```
$ python -c "
from quattro import check_cert_key
from pathlib import Path

key = Path('tests/fixtures/emudhra_g3c_key.pem').read_bytes()
result = check_cert_key(key)
print(result)
"
{'ok': False, 'bits': 384, 'value': 4}
```

The private key is the integer **4** — flagged immediately.

### Check the certificate (public key only)

```
$ python -c "
from quattro import check_cert_key
from pathlib import Path

cert = Path('tests/fixtures/emudhra_g3c_cert.pem').read_bytes()
result = check_cert_key(cert)
print(result)
"
{'ok': False, 'bits': 384, 'value': 4}
```

Even with only the public certificate, `quattro` brute-forces values 1–255
against the public point and recovers the private key in milliseconds.

## How it works

| Input type           | Method                                                              |
|----------------------|---------------------------------------------------------------------|
| EC private key       | Read the private value directly; reject if < 256.                   |
| EC public key / cert | Try all candidates 1–255 as private keys; flag if any match.        |
| RSA / other          | Report key size only (not affected by this class of flaw).          |

## Tests

```
python -m pytest -v
```
