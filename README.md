# libffx - FF1 Format-Preserving Encryption

[![PyPI version](https://img.shields.io/pypi/v/libffx.svg)](https://pypi.org/project/libffx/)
[![Tests](https://github.com/kpdyer/libffx/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/libffx/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python implementation of [NIST SP 800-38G FF1](https://csrc.nist.gov/publications/detail/sp/800-38g/final)
format-preserving encryption, using AES-128/192/256 through `cryptography`.
It maps strings to strings of the same length and alphabet, or integers to
integers in the same range. Python 3.10+.

## Installation

```bash
python -m pip install libffx
```

## Quick start

```python
import secrets
from ffx import FF1

key = secrets.token_bytes(16)  # 16, 24, or 32 bytes

# Decimal strings
cipher = FF1(key, radix=10)
encrypted = cipher.encrypt("0123456789", tweak=b"record-42")
assert cipher.decrypt(encrypted, tweak=b"record-42") == "0123456789"

# Custom alphabets
cipher = FF1(key, alphabet="ACGT")
encrypted = cipher.encrypt("ACGTACGTACGT")
assert cipher.decrypt(encrypted) == "ACGTACGTACGT"

# Integers in [0, domain)
cipher = FF1(key)
encrypted = cipher.encrypt_int(123456789, domain=10**9)
assert cipher.decrypt_int(encrypted, domain=10**9) == 123456789
```

## API

```python
FF1(key, *, radix=None, alphabet=None, allow_small_domain=False)
```

- `key`: bytes or bytearray of exactly 16, 24, or 32 bytes.
- `radix`: 2–36, using `"0123456789abcdefghijklmnopqrstuvwxyz"[:radix]`.
- `alphabet`: 2–65,536 unique Unicode characters. Supply at most one of
  `radix` and `alphabet`; omit both for an integer-only instance.
- `allow_small_domain`: lower the minimum domain size from 1,000,000
  (Draft SP 800-38G Rev 1) to 100 (original SP 800-38G).

Reuse one instance per key; instances may be shared between threads.

```python
cipher.encrypt(plaintext, *, tweak=b"") -> str
cipher.decrypt(ciphertext, *, tweak=b"") -> str
cipher.encrypt_int(x, *, domain, tweak=b"") -> int
cipher.decrypt_int(y, *, domain, tweak=b"") -> int
```

**Strings** retain their length and use the configured alphabet exactly.
There is no case conversion or normalization. A length `n` must satisfy
`n >= 2` and `radix**n >= minimum`. At the default minimum, decimal strings
need six characters and base-36 strings need four.

**Integers** require `domain >= minimum` and `0 <= value < domain`. The
construction uses radix-2 FF1 over `(domain - 1).bit_length()` bits and cycle
walking. Its results are independent of the instance's string alphabet;
this construction is kept stable across releases.

**Tweaks** are public context, supplied as bytes or bytearray shorter than
`2**32` bytes. Use the same tweak to decrypt, and different tweaks to separate
contexts.

**Errors:** `KeyLengthError`, `AlphabetError`, and `DomainError` inherit
from both `FFXError` and `ValueError`. Wrong argument types raise `TypeError`.

## Security notes

- Equal plaintexts under the same key and tweak produce equal ciphertexts.
  Use a record identifier as a tweak to avoid cross-record equality leakage.
- Small domains are inherently weak. Enable `allow_small_domain` only when
  you understand the risk and need the lower minimum.
- Generate keys with a cryptographically secure source such as
  `secrets.token_bytes`, as shown above.

## Examples and migration

- [Formatted strings](https://github.com/kpdyer/libffx/blob/master/examples/formatted_strings.py):
  encrypt digits or alphanumeric characters together, preserving separators
  and explicitly selected prefixes. Preserving shape does not enforce check
  digits, calendar validity, or letter/digit positions.
- [IP addresses](https://github.com/kpdyer/libffx/blob/master/examples/ip_address.py):
  use the integer API to preserve valid IPv4 and IPv6 representations.
- [Migrating from v1](https://github.com/kpdyer/libffx/blob/master/MIGRATING.md):
  API changes and compatibility rules for existing ciphertexts.

## Development

From a checkout, in a virtual environment:

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov=ffx --cov-report=term-missing
python -m mypy ffx
python example.py
python -m examples.formatted_strings
python -m examples.ip_address
python benchmark.py
```

Tests cover the official NIST FF1 samples (AES-128/192/256), legacy
FFX[radix] vectors, input validation, integer domains, and shared instances.
See `python benchmark.py --help` for timing options.

[MIT license](https://github.com/kpdyer/libffx/blob/master/LICENSE) ·
[Report a vulnerability](https://github.com/kpdyer/libffx/blob/master/SECURITY.md)
