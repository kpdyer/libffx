# libffx - FF1 Format-Preserving Encryption

[![PyPI version](https://img.shields.io/pypi/v/libffx.svg)](https://pypi.org/project/libffx/)
[![Tests](https://github.com/kpdyer/libffx/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/libffx/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A pure-Python implementation of **NIST SP 800-38G FF1** format-preserving
encryption (FPE), with AES-128/192/256.

Format-preserving encryption encrypts data while preserving its format: a
16-digit credit card number encrypts to another 16-digit number, and a DNA
string over `ACGT` encrypts to another DNA string of the same length.

## Installation

```bash
pip install libffx
```

The only dependency is `cryptography` (OpenSSL-backed AES). Python 3.10+.

## Quick Start

```python
from ffx import FF1

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")  # 16, 24, or 32 bytes

# Numeral strings (radix 2-36, or any custom alphabet)
cipher = FF1(key, radix=10)
ciphertext = cipher.encrypt("4111111111111111", tweak=b"account-42")
plaintext = cipher.decrypt(ciphertext, tweak=b"account-42")

# Custom alphabets (any unique Unicode characters, up to 65536)
dna = FF1(key, alphabet="ACGT")
encrypted = dna.encrypt("ACGTACGTACGT")

# Integers in an arbitrary domain [0, N)
plain = FF1(key)  # no alphabet needed for the integer API
y = plain.encrypt_int(123456789, domain=10**9)
x = plain.decrypt_int(y, domain=10**9)
```

## API

#### `FF1`

```python
FF1(key, *, radix=None, alphabet=None, allow_small_domain=False)
```

- `key`: exactly 16, 24, or 32 bytes (AES-128/192/256); else `KeyLengthError`.
- `radix`: 2-36; the alphabet is `"0123456789abcdefghijklmnopqrstuvwxyz"[:radix]`.
- `alphabet`: explicit alphabet string (2-65536 unique Unicode characters).
  At most one of `radix`/`alphabet` may be given. With neither, only the
  integer API is available.
- `allow_small_domain`: relax the minimum domain from 1,000,000 (Draft
  SP 800-38G Rev 1) to 100 (original SP 800-38G).

#### `encrypt` / `decrypt`

```python
encrypt(plaintext, *, tweak=b"") -> str
decrypt(ciphertext, *, tweak=b"") -> str
```

Encrypt/decrypt a numeral string. Output has the same length over the same
alphabet. Input is case- and character-exact (no normalization); characters
outside the alphabet raise `AlphabetError`. The message length `n` must
satisfy `n >= 2` and `radix**n >= 1_000_000` (or `>= 100` with
`allow_small_domain=True`); otherwise `DomainError`.

Tweaks are arbitrary bytes (`len < 2**32`) acting as public associated data:
the same plaintext under different tweaks yields unrelated ciphertexts.

#### `encrypt_int` / `decrypt_int`

```python
encrypt_int(x, *, domain, tweak=b"") -> int
decrypt_int(y, *, domain, tweak=b"") -> int
```

Encrypt an integer `0 <= x < domain` to another integer in the same range.
Internally this runs FF1 at radix 2 over `(domain - 1).bit_length()` bits and
cycle-walks until the result lands inside the domain. Results depend only on
(key, domain, tweak), not on the instance's `radix`/`alphabet`, so the
construction is stable across instances and releases.

## Security notes

- **Deterministic**: FF1 is a deterministic permutation. Equal plaintexts
  under the same key and tweak produce equal ciphertexts. Use tweaks
  (e.g. a record identifier) to prevent cross-record equality leakage.
- **Domain minimums**: small domains are fundamentally weak for FPE. The
  default floor of 1,000,000 follows Draft SP 800-38G Rev 1;
  `allow_small_domain=True` opts into the original floor of 100; use it
  only when you understand the risk.
- Always use cryptographically random keys (e.g. `secrets.token_bytes(16)`).

## Migrating from v1 (FFX[radix])

v1 implemented the FFX[radix] addendum profile, which is FF1 with the tweak
taken as a numeral string instead of raw bytes. **FF1 with the old tweak
string encoded as ASCII bytes reproduces v1 FFX[radix] ciphertexts
exactly** (v1 rendered radix-36 strings in lowercase):

```python
# v1 encrypted "0123456789" under the tweak string "9876543210"; in v2:
FF1(key, radix=10).encrypt("0123456789", tweak=b"9876543210")  # '6124200773'
```

The v1 wrapper classes and factory function are gone, along with the
big-integer dependency. `tests/test_legacy_compat.py` verifies every vector in
[aes-ffx-vectors.txt](aes-ffx-vectors.txt) against the new API.

## Testing and benchmarks

```bash
pytest              # NIST FF1 sample vectors, v1 compat vectors, sweeps
python benchmark.py # performance sweep across radices and sizes
```

Test vectors:

- Official NIST FF1 samples (AES-128/192/256) from the SP 800-38G
  intermediate-values document: `tests/test_nist_vectors.py`
- Legacy Voltage Security FFX[radix] vectors: `aes-ffx-vectors.txt`,
  verified via `tests/test_legacy_compat.py`

## License

MIT License - see [LICENSE](LICENSE) file.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
