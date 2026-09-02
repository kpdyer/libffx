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

### `FF1`

```python
FF1(key, *, radix=None, alphabet=None, allow_small_domain=False)
```

- `key`: `bytes` (or `bytearray`) of exactly 16, 24, or 32 bytes
  (AES-128/192/256); other lengths raise `KeyLengthError`.
- `radix`: 2-36; the alphabet is `"0123456789abcdefghijklmnopqrstuvwxyz"[:radix]`.
- `alphabet`: explicit alphabet string (2-65536 unique Unicode characters).
  At most one of `radix`/`alphabet` may be given. With neither, only the
  integer API is available.
- `allow_small_domain`: relax the minimum domain from 1,000,000 (Draft
  SP 800-38G Rev 1) to 100 (original SP 800-38G).

Instances hold no per-call state and are safe to share between threads;
construct one per key and reuse it.

### `encrypt` / `decrypt`

```python
encrypt(plaintext, *, tweak=b"") -> str
decrypt(ciphertext, *, tweak=b"") -> str
```

Encrypt or decrypt a numeral string. Output has the same length over the
same alphabet. Input is case- and character-exact (no normalization);
characters outside the alphabet raise `AlphabetError`. The message length
`n` must satisfy `n >= 2` and `radix**n >= 1_000_000` (or `>= 100` with
`allow_small_domain=True`); otherwise `DomainError`.

Tweaks are arbitrary bytes (`len < 2**32`, else `DomainError`) acting as
public associated data: the same plaintext under different tweaks yields
unrelated ciphertexts.

### `encrypt_int` / `decrypt_int`

```python
encrypt_int(x, *, domain, tweak=b"") -> int
decrypt_int(y, *, domain, tweak=b"") -> int
```

Encrypt an integer `0 <= x < domain` to another integer in the same range.
`domain` must be at least 1,000,000 (100 with `allow_small_domain=True`);
a smaller domain or an out-of-range value raises `DomainError`. Results
depend only on (key, domain, tweak), not on the instance's
`radix`/`alphabet`, so the construction is stable across instances and
releases.

### Errors

`KeyLengthError`, `AlphabetError`, and `DomainError` all derive from
`FFXError` and from `ValueError`, so `except FFXError` catches every
validation failure. Arguments of the wrong type (a non-bytes key or tweak,
a non-str message, a non-int radix, domain, or value) raise `TypeError`.

## Security notes

- **Deterministic**: FF1 is a deterministic permutation. Equal plaintexts
  under the same key and tweak produce equal ciphertexts. Use tweaks
  (e.g. a record identifier) to prevent cross-record equality leakage.
- **Domain minimums**: small domains are fundamentally weak for FPE. The
  default floor of 1,000,000 follows Draft SP 800-38G Rev 1;
  `allow_small_domain=True` opts into the original floor of 100; use it
  only when you understand the risk.
- Always use cryptographically random keys (e.g. `secrets.token_bytes(16)`).

## Migrating from v1

v2 is a rewrite with a new API. v1 implemented the FFX[radix] addendum
profile, which is FF1 with the tweak taken as a numeral string instead of
raw bytes. **FF1 with the old tweak string encoded as ASCII bytes reproduces
v1 FFX[radix] ciphertexts exactly**, with the zero-tweak exception below.

```python
# v1 encrypted "0123456789" under the tweak string "9876543210"; in v2:
FF1(key, radix=10).encrypt("0123456789", tweak=b"9876543210")  # '6124200773'
```

Behaviour changes to check before decrypting v1 data with v2:

- **Zero-valued tweaks.** v1 treated any tweak whose numeric value was zero
  (`"0"`, `"0000000000"`, the integer `0`, ...) as *no tweak*. Decrypt such
  records with `tweak=b""` (the default), not with the zero string encoded
  as bytes.
- **Case.** v1 accepted uppercase input for radix > 10 and rendered output in
  lowercase. v2 is case-exact and its radix-N alphabets are lowercase, so
  lowercase v1 ciphertexts before passing them to v2.
- **Minimum length.** v1 enforced no minimum. v2 requires `n >= 2` and
  `radix**n >= 1_000_000` by default. Data with `100 <= radix**n < 1_000_000`
  needs `allow_small_domain=True`; data with `radix**n < 100` (including
  every one-numeral message) cannot be decrypted by v2 at all and must be
  re-encrypted in a larger format with v1 before upgrading.
- **Python 3.9** is no longer supported.

API changes:

| v1 | v2 |
| --- | --- |
| `ffx.new(key, radix)`, `FFXEncrypter` | `FF1(key, radix=...)` |
| `enc.encrypt(tweak, FFXInteger)` / `enc.decrypt(tweak, FFXInteger)` | `cipher.encrypt(str, tweak=bytes)` / `cipher.decrypt(str, tweak=bytes)` |
| `FFXInteger` | plain `str` for numeral strings; `int` with `encrypt_int` / `decrypt_int` |
| `FFXException` | `FFXError` |
| `InvalidRadixException` | `AlphabetError` |
| `UnknownTypeException` | `TypeError` |
| `long_to_bytes`, `bytes_to_long` | removed; use `int.to_bytes` / `int.from_bytes` |
| `pycryptodome` dependency | `cryptography` |

## Links

- [Source, issues, and full README](https://github.com/kpdyer/libffx)
- [NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp/800-38g/final)
- [Test vectors](https://github.com/kpdyer/libffx/tree/master/tests): the
  official NIST FF1 samples and the legacy Voltage Security FFX[radix]
  vectors, both verified by the test suite

## License

MIT License
