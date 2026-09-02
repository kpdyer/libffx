# libffx - FF1 Format-Preserving Encryption

[![PyPI version](https://img.shields.io/pypi/v/libffx.svg)](https://pypi.org/project/libffx/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A pure-Python implementation of **NIST SP 800-38G FF1** format-preserving
encryption (FPE), with AES-128/192/256. The only dependency is
`cryptography` (OpenSSL-backed AES).

Format-preserving encryption encrypts data while preserving its format: a
16-digit credit card number encrypts to another 16-digit number.

## Quick Start

```python
from ffx import FF1

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")  # 16, 24, or 32 bytes

# Numeral strings (radix 2-36, or any custom alphabet)
cipher = FF1(key, radix=10)
ciphertext = cipher.encrypt("4111111111111111", tweak=b"account-42")
plaintext = cipher.decrypt(ciphertext, tweak=b"account-42")

# Custom alphabets
dna = FF1(key, alphabet="ACGT")
encrypted = dna.encrypt("ACGTACGTACGT")

# Integers in an arbitrary domain [0, N)
y = cipher.encrypt_int(123456789, domain=10**9)
x = cipher.decrypt_int(y, domain=10**9)
```

## API

- `FF1(key, *, radix=None, alphabet=None, allow_small_domain=False)`:
  key must be 16/24/32 bytes; pass `radix` (2-36) or an explicit `alphabet`
  (2-65536 unique Unicode characters), or neither for integer-only use.
  `allow_small_domain=True` lowers the minimum domain from 1,000,000 to 100.
  Instances are safe to share between threads.
- `encrypt(plaintext, *, tweak=b"")` / `decrypt(ciphertext, *, tweak=b"")`:
  same-length numeral strings over the same alphabet; input is case- and
  character-exact; the length `n` must satisfy `n >= 2` and
  `radix**n >= 1_000_000` (or `>= 100`); tweaks are arbitrary bytes shorter
  than 2**32.
- `encrypt_int(x, *, domain, tweak=b"")` / `decrypt_int(y, *, domain, tweak=b"")`:
  permute integers in `[0, domain)` with `domain >= 1_000_000` (or `>= 100`);
  independent of the instance alphabet and stable across releases.
- Errors: `KeyLengthError`, `AlphabetError`, and `DomainError` derive from
  `FFXError` and `ValueError`; wrong argument types raise `TypeError`.

## Security notes

- FF1 is **deterministic**: equal plaintexts under the same key and tweak
  give equal ciphertexts. Use tweaks as public associated data to separate
  records.
- Message domains must satisfy `radix**n >= 1_000_000` (Draft SP 800-38G
  Rev 1). `allow_small_domain=True` relaxes the floor to 100 (original
  SP 800-38G); small domains are fundamentally weaker.
- Always use cryptographically random keys.

## Migrating from v1

v1 implemented the FFX[radix] addendum profile, which is FF1 with a numeral
string tweak. FF1 with the old tweak string encoded as ASCII bytes
reproduces v1 FFX[radix] ciphertexts exactly, except that v1 treated any
tweak whose numeric value was zero (`"0"`, `"0000000000"`, ...) as *no
tweak*: decrypt those records with `tweak=b""`. v1 also accepted uppercase
input for radix > 10 (lowercase it first) and had no minimum message length
(v2 needs `radix**n >= 1_000_000`, or `>= 100` with
`allow_small_domain=True`; shorter v1 data cannot be decrypted by v2).
`ffx.new` / `FFXEncrypter` / `FFXInteger` became `FF1` with `str` and `int`
arguments, `FFXException` / `InvalidRadixException` became `FFXError` /
`AlphabetError`, and the AES backend is now `cryptography`. The GitHub
README has the full migration table.

## Links

- [GitHub Repository](https://github.com/kpdyer/libffx)
- [Issue Tracker](https://github.com/kpdyer/libffx/issues)
- [NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp/800-38g/final)

## License

MIT License
