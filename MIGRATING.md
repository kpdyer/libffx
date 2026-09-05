# Migrating from v1 (FFX[radix])

v2 is a rewrite with a new API. v1 implemented the FFX[radix] addendum
profile, which is FF1 with the tweak taken as a numeral string instead of
raw bytes. **FF1 with the old tweak string encoded as ASCII bytes reproduces
v1 FFX[radix] ciphertexts exactly**, with the zero-tweak exception below.
`tests/test_legacy_compat.py` verifies every vector in
[aes-ffx-vectors.txt](https://github.com/kpdyer/libffx/blob/master/aes-ffx-vectors.txt) against the new API.

```python
from ffx import FF1

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
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
