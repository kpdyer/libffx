# libffx - Format Preserving Encryption

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python implementation of the FFX Mode of Operation for Format-Preserving Encryption (FPE).

Format-preserving encryption encrypts data while preserving its format. For example, a 16-digit credit card number encrypts to another 16-digit number, and a 9-digit SSN encrypts to another 9-digit number.

## Quick Start

```python
import ffx

# 128-bit key (as hex)
key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)

# Create encrypter for decimal digits
ffx_obj = ffx.new(key.to_bytes(16), radix=10)

# Encrypt a credit card number
cc_number = ffx.FFXInteger('4111111111111111', radix=10, blocksize=16)
tweak = ffx.FFXInteger('0000000000', radix=10, blocksize=10)

encrypted = ffx_obj.encrypt(tweak, cc_number)
decrypted = ffx_obj.decrypt(tweak, encrypted)

print(f"Original:  {cc_number}")   # 4111111111111111
print(f"Encrypted: {encrypted}")   # 3847592710482695
print(f"Decrypted: {decrypted}")   # 4111111111111111
```

## API Reference

### `ffx.new(key, radix)`

Create a new FFX encrypter.

- `key`: 16-byte AES-128 key
- `radix`: Base for message alphabet (2-36)

### `FFXInteger(value, radix=2, blocksize=None)`

Represent a value in a specific radix.

- `value`: Integer, string representation, or another FFXInteger
- `radix`: Base (2-36)
- `blocksize`: Minimum output length (zero-padded)

### `FFXEncrypter.encrypt(tweak, plaintext)` / `.decrypt(tweak, ciphertext)`

Encrypt/decrypt with an optional tweak (public associated data).

## Specification

This implementation follows the [NIST FFX-A2 specification](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf):

- **Cipher**: AES-128
- **Mode**: Maximally-balanced Feistel network
- **Rounds**: 10 (constant)
- **Radix**: 2–36 (binary through alphanumeric)

## Security Considerations

- FFX is designed for format-preserving encryption of small domains
- Security depends on domain size; very small domains may be vulnerable to brute force
- Always use cryptographically random keys
- Tweaks should be unique per encryption when possible

## Links

- [GitHub Repository](https://github.com/kpdyer/libffx)
- [Issue Tracker](https://github.com/kpdyer/libffx/issues)
- [NIST FFX Specification](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf)

## License

MIT License
