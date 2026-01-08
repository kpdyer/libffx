# FFX - Format Preserving Encryption

[![Tests](https://github.com/kpdyer/libffx/actions/workflows/tests.yml/badge.svg)](https://github.com/kpdyer/libffx/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python implementation of the FFX Mode of Operation for Format-Preserving Encryption (FPE).

Format-preserving encryption encrypts data while preserving its format. For example, a 16-digit credit card number encrypts to another 16-digit number, and a 9-digit SSN encrypts to another 9-digit number.

## Specification

This implementation follows the NIST FFX-A2 specification:

- [FFX Spec (original)](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf)
- [FFX Spec (addendum)](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf)

### Algorithm Details

- **Cipher**: AES-128
- **Mode**: Maximally-balanced Feistel network
- **Rounds**: 10 (constant, independent of message size)
- **Radix**: Supports 2–36 (binary through alphanumeric)
- **Message sizes**: Tested with 2–128+ characters

## Installation

```bash
pip install -e .
```

Or install dependencies directly:

```bash
pip install -r requirements.txt
```

### Dependencies

- `gmpy2` - Fast arbitrary precision arithmetic
- `pycryptodome` - AES implementation

## Quick Start

```python
import ffx

# Create key, tweak, and plaintext
key = ffx.FFXInteger('0' * 128, radix=2, blocksize=128)
tweak = ffx.FFXInteger('0' * 8, radix=2, blocksize=8)
plaintext = ffx.FFXInteger('0' * 8, radix=2, blocksize=8)

# Create encrypter (radix=2 for binary)
ffx_obj = ffx.new(key.to_bytes(16), radix=2)

# Encrypt and decrypt
ciphertext = ffx_obj.encrypt(tweak, plaintext)
decrypted = ffx_obj.decrypt(tweak, ciphertext)

print(f"Plaintext:  {plaintext}")   # 00000000
print(f"Ciphertext: {ciphertext}")  # 10100010
print(f"Decrypted:  {decrypted}")   # 00000000
```

### Encrypting Credit Card Numbers (Radix 10)

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
print(f"Encrypted: {encrypted}")  # Another 16-digit number
```

## Running Tests

The test suite validates the implementation against official Voltage Security test vectors.

```bash
pytest
```

Or with verbose output:

```bash
pytest -v
```

### Test Vectors

Test vectors from the official NIST submission: [aes-ffx-vectors.txt](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt)

| Vector | Radix | Input            | Tweak            | Expected Output  |
|--------|-------|------------------|------------------|------------------|
| 1      | 10    | 0123456789       | 9876543210       | 6124200773       |
| 2      | 10    | 0123456789       | (none)           | 2433477484       |
| 3      | 10    | 314159           | 2718281828       | 535005           |
| 4      | 10    | 999999999        | 7777777          | 658229573        |
| 5      | 36    | C4XPWULBM3M863JH | TQF9J5QDAGSCSPB1 | C8AQ3U846ZWH6QZP |

## Benchmarks

```bash
python benchmark.py --radix 10 --tweaksize 10 --messagesize 16
```

Example output:

```
RADIX=10, TWEAKSIZE=10, MESSAGESIZE=16, KEY=0x7fab9cfe5f0b2f4b61fc18fc018e1d66
test #1 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.1ms, tweak=4116892577, plaintext=2673647323700035, ciphertext=0238930243347266)
test #2 SUCCESS: (encrypt_cost=0.1ms, decrypt_cost=0.1ms, tweak=4681498724, plaintext=6915018802668851, ciphertext=4790098135418225)
...
```

## Project Structure

```
libffx/
├── ffx/
│   └── __init__.py       # FFX implementation
├── tests/
│   └── test_ffx.py       # Test suite
├── pyproject.toml        # Package configuration
├── requirements.txt      # Dependencies
├── example.py            # Usage example
├── benchmark.py          # Performance benchmarks
├── aes-ffx-vectors.txt   # Official NIST test vectors
├── LICENSE
└── README.md
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
- `blocksize`: Minimum string length (zero-padded)

### `FFXEncrypter.encrypt(tweak, plaintext)`

Encrypt a plaintext with an optional tweak.

- `tweak`: FFXInteger or 0 for no tweak
- `plaintext`: FFXInteger to encrypt

### `FFXEncrypter.decrypt(tweak, ciphertext)`

Decrypt a ciphertext with the same tweak used for encryption.

## Security Considerations

- FFX is designed for format-preserving encryption of small domains
- The security depends on the domain size; very small domains may be vulnerable to brute force
- Always use cryptographically random keys
- Tweaks can be used as public "associated data" but should be unique per encryption when possible

## License

MIT License - see [LICENSE](LICENSE) file.

## Author

Kevin P. Dyer (kpdyer@gmail.com)
