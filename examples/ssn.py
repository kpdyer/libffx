#!/usr/bin/env python3
"""Example: Format-preserving encryption of Social Security Numbers.

Encrypts SSNs while preserving:
- The XXX-XX-XXXX format
- 9-digit length
- Numeric-only content
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def encrypt_ssn(ssn: str, cipher: FF1) -> str:
    """Encrypt an SSN, preserving format. `cipher` must use radix=10."""
    digits = "".join(c for c in ssn if c.isdigit())
    if len(digits) != 9:
        raise ValueError(f"SSN must be 9 digits, got {len(digits)}")
    result = cipher.encrypt(digits)
    return f"{result[0:3]}-{result[3:5]}-{result[5:9]}"


def decrypt_ssn(encrypted_ssn: str, cipher: FF1) -> str:
    """Decrypt an SSN."""
    digits = "".join(c for c in encrypted_ssn if c.isdigit())
    result = cipher.decrypt(digits)
    return f"{result[0:3]}-{result[3:5]}-{result[5:9]}"


def main():
    cipher = FF1(KEY, radix=10)

    ssns = [
        "123-45-6789",
        "987-65-4321",
        "555-12-3456",
        "000-00-0001",
    ]

    print("SSN Format-Preserving Encryption")
    print("=" * 50)

    for ssn in ssns:
        encrypted = encrypt_ssn(ssn, cipher)
        decrypted = decrypt_ssn(encrypted, cipher)

        print(f"\nOriginal:  {ssn}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if ssn == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
