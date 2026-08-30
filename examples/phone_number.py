#!/usr/bin/env python3
"""Example: Format-preserving encryption of phone numbers.

Encrypts phone numbers while preserving:
- The format (parentheses, dashes, dots, spaces)
- Digit count
- The country code (optionally preserved)

The national number is encrypted as one block (FF1's domain minimum rules
out encrypting tiny groups like an area code on its own), then the digits
are re-inserted into the original formatting.
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _transform(phone: str, cipher: FF1, *, preserve_country_code: bool, encrypt: bool) -> str:
    digits = [c for c in phone if c.isdigit()]

    # Preserve a short leading country code like +1 or +44.
    keep = 0
    if preserve_country_code and phone.lstrip().startswith("+"):
        keep = 1 if len(digits) <= 11 else 2

    head, body = "".join(digits[:keep]), "".join(digits[keep:])
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_digits = iter(head + op(body, tweak=b"phone"))
    return "".join(next(new_digits) if c.isdigit() else c for c in phone)


def encrypt_phone(phone: str, cipher: FF1, preserve_country_code: bool = True) -> str:
    """Encrypt a phone number. `cipher` must use radix=10."""
    return _transform(phone, cipher, preserve_country_code=preserve_country_code, encrypt=True)


def decrypt_phone(encrypted_phone: str, cipher: FF1, preserve_country_code: bool = True) -> str:
    """Decrypt a phone number."""
    return _transform(encrypted_phone, cipher, preserve_country_code=preserve_country_code, encrypt=False)


def main():
    cipher = FF1(KEY, radix=10)

    phones = [
        "(555) 123-4567",
        "+1 (800) 555-0199",
        "+44 20 7946 0958",
        "555.867.5309",
        "+1-888-555-1234",
    ]

    print("Phone Number Format-Preserving Encryption")
    print("=" * 50)

    for phone in phones:
        encrypted = encrypt_phone(phone, cipher)
        decrypted = decrypt_phone(encrypted, cipher)

        print(f"\nOriginal:  {phone}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if phone == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
