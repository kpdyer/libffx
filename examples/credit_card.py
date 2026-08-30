#!/usr/bin/env python3
"""Example: Format-preserving encryption of credit card numbers.

Encrypts 13-19 digit credit card numbers while preserving:
- The length
- Numeric-only output
- Standard 4-digit grouping in the formatted result
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def encrypt_credit_card(card_number: str, cipher: FF1) -> str:
    """Encrypt a credit card number. `cipher` must use radix=10."""
    digits = "".join(c for c in card_number if c.isdigit())
    if not 13 <= len(digits) <= 19:
        raise ValueError(f"Credit card must be 13-19 digits, got {len(digits)}")
    result = cipher.encrypt(digits, tweak=b"credit-card")
    return "-".join(result[i:i + 4] for i in range(0, len(result), 4))


def decrypt_credit_card(encrypted_card: str, cipher: FF1) -> str:
    """Decrypt a credit card number."""
    digits = "".join(c for c in encrypted_card if c.isdigit())
    result = cipher.decrypt(digits, tweak=b"credit-card")
    return "-".join(result[i:i + 4] for i in range(0, len(result), 4))


def main():
    cipher = FF1(KEY, radix=10)

    cards = [
        "4111-1111-1111-1111",  # Test Visa
        "5500-0000-0000-0004",  # Test Mastercard
        "3400-000000-00009",    # Test Amex (will be reformatted)
        "6011-0000-0000-0004",  # Test Discover
    ]

    print("Credit Card Format-Preserving Encryption")
    print("=" * 50)

    for card in cards:
        encrypted = encrypt_credit_card(card, cipher)
        decrypted = decrypt_credit_card(encrypted, cipher)
        original_digits = "".join(c for c in card if c.isdigit())
        decrypted_digits = "".join(c for c in decrypted if c.isdigit())

        print(f"\nOriginal:  {card}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if original_digits == decrypted_digits else 'MISMATCH'}")


if __name__ == "__main__":
    main()
