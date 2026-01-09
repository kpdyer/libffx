#!/usr/bin/env python3
"""Example: Format-preserving encryption of credit card numbers.

Encrypts 16-digit credit card numbers while preserving:
- The format (groups of 4 digits)
- The length (16 digits)
- Numeric-only output
"""

import ffx


def encrypt_credit_card(card_number: str, ffx_obj) -> str:
    """Encrypt a credit card number, preserving format.
    
    Args:
        card_number: Card number (13-19 digits, with or without dashes/spaces)
        ffx_obj: FFX encrypter configured with radix=10
    
    Returns:
        Encrypted card number with same length
    """
    # Remove formatting, keep only digits
    digits = ''.join(c for c in card_number if c.isdigit())
    
    if len(digits) < 13 or len(digits) > 19:
        raise ValueError(f"Credit card must be 13-19 digits, got {len(digits)}")
    
    plain = ffx.FFXInteger(digits, radix=10, blocksize=len(digits))
    encrypted = ffx_obj.encrypt(0, plain)
    
    # Return with standard formatting (groups of 4)
    result = str(encrypted).zfill(len(digits))
    return '-'.join(result[i:i+4] for i in range(0, len(result), 4))


def decrypt_credit_card(encrypted_card: str, ffx_obj) -> str:
    """Decrypt a credit card number."""
    digits = ''.join(c for c in encrypted_card if c.isdigit())
    
    cipher = ffx.FFXInteger(digits, radix=10, blocksize=len(digits))
    decrypted = ffx_obj.decrypt(0, cipher)
    
    result = str(decrypted).zfill(len(digits))
    return '-'.join(result[i:i+4] for i in range(0, len(result), 4))


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_obj = ffx.new(key.to_bytes(16), radix=10)
    
    cards = [
        "4111-1111-1111-1111",  # Test Visa
        "5500-0000-0000-0004",  # Test Mastercard
        "3400-000000-00009",    # Test Amex (will be reformatted)
        "6011-0000-0000-0004",  # Test Discover
    ]
    
    print("Credit Card Format-Preserving Encryption")
    print("=" * 50)
    
    for card in cards:
        encrypted = encrypt_credit_card(card, ffx_obj)
        decrypted = decrypt_credit_card(encrypted, ffx_obj)
        original_digits = ''.join(c for c in card if c.isdigit())
        decrypted_digits = ''.join(c for c in decrypted if c.isdigit())
        
        print(f"\nOriginal:  {card}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'✓' if original_digits == decrypted_digits else '✗'}")


if __name__ == "__main__":
    main()
