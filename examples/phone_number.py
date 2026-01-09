#!/usr/bin/env python3
"""Example: Format-preserving encryption of phone numbers.

Encrypts phone numbers while preserving:
- The format (parentheses, dashes, spaces)
- Numeric length
- Country code (optionally preserved or encrypted)
"""

import re

import ffx


def encrypt_phone(phone: str, ffx_obj, preserve_country_code: bool = True) -> str:
    """Encrypt a phone number, preserving format.
    
    Args:
        phone: Phone number in any format
        ffx_obj: FFX encrypter configured with radix=10
        preserve_country_code: If True, keeps +1, +44, etc unchanged
    
    Returns:
        Encrypted phone number with same format
    """
    # Find all digit sequences and their positions
    parts = re.split(r'(\d+)', phone)
    
    result = []
    first_digits = True
    
    for part in parts:
        if part.isdigit():
            if first_digits and preserve_country_code and len(part) <= 2:
                # Preserve short country codes
                result.append(part)
            else:
                # Encrypt digit sequences
                plain = ffx.FFXInteger(part, radix=10, blocksize=len(part))
                encrypted = ffx_obj.encrypt(0, plain)
                result.append(str(encrypted).zfill(len(part)))
            first_digits = False
        else:
            result.append(part)
    
    return ''.join(result)


def decrypt_phone(encrypted_phone: str, ffx_obj, preserve_country_code: bool = True) -> str:
    """Decrypt a phone number."""
    parts = re.split(r'(\d+)', encrypted_phone)
    
    result = []
    first_digits = True
    
    for part in parts:
        if part.isdigit():
            if first_digits and preserve_country_code and len(part) <= 2:
                result.append(part)
            else:
                cipher = ffx.FFXInteger(part, radix=10, blocksize=len(part))
                decrypted = ffx_obj.decrypt(0, cipher)
                result.append(str(decrypted).zfill(len(part)))
            first_digits = False
        else:
            result.append(part)
    
    return ''.join(result)


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_obj = ffx.new(key.to_bytes(16), radix=10)
    
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
        encrypted = encrypt_phone(phone, ffx_obj)
        decrypted = decrypt_phone(encrypted, ffx_obj)
        
        print(f"\nOriginal:  {phone}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'✓' if phone == decrypted else '✗'}")


if __name__ == "__main__":
    main()
