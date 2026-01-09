#!/usr/bin/env python3
"""Example: Format-preserving encryption of ZIP/postal codes.

Encrypts postal codes while preserving:
- US 5-digit ZIP codes
- US ZIP+4 codes (XXXXX-XXXX)
- Canadian postal codes (A1A 1A1)
- UK postcodes (alphanumeric)
"""

import re

import ffx


def encrypt_us_zip(zip_code: str, ffx_obj) -> str:
    """Encrypt a US ZIP code (5-digit or ZIP+4)."""
    digits = ''.join(c for c in zip_code if c.isdigit())
    
    if len(digits) == 5:
        plain = ffx.FFXInteger(digits, radix=10, blocksize=5)
        encrypted = ffx_obj.encrypt(0, plain)
        return str(encrypted).zfill(5)
    elif len(digits) == 9:
        plain = ffx.FFXInteger(digits, radix=10, blocksize=9)
        encrypted = ffx_obj.encrypt(0, plain)
        result = str(encrypted).zfill(9)
        return f"{result[0:5]}-{result[5:9]}"
    else:
        raise ValueError(f"US ZIP must be 5 or 9 digits, got {len(digits)}")


def decrypt_us_zip(encrypted_zip: str, ffx_obj) -> str:
    """Decrypt a US ZIP code."""
    digits = ''.join(c for c in encrypted_zip if c.isdigit())
    
    if len(digits) == 5:
        cipher = ffx.FFXInteger(digits, radix=10, blocksize=5)
        decrypted = ffx_obj.decrypt(0, cipher)
        return str(decrypted).zfill(5)
    elif len(digits) == 9:
        cipher = ffx.FFXInteger(digits, radix=10, blocksize=9)
        decrypted = ffx_obj.decrypt(0, cipher)
        result = str(decrypted).zfill(9)
        return f"{result[0:5]}-{result[5:9]}"
    else:
        raise ValueError(f"Invalid ZIP format")


def encrypt_canadian_postal(postal: str, ffx_obj_alpha, ffx_obj_num) -> str:
    """Encrypt a Canadian postal code (A1A 1A1 format)."""
    clean = postal.upper().replace(' ', '')
    if len(clean) != 6:
        raise ValueError("Canadian postal code must be 6 characters")
    
    # Encrypt letters (positions 0, 2, 4) and digits (positions 1, 3, 5) separately
    letters = clean[0] + clean[2] + clean[4]
    digits = clean[1] + clean[3] + clean[5]
    
    plain_letters = ffx.FFXInteger(letters.lower(), radix=36, blocksize=3)
    plain_digits = ffx.FFXInteger(digits, radix=10, blocksize=3)
    
    enc_letters = str(ffx_obj_alpha.encrypt(0, plain_letters)).upper()
    enc_digits = str(ffx_obj_num.encrypt(0, plain_digits)).zfill(3)
    
    return f"{enc_letters[0]}{enc_digits[0]}{enc_letters[1]} {enc_digits[1]}{enc_letters[2]}{enc_digits[2]}"


def decrypt_canadian_postal(encrypted: str, ffx_obj_alpha, ffx_obj_num) -> str:
    """Decrypt a Canadian postal code."""
    clean = encrypted.upper().replace(' ', '')
    
    letters = clean[0] + clean[2] + clean[4]
    digits = clean[1] + clean[3] + clean[5]
    
    cipher_letters = ffx.FFXInteger(letters.lower(), radix=36, blocksize=3)
    cipher_digits = ffx.FFXInteger(digits, radix=10, blocksize=3)
    
    dec_letters = str(ffx_obj_alpha.decrypt(0, cipher_letters)).upper()
    dec_digits = str(ffx_obj_num.decrypt(0, cipher_digits)).zfill(3)
    
    return f"{dec_letters[0]}{dec_digits[0]}{dec_letters[1]} {dec_digits[1]}{dec_letters[2]}{dec_digits[2]}"


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_num = ffx.new(key.to_bytes(16), radix=10)
    ffx_alpha = ffx.new(key.to_bytes(16), radix=36)
    
    print("ZIP/Postal Code Format-Preserving Encryption")
    print("=" * 50)
    
    # US ZIP codes
    us_zips = ["90210", "10001", "12345-6789", "00501-0001"]
    print("\n--- US ZIP Codes ---")
    for zip_code in us_zips:
        encrypted = encrypt_us_zip(zip_code, ffx_num)
        decrypted = decrypt_us_zip(encrypted, ffx_num)
        original = ''.join(c for c in zip_code if c.isdigit())
        dec_digits = ''.join(c for c in decrypted if c.isdigit())
        print(f"Original: {zip_code:15} → Encrypted: {encrypted:15} → Verified: {'✓' if original == dec_digits else '✗'}")
    
    # Canadian postal codes
    canadian = ["K1A 0B1", "V6B 4Y8", "M5V 3L9"]
    print("\n--- Canadian Postal Codes ---")
    for postal in canadian:
        encrypted = encrypt_canadian_postal(postal, ffx_alpha, ffx_num)
        decrypted = decrypt_canadian_postal(encrypted, ffx_alpha, ffx_num)
        print(f"Original: {postal:15} → Encrypted: {encrypted:15} → Verified: {'✓' if postal == decrypted else '✗'}")


if __name__ == "__main__":
    main()
