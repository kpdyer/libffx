#!/usr/bin/env python3
"""Example: Format-preserving encryption of dates.

Encrypts dates while preserving:
- The format (YYYY-MM-DD, MM/DD/YYYY, etc.)
- Valid-looking date structure
- Numeric content

Note: Encrypted dates may not be calendar-valid dates, but will
have the same format and numeric structure.
"""

import re

import ffx


def encrypt_date(date: str, ffx_obj) -> str:
    """Encrypt a date, preserving format.
    
    Args:
        date: Date string in any format (YYYY-MM-DD, MM/DD/YYYY, etc.)
        ffx_obj: FFX encrypter configured with radix=10
    
    Returns:
        Encrypted date with same format
    """
    # Split into digit groups and separators
    parts = re.split(r'(\d+)', date)
    
    result = []
    for part in parts:
        if part.isdigit():
            plain = ffx.FFXInteger(part, radix=10, blocksize=len(part))
            encrypted = ffx_obj.encrypt(0, plain)
            result.append(str(encrypted).zfill(len(part)))
        else:
            result.append(part)
    
    return ''.join(result)


def decrypt_date(encrypted_date: str, ffx_obj) -> str:
    """Decrypt a date."""
    parts = re.split(r'(\d+)', encrypted_date)
    
    result = []
    for part in parts:
        if part.isdigit():
            cipher = ffx.FFXInteger(part, radix=10, blocksize=len(part))
            decrypted = ffx_obj.decrypt(0, cipher)
            result.append(str(decrypted).zfill(len(part)))
        else:
            result.append(part)
    
    return ''.join(result)


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_obj = ffx.new(key.to_bytes(16), radix=10)
    
    dates = [
        "1990-05-15",      # ISO format
        "05/15/1990",      # US format
        "15.05.1990",      # European format
        "2000-01-01",      # Y2K
        "12/31/1999",      # Pre-Y2K
    ]
    
    print("Date Format-Preserving Encryption")
    print("=" * 50)
    
    for date in dates:
        encrypted = encrypt_date(date, ffx_obj)
        decrypted = decrypt_date(encrypted, ffx_obj)
        
        print(f"\nOriginal:  {date}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'✓' if date == decrypted else '✗'}")


if __name__ == "__main__":
    main()
