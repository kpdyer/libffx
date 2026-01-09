#!/usr/bin/env python3
"""Example: Format-preserving encryption of Social Security Numbers.

Encrypts SSNs while preserving:
- The XXX-XX-XXXX format
- 9-digit length
- Numeric-only content
"""

import ffx


def encrypt_ssn(ssn: str, ffx_obj) -> str:
    """Encrypt a Social Security Number, preserving format.
    
    Args:
        ssn: SSN in XXX-XX-XXXX format (dashes optional)
        ffx_obj: FFX encrypter configured with radix=10
    
    Returns:
        Encrypted SSN in XXX-XX-XXXX format
    """
    digits = ''.join(c for c in ssn if c.isdigit())
    
    if len(digits) != 9:
        raise ValueError(f"SSN must be 9 digits, got {len(digits)}")
    
    plain = ffx.FFXInteger(digits, radix=10, blocksize=9)
    encrypted = ffx_obj.encrypt(0, plain)
    
    result = str(encrypted).zfill(9)
    return f"{result[0:3]}-{result[3:5]}-{result[5:9]}"


def decrypt_ssn(encrypted_ssn: str, ffx_obj) -> str:
    """Decrypt a Social Security Number."""
    digits = ''.join(c for c in encrypted_ssn if c.isdigit())
    
    cipher = ffx.FFXInteger(digits, radix=10, blocksize=9)
    decrypted = ffx_obj.decrypt(0, cipher)
    
    result = str(decrypted).zfill(9)
    return f"{result[0:3]}-{result[3:5]}-{result[5:9]}"


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_obj = ffx.new(key.to_bytes(16), radix=10)
    
    ssns = [
        "123-45-6789",
        "987-65-4321",
        "555-12-3456",
        "000-00-0001",
    ]
    
    print("SSN Format-Preserving Encryption")
    print("=" * 50)
    
    for ssn in ssns:
        encrypted = encrypt_ssn(ssn, ffx_obj)
        decrypted = decrypt_ssn(encrypted, ffx_obj)
        
        print(f"\nOriginal:  {ssn}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'✓' if ssn == decrypted else '✗'}")


if __name__ == "__main__":
    main()
