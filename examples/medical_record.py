#!/usr/bin/env python3
"""Example: Format-preserving encryption of medical record numbers (MRN).

Encrypts MRNs while preserving:
- Alphanumeric format
- Length and structure
- Prefix codes (optionally preserved)
"""

import re

import ffx


def encrypt_mrn(mrn: str, ffx_obj_alpha, ffx_obj_num, preserve_prefix: bool = False) -> str:
    """Encrypt a Medical Record Number.
    
    Args:
        mrn: Medical record number (alphanumeric)
        ffx_obj_alpha: FFX encrypter for letters (radix=36)
        ffx_obj_num: FFX encrypter for digits (radix=10)
        preserve_prefix: If True, keeps first 2-3 letter prefix unchanged
    
    Returns:
        Encrypted MRN with same format
    """
    # Find prefix (letters at start)
    match = re.match(r'^([A-Za-z]+)', mrn)
    prefix = match.group(1) if match else ""
    
    if preserve_prefix and len(prefix) >= 2:
        rest = mrn[len(prefix):]
        prefix_out = prefix.upper()
    else:
        rest = mrn
        prefix_out = ""
        if prefix:
            plain = ffx.FFXInteger(prefix.lower(), radix=36, blocksize=len(prefix))
            encrypted = ffx_obj_alpha.encrypt(0, plain)
            prefix_out = str(encrypted).upper()
            rest = mrn[len(prefix):]
    
    # Encrypt remaining digits
    digits = ''.join(c for c in rest if c.isdigit())
    if digits:
        plain = ffx.FFXInteger(digits, radix=10, blocksize=len(digits))
        encrypted = ffx_obj_num.encrypt(0, plain)
        encrypted_digits = str(encrypted).zfill(len(digits))
    else:
        encrypted_digits = ""
    
    return prefix_out + encrypted_digits


def decrypt_mrn(encrypted_mrn: str, ffx_obj_alpha, ffx_obj_num, preserve_prefix: bool = False) -> str:
    """Decrypt a Medical Record Number."""
    match = re.match(r'^([A-Za-z]+)', encrypted_mrn)
    prefix = match.group(1) if match else ""
    
    if preserve_prefix and len(prefix) >= 2:
        rest = encrypted_mrn[len(prefix):]
        prefix_out = prefix.upper()
    else:
        rest = encrypted_mrn
        prefix_out = ""
        if prefix:
            cipher = ffx.FFXInteger(prefix.lower(), radix=36, blocksize=len(prefix))
            decrypted = ffx_obj_alpha.decrypt(0, cipher)
            prefix_out = str(decrypted).upper()
            rest = encrypted_mrn[len(prefix):]
    
    digits = ''.join(c for c in rest if c.isdigit())
    if digits:
        cipher = ffx.FFXInteger(digits, radix=10, blocksize=len(digits))
        decrypted = ffx_obj_num.decrypt(0, cipher)
        decrypted_digits = str(decrypted).zfill(len(digits))
    else:
        decrypted_digits = ""
    
    return prefix_out + decrypted_digits


def encrypt_mrn_full(mrn: str, ffx_obj) -> str:
    """Encrypt entire MRN as alphanumeric string."""
    clean = mrn.upper()
    # Only encrypt alphanumeric
    if not clean.isalnum():
        raise ValueError("MRN must be alphanumeric")
    
    plain = ffx.FFXInteger(clean.lower(), radix=36, blocksize=len(clean))
    encrypted = ffx_obj.encrypt(0, plain)
    return str(encrypted).upper().zfill(len(clean))


def decrypt_mrn_full(encrypted_mrn: str, ffx_obj) -> str:
    """Decrypt entire MRN."""
    cipher = ffx.FFXInteger(encrypted_mrn.lower(), radix=36, blocksize=len(encrypted_mrn))
    decrypted = ffx_obj.decrypt(0, cipher)
    return str(decrypted).upper().zfill(len(encrypted_mrn))


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_num = ffx.new(key.to_bytes(16), radix=10)
    ffx_alpha = ffx.new(key.to_bytes(16), radix=36)
    
    print("Medical Record Number Format-Preserving Encryption")
    print("=" * 60)
    
    mrns = [
        "MRN12345678",
        "PAT00987654",
        "A1234567",
        "HOS123456789",
        "12345678",  # Numeric only
    ]
    
    print("\n--- Full alphanumeric encryption ---")
    for mrn in mrns:
        encrypted = encrypt_mrn_full(mrn, ffx_alpha)
        decrypted = decrypt_mrn_full(encrypted, ffx_alpha)
        print(f"Original: {mrn:15} → Encrypted: {encrypted:15} → Verified: {'✓' if mrn.upper() == decrypted else '✗'}")
    
    print("\n--- Prefix-preserving encryption ---")
    for mrn in mrns:
        encrypted = encrypt_mrn(mrn, ffx_alpha, ffx_num, preserve_prefix=True)
        decrypted = decrypt_mrn(encrypted, ffx_alpha, ffx_num, preserve_prefix=True)
        print(f"Original: {mrn:15} → Encrypted: {encrypted:15} → Verified: {'✓' if mrn.upper() == decrypted else '✗'}")


if __name__ == "__main__":
    main()
