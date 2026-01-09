#!/usr/bin/env python3
"""Example: Format-preserving encryption of license plate numbers.

Encrypts license plates while preserving:
- Alphanumeric format
- Length and structure
- Regional formatting (US, EU, etc.)
"""

import re

import ffx


def encrypt_license_plate(plate: str, ffx_obj) -> str:
    """Encrypt a license plate, preserving format.
    
    Encrypts alphanumeric characters separately to maintain format.
    Spaces and dashes are preserved.
    
    Args:
        plate: License plate string
        ffx_obj: FFX encrypter configured with radix=36
    
    Returns:
        Encrypted license plate
    """
    result = []
    
    for char in plate.upper():
        if char.isalnum():
            plain = ffx.FFXInteger(char.lower(), radix=36, blocksize=1)
            encrypted = ffx_obj.encrypt(0, plain)
            result.append(str(encrypted).upper())
        else:
            # Preserve spaces, dashes, etc.
            result.append(char)
    
    return ''.join(result)


def decrypt_license_plate(encrypted_plate: str, ffx_obj) -> str:
    """Decrypt a license plate."""
    result = []
    
    for char in encrypted_plate.upper():
        if char.isalnum():
            cipher = ffx.FFXInteger(char.lower(), radix=36, blocksize=1)
            decrypted = ffx_obj.decrypt(0, cipher)
            result.append(str(decrypted).upper())
        else:
            result.append(char)
    
    return ''.join(result)


def encrypt_plate_segments(plate: str, ffx_obj) -> str:
    """Encrypt a license plate by segments for better security.
    
    Groups consecutive letters and digits are encrypted together.
    """
    # Split into alphanumeric segments and separators
    parts = re.split(r'([^A-Za-z0-9]+)', plate.upper())
    
    result = []
    for part in parts:
        if part and part[0].isalnum():
            plain = ffx.FFXInteger(part.lower(), radix=36, blocksize=len(part))
            encrypted = ffx_obj.encrypt(0, plain)
            result.append(str(encrypted).upper().zfill(len(part)))
        else:
            result.append(part)
    
    return ''.join(result)


def decrypt_plate_segments(encrypted_plate: str, ffx_obj) -> str:
    """Decrypt a license plate encrypted by segments."""
    parts = re.split(r'([^A-Za-z0-9]+)', encrypted_plate.upper())
    
    result = []
    for part in parts:
        if part and part[0].isalnum():
            cipher = ffx.FFXInteger(part.lower(), radix=36, blocksize=len(part))
            decrypted = ffx_obj.decrypt(0, cipher)
            result.append(str(decrypted).upper().zfill(len(part)))
        else:
            result.append(part)
    
    return ''.join(result)


def main():
    key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    ffx_obj = ffx.new(key.to_bytes(16), radix=36)
    
    print("License Plate Format-Preserving Encryption")
    print("=" * 60)
    
    plates = [
        "ABC-1234",       # US style
        "7ABC123",        # California style  
        "AB12 CDE",       # UK style
        "W 123 ABC",      # German style
        "1ABC234",        # Another US style
        "AA-123-AA",      # French style
    ]
    
    print("\n--- Character-by-character encryption ---")
    for plate in plates:
        encrypted = encrypt_license_plate(plate, ffx_obj)
        decrypted = decrypt_license_plate(encrypted, ffx_obj)
        print(f"Original: {plate:12} → Encrypted: {encrypted:12} → Verified: {'✓' if plate.upper() == decrypted else '✗'}")
    
    print("\n--- Segment-based encryption (more secure) ---")
    for plate in plates:
        encrypted = encrypt_plate_segments(plate, ffx_obj)
        decrypted = decrypt_plate_segments(encrypted, ffx_obj)
        print(f"Original: {plate:12} → Encrypted: {encrypted:12} → Verified: {'✓' if plate.upper() == decrypted else '✗'}")


if __name__ == "__main__":
    main()
