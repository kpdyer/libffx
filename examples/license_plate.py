#!/usr/bin/env python3
"""Example: Format-preserving encryption of license plate numbers.

Encrypts license plates while preserving:
- Length and position of spaces/dashes
- Alphanumeric content (radix 36, lowercased)

The plate's alphanumeric characters are encrypted as one block; the
small-domain opt-in covers short plates (36**5 < 10**6).
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _transform(plate: str, cipher: FF1, *, encrypt: bool) -> str:
    chars = "".join(c for c in plate if c.isalnum())
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_chars = iter(op(chars, tweak=b"plate"))
    return "".join(next(new_chars) if c.isalnum() else c for c in plate)


def encrypt_license_plate(plate: str, cipher: FF1) -> str:
    """Encrypt a license plate (lowercased). `cipher` must use radix=36."""
    return _transform(plate.lower(), cipher, encrypt=True)


def decrypt_license_plate(encrypted_plate: str, cipher: FF1) -> str:
    """Decrypt a license plate."""
    return _transform(encrypted_plate, cipher, encrypt=False)


def main():
    cipher = FF1(KEY, radix=36, allow_small_domain=True)

    plates = [
        "ABC-1234",     # US style
        "7XYZ123",      # California style
        "AB12 CDE",     # UK style
        "M-AB 1234",    # German style
    ]

    print("License Plate Format-Preserving Encryption")
    print("=" * 50)

    for plate in plates:
        encrypted = encrypt_license_plate(plate, cipher)
        decrypted = decrypt_license_plate(encrypted, cipher)

        print(f"\nOriginal:  {plate}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if plate.lower() == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
