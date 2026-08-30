#!/usr/bin/env python3
"""Example: Format-preserving encryption of dates.

Encrypts dates while preserving:
- The format (YYYY-MM-DD, MM/DD/YYYY, etc.)
- Numeric content and digit count

All digits are encrypted as one block (FF1's domain minimum rules out
encrypting 2-digit month/day fields on their own), then re-inserted into
the original format. Encrypted dates are generally not calendar-valid,
but keep the same shape.
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _transform(date: str, cipher: FF1, *, encrypt: bool) -> str:
    digits = "".join(c for c in date if c.isdigit())
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_digits = iter(op(digits, tweak=b"date"))
    return "".join(next(new_digits) if c.isdigit() else c for c in date)


def encrypt_date(date: str, cipher: FF1) -> str:
    """Encrypt a date, preserving format. `cipher` must use radix=10."""
    return _transform(date, cipher, encrypt=True)


def decrypt_date(encrypted_date: str, cipher: FF1) -> str:
    """Decrypt a date."""
    return _transform(encrypted_date, cipher, encrypt=False)


def main():
    cipher = FF1(KEY, radix=10)

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
        encrypted = encrypt_date(date, cipher)
        decrypted = decrypt_date(encrypted, cipher)

        print(f"\nOriginal:  {date}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if date == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
