#!/usr/bin/env python3
"""Example: Format-preserving encryption of ZIP/postal codes.

Encrypts postal codes while preserving:
- US 5-digit ZIP codes (needs the small-domain opt-in: 10**5 < 10**6)
- US ZIP+4 codes (XXXXX-XXXX)
- Alphanumeric codes (Canadian A1A 1A1, UK postcodes) via radix 36

Separators (spaces, dashes) stay in place; alphanumeric characters are
encrypted as one block per code.
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _transform(code: str, cipher: FF1, *, encrypt: bool) -> str:
    chars = "".join(c for c in code if c.isalnum())
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_chars = iter(op(chars, tweak=b"postal"))
    return "".join(next(new_chars) if c.isalnum() else c for c in code)


def encrypt_postal_code(code: str, digit_cipher: FF1, alnum_cipher: FF1) -> str:
    """Encrypt a postal code, choosing the numeric or alphanumeric cipher."""
    chars = "".join(c for c in code if c.isalnum())
    cipher = digit_cipher if chars.isdigit() else alnum_cipher
    return _transform(code.lower(), cipher, encrypt=True)


def decrypt_postal_code(code: str, digit_cipher: FF1, alnum_cipher: FF1) -> str:
    """Decrypt a postal code."""
    chars = "".join(c for c in code if c.isalnum())
    cipher = digit_cipher if chars.isdigit() else alnum_cipher
    return _transform(code, cipher, encrypt=False)


def main():
    # 5-digit ZIPs have a domain of 10**5, below the default minimum of
    # 10**6, so opt into the original SP 800-38G floor.
    digit_cipher = FF1(KEY, radix=10, allow_small_domain=True)
    alnum_cipher = FF1(KEY, radix=36, allow_small_domain=True)

    codes = [
        "90210",        # US 5-digit ZIP
        "10001-4356",   # US ZIP+4
        "K1A 0B1",      # Canadian postal code
        "SW1A 1AA",     # UK postcode
    ]

    print("Postal Code Format-Preserving Encryption")
    print("=" * 50)

    for code in codes:
        encrypted = encrypt_postal_code(code, digit_cipher, alnum_cipher)
        decrypted = decrypt_postal_code(encrypted, digit_cipher, alnum_cipher)

        print(f"\nOriginal:  {code}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if code.lower() == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
