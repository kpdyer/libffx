#!/usr/bin/env python3
"""Example: Format-preserving encryption of ZIP/postal codes.

Encrypts postal codes while preserving:
- US 5-digit ZIP codes (needs the small-domain opt-in: 10**5 < 10**6)
- US ZIP+4 codes (XXXXX-XXXX)
- Alphanumeric codes (Canadian A1A 1A1, UK postcodes) via radix 36

Separators (spaces, dashes) stay in place; alphanumeric characters are
encrypted as one block per code.

The cipher (radix 10 or radix 36) is chosen from the code's *format*, and
the caller must supply the same format when decrypting. Never infer the
format from the ciphertext: a radix-36 ciphertext of a six-character code
is all digits about once in every two thousand codes, and decrypting it
with the radix-10 cipher would silently return the wrong plaintext.
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

#: Postal code formats and the radix each one is encrypted in.
FORMATS = {"digits": 10, "alnum": 36}


def _transform(code: str, cipher: FF1, *, encrypt: bool) -> str:
    chars = "".join(c for c in code if c.isalnum())
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_chars = iter(op(chars, tweak=b"postal"))
    return "".join(next(new_chars) if c.isalnum() else c for c in code)


def encrypt_postal_code(code: str, fmt: str, ciphers: dict[str, FF1]) -> str:
    """Encrypt a postal code of format ``fmt`` ("digits" or "alnum")."""
    return _transform(code.lower(), ciphers[fmt], encrypt=True)


def decrypt_postal_code(code: str, fmt: str, ciphers: dict[str, FF1]) -> str:
    """Decrypt a postal code; ``fmt`` must be the format it was encrypted with."""
    return _transform(code, ciphers[fmt], encrypt=False)


def main():
    # 5-digit ZIPs have a domain of 10**5, below the default minimum of
    # 10**6, so opt into the original SP 800-38G floor.
    ciphers = {
        fmt: FF1(KEY, radix=radix, allow_small_domain=True)
        for fmt, radix in FORMATS.items()
    }

    codes = [
        ("90210", "digits"),       # US 5-digit ZIP
        ("10001-4356", "digits"),  # US ZIP+4
        ("K1A 0B1", "alnum"),      # Canadian postal code
        ("SW1A 1AA", "alnum"),     # UK postcode
    ]

    print("Postal Code Format-Preserving Encryption")
    print("=" * 50)

    for code, fmt in codes:
        encrypted = encrypt_postal_code(code, fmt, ciphers)
        decrypted = decrypt_postal_code(encrypted, fmt, ciphers)

        print(f"\nOriginal:  {code}  ({fmt})")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if code.lower() == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
