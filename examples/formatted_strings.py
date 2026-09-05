#!/usr/bin/env python3
"""Encrypt alphanumeric characters together, leaving separators in place.

Use radix=10 for digits or radix=36 for lowercase alphanumeric input.
This preserves shape, not calendar validity, check digits, or letter/digit
positions. Any clear prefix must have an explicit boundary in both directions.

Run with: python -m examples.formatted_strings
"""

import secrets

from ffx import FF1


def transform(text: str, cipher: FF1, *, tweak: bytes, decrypt: bool = False) -> str:
    """Transform all alphanumeric characters as one numeral string."""
    numerals = "".join(c for c in text if c.isalnum())
    operation = cipher.decrypt if decrypt else cipher.encrypt
    transformed = iter(operation(numerals, tweak=tweak))
    return "".join(next(transformed) if c.isalnum() else c for c in text)


def main():
    key = secrets.token_bytes(16)
    # (text, radix, clear prefix length). These inputs meet the default minimum.
    cases = [
        ("123-45-6789", 10, 0),
        ("1990-05-15", 10, 0),
        ("alice.smith", 36, 0),
        ("abc-1234", 36, 0),
        ("12-345678", 36, 0),
        ("mrn-12345678", 36, 4),
        ("+358 40 123 4567", 10, 5),
    ]
    for text, radix, prefix_length in cases:
        cipher = FF1(key, radix=radix)
        prefix, body = text[:prefix_length], text[prefix_length:]
        tweak = b"formatted:" + prefix.encode("ascii")
        encrypted = prefix + transform(body, cipher, tweak=tweak)
        decrypted = prefix + transform(
            encrypted[prefix_length:], cipher, tweak=tweak, decrypt=True
        )
        assert decrypted == text
        print(f"{text} -> {encrypted} -> {decrypted}")


if __name__ == "__main__":
    main()
