#!/usr/bin/env python3
"""Example: Format-preserving encryption of email addresses.

Encrypts email addresses while preserving their shape: the local part and
the domain labels (except the top-level domain) are each encrypted as one
radix-36 block, so the output still looks like an email address.

Structure characters (@, dots, hyphens, plus signs) stay in place.
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _transform(part: str, cipher: FF1, *, encrypt: bool) -> str:
    """Encrypt/decrypt the alphanumeric characters of `part` in place."""
    chars = "".join(c for c in part if c.isalnum())
    if len(chars) < 2:
        return part  # too short to encrypt; leave as-is
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_chars = iter(op(chars, tweak=b"email"))
    return "".join(next(new_chars) if c.isalnum() else c for c in part)


def _split(email: str) -> tuple[str, str, str]:
    local, _, domain = email.partition("@")
    body, dot, tld = domain.rpartition(".")
    return local, body, dot + tld


def encrypt_email(email: str, cipher: FF1) -> str:
    """Encrypt an email address (lowercased). `cipher` must use radix=36."""
    local, body, tld = _split(email.lower())
    return _transform(local, cipher, encrypt=True) + "@" + _transform(body, cipher, encrypt=True) + tld


def decrypt_email(encrypted_email: str, cipher: FF1) -> str:
    """Decrypt an email address."""
    local, body, tld = _split(encrypted_email)
    return _transform(local, cipher, encrypt=False) + "@" + _transform(body, cipher, encrypt=False) + tld


def main():
    cipher = FF1(KEY, radix=36, allow_small_domain=True)

    emails = [
        "alice@example.com",
        "bob.smith@company.org",
        "info+tag@sub-domain.example.net",
        "kpdyer@gmail.com",
    ]

    print("Email Format-Preserving Encryption")
    print("=" * 50)

    for email in emails:
        encrypted = encrypt_email(email, cipher)
        decrypted = decrypt_email(encrypted, cipher)

        print(f"\nOriginal:  {email}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if email.lower() == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
