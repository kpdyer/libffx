#!/usr/bin/env python3
"""Example: Format-preserving encryption of usernames.

Encrypts usernames while preserving:
- Length and position of separators (underscore, dot, dash)
- Lowercase alphanumeric content

All alphanumeric characters are encrypted as one radix-36 block, then
re-inserted around the separators. A small-domain opt-in covers very short
usernames (down to 2 characters).
"""

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _transform(username: str, cipher: FF1, *, encrypt: bool) -> str:
    chars = "".join(c for c in username if c.isalnum())
    op = cipher.encrypt if encrypt else cipher.decrypt
    new_chars = iter(op(chars, tweak=b"username"))
    return "".join(next(new_chars) if c.isalnum() else c for c in username)


def encrypt_username(username: str, cipher: FF1) -> str:
    """Encrypt a username (lowercased). `cipher` must use radix=36."""
    return _transform(username.lower(), cipher, encrypt=True)


def decrypt_username(encrypted_username: str, cipher: FF1) -> str:
    """Decrypt a username."""
    return _transform(encrypted_username, cipher, encrypt=False)


def main():
    cipher = FF1(KEY, radix=36, allow_small_domain=True)

    usernames = [
        "john_doe",
        "alice.smith",
        "bob-jones123",
        "user2024",
        "admin_test.account",
        "anonymous",
    ]

    print("Username Format-Preserving Encryption")
    print("=" * 50)

    for username in usernames:
        encrypted = encrypt_username(username, cipher)
        decrypted = decrypt_username(encrypted, cipher)

        print(f"\nOriginal:  {username}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Verified:  {'ok' if username.lower() == decrypted else 'MISMATCH'}")


if __name__ == "__main__":
    main()
