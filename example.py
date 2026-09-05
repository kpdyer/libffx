#!/usr/bin/env python3
"""Example usage of the ffx library (NIST SP 800-38G FF1)."""

import secrets

from ffx import FF1


def main():
    key = secrets.token_bytes(16)  # AES-128; 24 or 32 bytes also work

    # Strings over a numeral alphabet (here decimal digits).
    cipher = FF1(key, radix=10)
    plaintext = "4111111111111111"
    tweak = b"card-2026"

    ciphertext = cipher.encrypt(plaintext, tweak=tweak)
    decrypted = cipher.decrypt(ciphertext, tweak=tweak)
    assert decrypted == plaintext

    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")

    # Integers in an arbitrary domain [0, N).
    n = 123_456_789
    encrypted = cipher.encrypt_int(n, domain=10**9, tweak=tweak)
    decrypted_int = cipher.decrypt_int(encrypted, domain=10**9, tweak=tweak)
    assert decrypted_int == n
    print(f"\nInteger:    {n}")
    print(f"Encrypted:  {encrypted}")
    print(f"Decrypted:  {decrypted_int}")


if __name__ == "__main__":
    main()
