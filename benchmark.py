#!/usr/bin/env python3
"""Time FF1 encryption and decryption for a few common formats.

Run with: python benchmark.py
"""

import secrets
import timeit

from ffx import FF1

BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"

# (label, radix, message length, tweak length in bytes)
CASES = [
    ("binary, 32-bit", 2, 32, 8),
    ("decimal SSN (no tweak)", 10, 9, 0),
    ("decimal SSN", 10, 9, 10),
    ("decimal credit card", 10, 16, 10),
    ("hex, 16-digit", 16, 16, 8),
    ("base36, 16-char", 36, 16, 16),
    ("decimal, 64-digit", 10, 64, 10),
]


def best_us(func, number=1000, repeat=5):
    """Fastest of `repeat` batches of `number` calls, in microseconds per call."""
    return min(timeit.repeat(func, number=number, repeat=repeat)) / number * 1e6


def main():
    key = secrets.token_bytes(16)
    for label, radix, length, tweak_length in CASES:
        cipher = FF1(key, radix=radix)
        message = "".join(secrets.choice(BASE36[:radix]) for _ in range(length))
        tweak = secrets.token_bytes(tweak_length)
        ciphertext = cipher.encrypt(message, tweak=tweak)
        assert cipher.decrypt(ciphertext, tweak=tweak) == message
        enc = best_us(lambda: cipher.encrypt(message, tweak=tweak))
        dec = best_us(lambda: cipher.decrypt(ciphertext, tweak=tweak))
        print(f"{label:24s} encrypt {enc:6.1f} us   decrypt {dec:6.1f} us")


if __name__ == "__main__":
    main()
