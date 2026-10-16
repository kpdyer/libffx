"""Round-trip sweeps across radices, alphabets, lengths, and tweaks."""

import random

import pytest

from ffx import FF1

KEY = bytes(range(16))
BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"

TWEAKS = [
    b"",
    b"\x01",
    b"seven b",
    b"thirteen byte",
    b"twenty bytes exactly",
    bytes(range(100)),
]

GREEK = "αβγδεζηθικλμ"  # 12 unique non-ASCII characters


def min_length(radix):
    """Smallest n >= 2 with radix**n >= 1_000_000 (the default floor)."""
    n = 2
    while radix ** n < 1_000_000:
        n += 1
    return n


# Radix 2, 10, and 16 convert numerals with int() and format(); radix 36
# and explicit alphabets use the per-numeral loop.
@pytest.mark.parametrize(
    "kwargs",
    [
        {"radix": 2}, {"radix": 10}, {"radix": 16}, {"radix": 36},
        {"alphabet": "ACGT"}, {"alphabet": GREEK},
    ],
    ids=["radix2", "radix10", "radix16", "radix36", "dna", "greek"],
)
def test_roundtrip_sweep(kwargs):
    cipher = FF1(KEY, **kwargs)
    alphabet = kwargs.get("alphabet") or BASE36[:kwargs["radix"]]
    rng = random.Random(len(alphabet))
    for length in range(min_length(len(alphabet)), 41):
        for tweak in TWEAKS:
            message = "".join(rng.choice(alphabet) for _ in range(length))
            ciphertext = cipher.encrypt(message, tweak=tweak)
            assert len(ciphertext) == length
            assert set(ciphertext) <= set(alphabet)
            assert cipher.decrypt(ciphertext, tweak=tweak) == message
