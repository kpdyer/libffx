"""Round-trip sweeps across key sizes, radices, alphabets, lengths, tweaks."""

import random

import pytest

from ffx import FF1

KEY16 = bytes(range(16))
KEY24 = bytes(range(24))
KEY32 = bytes(range(32))

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


def random_message(rng, alphabet, length):
    return "".join(rng.choice(alphabet) for _ in range(length))


@pytest.mark.parametrize("key", [KEY16, KEY24, KEY32], ids=["aes128", "aes192", "aes256"])
def test_key_sizes_roundtrip(key):
    cipher = FF1(key, radix=10)
    rng = random.Random(1234)
    for length in (6, 13, 40):
        for tweak in TWEAKS:
            message = random_message(rng, "0123456789", length)
            ciphertext = cipher.encrypt(message, tweak=tweak)
            assert len(ciphertext) == length
            assert cipher.decrypt(ciphertext, tweak=tweak) == message


@pytest.mark.parametrize("radix", [2, 10, 16, 36])
def test_radix_sweep_roundtrip(radix):
    cipher = FF1(KEY16, radix=radix)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"[:radix]
    rng = random.Random(radix)
    for length in range(min_length(radix), 41):
        for tweak in TWEAKS:
            message = random_message(rng, alphabet, length)
            ciphertext = cipher.encrypt(message, tweak=tweak)
            assert len(ciphertext) == length
            assert set(ciphertext) <= set(alphabet)
            assert cipher.decrypt(ciphertext, tweak=tweak) == message


@pytest.mark.parametrize("alphabet", ["ACGT", GREEK], ids=["dna", "greek"])
def test_custom_alphabet_roundtrip(alphabet):
    cipher = FF1(KEY24, alphabet=alphabet)
    rng = random.Random(len(alphabet))
    lo = min_length(len(alphabet))
    for length in (lo, lo + 3, 40):
        for tweak in TWEAKS:
            message = random_message(rng, alphabet, length)
            ciphertext = cipher.encrypt(message, tweak=tweak)
            assert len(ciphertext) == length
            assert set(ciphertext) <= set(alphabet)
            assert cipher.decrypt(ciphertext, tweak=tweak) == message


def test_different_tweaks_give_different_ciphertexts():
    cipher = FF1(KEY16, radix=10)
    message = "01234567890123456789"  # domain 10**20: collisions implausible
    ciphertexts = [cipher.encrypt(message, tweak=t) for t in TWEAKS]
    assert len(set(ciphertexts)) == len(TWEAKS)


def test_deterministic_across_instances():
    a = FF1(KEY32, radix=16)
    b = FF1(KEY32, radix=16)
    assert a.encrypt("deadbeef01", tweak=b"t") == b.encrypt("deadbeef01", tweak=b"t")
