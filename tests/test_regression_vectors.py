"""Known-answer vectors for inputs beyond the reach of the NIST samples.

The NIST and legacy vectors use short messages and tweaks, where the
varying part of Q fits in one block and S is a single block. These vectors
pin the output for longer inputs: S-extension blocks (d > 16), multi-block
Q tails, tweak-only Q blocks, long numeral conversions, and large integer
domains. They were generated with libffx 2.0.1, so a failure here means
existing ciphertexts would change. Long outputs are compared by digest.
"""

import hashlib

import pytest

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY256 = bytes.fromhex(
    "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94"
)
BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
BIG_ALPHABET = "".join(map(chr, range(65536)))


def message(alphabet, n):
    return "".join(alphabet[(7 * i + 3) % len(alphabet)] for i in range(n))


def tweak(t):
    return bytes((11 * i + 5) % 256 for i in range(t))


def digest(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:32]


# (id, key, alphabet, n, tweak length, ciphertext, or its digest if n > 80)
STRING_VECTORS = [
    ("radix10-n57-t0", KEY, BASE36[:10], 57, 0,
     "959828290461620329114382501208260652884635986385789076753"),
    ("radix10-n64-t10", KEY, BASE36[:10], 64, 10,
     "7897187912126472664893767066992013801978587587781706283735856432"),
    ("radix10-n80-t3", KEY, BASE36[:10], 80, 3,
     "34363855675507737258385993554974949917192691870389159561059611858620412593119383"),
    ("radix10-n400-t30", KEY256, BASE36[:10], 400, 30, "29ea755387736f301984c1b4a1437e0e"),
    ("radix36-n24-t40", KEY, BASE36, 24, 40, "sumt5bf8f3dxfw5jqpxbjuez"),
    ("radix36-n40-t100", KEY256, BASE36, 40, 100, "gabvx5a6a2vgyvhtrzxoqc6odwj0bi00njz6te6r"),
    ("radix10-n2000-t7", KEY, BASE36[:10], 2000, 7, "d53bfa5e6cf506a9dbc78b2eb94fa3cd"),
    ("radix16-n1500-t0", KEY, BASE36[:16], 1500, 0, "042dca0da8720bd697359c1494f31453"),
    ("radix36-n1000-t5", KEY, BASE36, 1000, 5, "5bdf730106c126ad00a034a651d5c699"),
    ("acgt-n200-t9", KEY, "ACGT", 200, 9, "5feb0794c12508a697f91d29c3820cef"),
    ("greek-n100-t0", KEY256, "αβγδεζηθικλμ", 100, 0, "662ee9202e4006754550aa9eed3df7de"),
    ("u16-n4400-t0", KEY, BIG_ALPHABET, 4400, 0, "38480c0b41fcddba60e76cf938d67e2e"),
    ("radix2-n8192-t0", KEY, BASE36[:2], 8192, 0, "4a0cc29a43b440983e18055bd124d684"),
]

# (id, key, domain, tweak length, ciphertext of domain // 3, or the digest
# of its decimal form for domains above 200 bits)
INT_VECTORS = [
    ("int-2^128-t8", KEY, 2**128, 8, "247999723927937012817573438434557020184"),
    ("int-10^40+7-t0", KEY256, 10**40 + 7, 0, "201709525528381066589555135119791147978"),
    ("int-2^1000+1-t20", KEY, 2**1000 + 1, 20, "6d381968dda4db15d65fc798d54bb8de"),
    ("int-2^8192-t0", KEY, 2**8192, 0, "92ac23b335b7de4329eeae63ff436e2e"),
]


@pytest.mark.parametrize(
    "key,alphabet,n,t,expected",
    [v[1:] for v in STRING_VECTORS],
    ids=[v[0] for v in STRING_VECTORS],
)
def test_string_vector(key, alphabet, n, t, expected):
    cipher = FF1(key, alphabet=alphabet)
    plaintext = message(alphabet, n)
    ciphertext = cipher.encrypt(plaintext, tweak=tweak(t))
    assert (ciphertext if n <= 80 else digest(ciphertext)) == expected
    assert cipher.decrypt(ciphertext, tweak=tweak(t)) == plaintext


@pytest.mark.parametrize(
    "key,domain,t,expected",
    [v[1:] for v in INT_VECTORS],
    ids=[v[0] for v in INT_VECTORS],
)
def test_int_vector(key, domain, t, expected):
    cipher = FF1(key)
    x = domain // 3
    y = cipher.encrypt_int(x, domain=domain, tweak=tweak(t))
    shown = str(y) if domain.bit_length() <= 200 else digest(str(y))
    assert shown == expected
    assert cipher.decrypt_int(y, domain=domain, tweak=tweak(t)) == x
