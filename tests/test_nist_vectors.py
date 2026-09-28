"""Official NIST FF1 sample vectors.

Vectors extracted from the NIST intermediate-values document for
SP 800-38G, "FF1 samples" (csrc.nist.gov ff1samples.pdf), and
cross-checked against independent implementations. They cover AES-128,
AES-192, and AES-256 keys with empty and non-empty byte tweaks at
radix 10 and radix 36.
"""

import pytest

from ffx import FF1

KEY128 = "2B7E151628AED2A6ABF7158809CF4F3C"
KEY192 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"
KEY256 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"
TWEAK_A = "39383736353433323130"
TWEAK_B = "3737373770717273373737"

# (sample, key hex, tweak hex, radix, plaintext, ciphertext)
NIST_VECTORS = [
    (1, KEY128, "", 10, "0123456789", "2433477484"),
    (2, KEY128, TWEAK_A, 10, "0123456789", "6124200773"),
    (3, KEY128, TWEAK_B, 36, "0123456789abcdefghi", "a9tv40mll9kdu509eum"),
    (4, KEY192, "", 10, "0123456789", "2830668132"),
    (5, KEY192, TWEAK_A, 10, "0123456789", "2496655549"),
    (6, KEY192, TWEAK_B, 36, "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"),
    (7, KEY256, "", 10, "0123456789", "6657667009"),
    (8, KEY256, TWEAK_A, 10, "0123456789", "1001623463"),
    (9, KEY256, TWEAK_B, 36, "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"),
]


@pytest.mark.parametrize(
    "key,tweak,radix,plaintext,ciphertext",
    [v[1:] for v in NIST_VECTORS],
    ids=[f"sample{v[0]}" for v in NIST_VECTORS],
)
def test_sample(key, tweak, radix, plaintext, ciphertext):
    cipher = FF1(bytes.fromhex(key), radix=radix)
    tweak = bytes.fromhex(tweak)
    assert cipher.encrypt(plaintext, tweak=tweak) == ciphertext
    assert cipher.decrypt(ciphertext, tweak=tweak) == plaintext
