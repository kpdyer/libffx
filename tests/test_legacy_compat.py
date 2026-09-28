"""v1 compatibility: FF1 subsumes the legacy FFX[radix] mode.

The legacy library implemented the FFX[radix] addendum profile, which is
FF1 with the tweak taken as a numeral *string* rather than raw bytes.
Encoding that tweak string as ASCII bytes must reproduce every vector in
Voltage Security's "AES FFX Test Vector Data" (FFX[radix] profile, June
2011) exactly. Vectors 1 and 2 are also NIST FF1 samples 2 and 1.

v1 rendered radix-36 numeral strings in lowercase (a quirk of its
big-integer library's digit rendering), so vector 5's plaintext and
ciphertext, uppercase in the vector data, appear here in lowercase. Tweak
strings are used byte-for-byte as they appear.
"""

import pytest

from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

# (radix, tweak, plaintext, ciphertext) for vectors 1 to 5
VECTORS = [
    (10, b"9876543210", "0123456789", "6124200773"),
    (10, b"", "0123456789", "2433477484"),
    (10, b"2718281828", "314159", "535005"),
    (10, b"7777777", "999999999", "658229573"),
    (36, b"TQF9J5QDAGSCSPB1", "c4xpwulbm3m863jh", "c8aq3u846zwh6qzp"),
]


@pytest.mark.parametrize(
    "radix,tweak,plaintext,ciphertext",
    VECTORS,
    ids=[f"vector{i}" for i in range(1, len(VECTORS) + 1)],
)
def test_legacy_vector(radix, tweak, plaintext, ciphertext):
    cipher = FF1(KEY, radix=radix)
    assert cipher.encrypt(plaintext, tweak=tweak) == ciphertext
    assert cipher.decrypt(ciphertext, tweak=tweak) == plaintext


def test_v1_zero_valued_tweak_means_no_tweak():
    """v1 treated any tweak whose numeric value was 0 as *no* tweak.

    The v1 README's own radix-2 example (all-zero key, tweak "0" * 8,
    plaintext "0" * 8) printed ciphertext "10100010"; FF1 reproduces it
    only with an empty tweak, not with the zero string encoded as bytes.
    """
    cipher = FF1(bytes(16), radix=2, allow_small_domain=True)
    assert cipher.encrypt("00000000") == "10100010"
    assert cipher.encrypt("00000000", tweak=b"00000000") != "10100010"


def test_v1_zero_valued_tweak_radix10():
    """Vectors generated with libffx 1.0.3 (radix 10, the NIST AES-128 key):
    the tweak strings "0000000000" and "0", and the integer tweak 0, all gave
    "3662311239797070" for "4111111111111111", i.e. the no-tweak ciphertext;
    the non-zero tweak string "0000000001" gave "9027324768307529", which its
    ASCII encoding reproduces."""
    cipher = FF1(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), radix=10)
    assert cipher.encrypt("4111111111111111") == "3662311239797070"
    assert cipher.encrypt("4111111111111111", tweak=b"0000000000") != "3662311239797070"
    assert cipher.encrypt("4111111111111111", tweak=b"0000000001") == "9027324768307529"
