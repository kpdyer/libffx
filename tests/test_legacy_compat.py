"""v1 compatibility: FF1 subsumes the legacy FFX[radix] mode.

The legacy library implemented the FFX[radix] addendum profile, which is
FF1 with the tweak taken as a numeral *string* rather than raw bytes.
Encoding that tweak string as ASCII bytes must reproduce every ciphertext
in the original Voltage Security vector file (aes-ffx-vectors.txt) exactly.

v1 rendered radix-36 numeral strings in lowercase (a quirk of its
big-integer library's digit rendering), so
radix-36 plaintexts/ciphertexts from the vector file are lowercased before
comparison. Tweak strings are used byte-for-byte as they appear.
"""

import re
from pathlib import Path

import pytest

from ffx import FF1

VECTOR_FILE = Path(__file__).resolve().parent.parent / "aes-ffx-vectors.txt"


def load_vectors():
    """Parse the radix-10 and radix-36 sections of aes-ffx-vectors.txt."""
    text = VECTOR_FILE.read_text()

    key_match = re.search(
        r"AES-128 key for all test vectors:\s*([0-9a-fA-F]{32})", text
    )
    assert key_match, "key line not found in aes-ffx-vectors.txt"
    key = bytes.fromhex(key_match.group(1))

    vectors = []
    for block in re.split(r"Test vector \d+:", text)[1:]:
        radix = int(re.search(r"Radix\s*=\s*(\d+)", block).group(1))
        plaintext = re.search(r'Input \(length = \d+\):\s*"([^"]+)"', block).group(1)
        tweak_match = re.search(r'Tweak \(length = \d+\):\s*"([^"]+)"', block)
        tweak = tweak_match.group(1).encode("ascii") if tweak_match else b""
        ciphertext = re.search(r'Encrypted:\s*"([^"]+)"', block).group(1)
        vectors.append((radix, tweak, plaintext, ciphertext))

    assert len(vectors) == 5, "expected 5 legacy vectors"
    return key, vectors


KEY, VECTORS = load_vectors()


def normalize(s, radix):
    """v1 rendered radix-36 numeral strings in lowercase."""
    return s.lower() if radix > 10 else s


@pytest.mark.parametrize(
    "radix,tweak,plaintext,ciphertext",
    VECTORS,
    ids=[f"radix{v[0]}-t{len(v[1])}-n{len(v[2])}" for v in VECTORS],
)
def test_legacy_encrypt(radix, tweak, plaintext, ciphertext):
    cipher = FF1(KEY, radix=radix)
    got = cipher.encrypt(normalize(plaintext, radix), tweak=tweak)
    assert got == normalize(ciphertext, radix)


@pytest.mark.parametrize(
    "radix,tweak,plaintext,ciphertext",
    VECTORS,
    ids=[f"radix{v[0]}-t{len(v[1])}-n{len(v[2])}" for v in VECTORS],
)
def test_legacy_decrypt(radix, tweak, plaintext, ciphertext):
    cipher = FF1(KEY, radix=radix)
    got = cipher.decrypt(normalize(ciphertext, radix), tweak=tweak)
    assert got == normalize(plaintext, radix)
