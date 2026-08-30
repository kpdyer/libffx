"""Official NIST FF1 sample vectors.

Vectors extracted from the NIST intermediate-values document for
SP 800-38G, "FF1 samples" (csrc.nist.gov ff1samples.pdf), and
cross-checked against independent implementations. They cover AES-128,
AES-192, and AES-256 keys with empty and non-empty byte tweaks at
radix 10 and radix 36.
"""

import pytest

from ffx import FF1

NIST_VECTORS = [
    {
        "name": "AES-128 sample 1",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3C",
        "tweak_hex": "",
        "radix": 10,
        "plaintext": "0123456789",
        "ciphertext": "2433477484",
    },
    {
        "name": "AES-128 sample 2",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3C",
        "tweak_hex": "39383736353433323130",
        "radix": 10,
        "plaintext": "0123456789",
        "ciphertext": "6124200773",
    },
    {
        "name": "AES-128 sample 3",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3C",
        "tweak_hex": "3737373770717273373737",
        "radix": 36,
        "plaintext": "0123456789abcdefghi",
        "ciphertext": "a9tv40mll9kdu509eum",
    },
    {
        "name": "AES-192 sample 4",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
        "tweak_hex": "",
        "radix": 10,
        "plaintext": "0123456789",
        "ciphertext": "2830668132",
    },
    {
        "name": "AES-192 sample 5",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
        "tweak_hex": "39383736353433323130",
        "radix": 10,
        "plaintext": "0123456789",
        "ciphertext": "2496655549",
    },
    {
        "name": "AES-192 sample 6",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
        "tweak_hex": "3737373770717273373737",
        "radix": 36,
        "plaintext": "0123456789abcdefghi",
        "ciphertext": "xbj3kv35jrawxv32ysr",
    },
    {
        "name": "AES-256 sample 7",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
        "tweak_hex": "",
        "radix": 10,
        "plaintext": "0123456789",
        "ciphertext": "6657667009",
    },
    {
        "name": "AES-256 sample 8",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
        "tweak_hex": "39383736353433323130",
        "radix": 10,
        "plaintext": "0123456789",
        "ciphertext": "1001623463",
    },
    {
        "name": "AES-256 sample 9",
        "key_hex": "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
        "tweak_hex": "3737373770717273373737",
        "radix": 36,
        "plaintext": "0123456789abcdefghi",
        "ciphertext": "xs8a0azh2avyalyzuwd",
    },
]


@pytest.mark.parametrize(
    "vector", NIST_VECTORS, ids=[v["name"] for v in NIST_VECTORS]
)
def test_encrypt(vector):
    cipher = FF1(bytes.fromhex(vector["key_hex"]), radix=vector["radix"])
    tweak = bytes.fromhex(vector["tweak_hex"])
    assert cipher.encrypt(vector["plaintext"], tweak=tweak) == vector["ciphertext"]


@pytest.mark.parametrize(
    "vector", NIST_VECTORS, ids=[v["name"] for v in NIST_VECTORS]
)
def test_decrypt(vector):
    cipher = FF1(bytes.fromhex(vector["key_hex"]), radix=vector["radix"])
    tweak = bytes.fromhex(vector["tweak_hex"])
    assert cipher.decrypt(vector["ciphertext"], tweak=tweak) == vector["plaintext"]
