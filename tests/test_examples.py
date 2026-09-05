"""Regression checks for the retained formatting and integer-domain recipes."""

import ipaddress

import pytest

from examples import formatted_strings
from examples.ip_address import decrypt_ip, encrypt_ip
from ffx import FF1

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


@pytest.mark.parametrize(
    "text,radix",
    [("123-45-6789", 10), ("1990-05-15", 10), ("alice.smith", 36), ("12-345678", 36)],
)
def test_formatted_roundtrip(text, radix):
    cipher = FF1(KEY, radix=radix)
    encrypted = formatted_strings.transform(text, cipher, tweak=b"mrn:")
    assert len(encrypted) == len(text)
    assert all(encrypted[i] == c for i, c in enumerate(text) if not c.isalnum())
    decrypted = formatted_strings.transform(encrypted, cipher, tweak=b"mrn:", decrypt=True)
    assert decrypted == text


def test_examples_preserve_explicit_prefixes(capsys):
    formatted_strings.main()
    lines = capsys.readouterr().out.splitlines()
    for prefix in ("mrn-", "+358 "):
        line = next(line for line in lines if line.startswith(prefix))
        original, encrypted, decrypted = line.split(" -> ")
        assert encrypted.startswith(prefix)
        assert decrypted == original


@pytest.mark.parametrize(
    "address",
    ["0.0.0.0", "192.168.1.1", "::", "::1", "::ffff:ffff", "2001:db8::1"],
)
def test_ip_family_and_roundtrip(address):
    cipher = FF1(KEY)
    encrypted = encrypt_ip(address, cipher)
    assert ipaddress.ip_address(encrypted).version == ipaddress.ip_address(address).version
    assert decrypt_ip(encrypted, cipher) == str(ipaddress.ip_address(address))


@pytest.mark.parametrize("value", [0, 1, 2**32 - 1])
def test_ipv6_small_ciphertext(value):
    cipher = FF1(KEY)
    original = str(ipaddress.IPv6Address(
        cipher.decrypt_int(value, domain=2**128, tweak=b"ip")
    ))
    encrypted = encrypt_ip(original, cipher)
    assert encrypted == str(ipaddress.IPv6Address(value))
    assert decrypt_ip(encrypted, cipher) == original
