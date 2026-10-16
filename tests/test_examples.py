"""Run each example, plus the IPv6 case its own checks can't reach."""

import ipaddress

import pytest

from examples import formatted_strings, ip_address
from ffx import FF1


@pytest.mark.parametrize(
    "example", [formatted_strings, ip_address], ids=lambda m: m.__name__
)
def test_example_runs(example):
    example.main()  # each example asserts its own round trips


@pytest.mark.parametrize("value", [0, 1, 2**32 - 1])
def test_small_ipv6_ciphertext_stays_ipv6(value):
    cipher = FF1(bytes(16))
    original = str(ipaddress.IPv6Address(
        cipher.decrypt_int(value, domain=2**128, tweak=b"ip")
    ))
    encrypted = ip_address.transform(original, cipher)
    assert encrypted == str(ipaddress.IPv6Address(value))
    assert ip_address.transform(encrypted, cipher, decrypt=True) == original
