"""Tests for the integer-domain API (encrypt_int / decrypt_int).

The construction is a wire contract: FF1 at radix 2 over
(domain-1).bit_length() bits with cycle walking, independent of the
instance's radix/alphabet.
"""

import pytest

from ffx import FF1, DomainError

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

DOMAINS = [10**6, 10**6 + 1, 2**20, 2**31 - 1, 10**12 + 39]


def sample_values(domain):
    return sorted(
        {0, 1, 2, 41, domain // 3, domain // 2, domain - 2, domain - 1}
    )


@pytest.mark.parametrize("domain", DOMAINS)
def test_roundtrip(domain):
    cipher = FF1(KEY)
    for tweak in (b"", b"tweak"):
        for x in sample_values(domain):
            y = cipher.encrypt_int(x, domain=domain, tweak=tweak)
            assert 0 <= y < domain
            assert cipher.decrypt_int(y, domain=domain, tweak=tweak) == x


@pytest.mark.parametrize("domain", DOMAINS)
def test_permutation_on_sample(domain):
    """Distinct inputs must map to distinct outputs."""
    cipher = FF1(KEY)
    xs = sample_values(domain)
    ys = [cipher.encrypt_int(x, domain=domain) for x in xs]
    assert len(set(ys)) == len(xs)


def test_deterministic():
    a = FF1(KEY)
    b = FF1(KEY)
    for x in (0, 999_999):
        first = a.encrypt_int(x, domain=10**6, tweak=b"t")
        assert a.encrypt_int(x, domain=10**6, tweak=b"t") == first
        assert b.encrypt_int(x, domain=10**6, tweak=b"t") == first


def test_tweak_separation():
    cipher = FF1(KEY)
    domain = 10**12 + 39
    xs = sample_values(domain)
    with_a = [cipher.encrypt_int(x, domain=domain, tweak=b"a") for x in xs]
    with_b = [cipher.encrypt_int(x, domain=domain, tweak=b"b") for x in xs]
    assert with_a != with_b


def test_independent_of_instance_alphabet():
    """Same key => same integer results, whatever the string alphabet is."""
    plain = FF1(KEY)
    decimal = FF1(KEY, radix=10)
    dna = FF1(KEY, alphabet="ACGT")
    for domain in (10**6, 2**31 - 1):
        for x in (0, 12345, domain - 1):
            expected = plain.encrypt_int(x, domain=domain, tweak=b"tw")
            assert decimal.encrypt_int(x, domain=domain, tweak=b"tw") == expected
            assert dna.encrypt_int(x, domain=domain, tweak=b"tw") == expected


def test_value_out_of_range():
    cipher = FF1(KEY)
    with pytest.raises(DomainError):
        cipher.encrypt_int(-1, domain=10**6)
    with pytest.raises(DomainError):
        cipher.encrypt_int(10**6, domain=10**6)
    with pytest.raises(DomainError):
        cipher.decrypt_int(-1, domain=10**6)
    with pytest.raises(DomainError):
        cipher.decrypt_int(10**6, domain=10**6)


def test_small_domain_gating():
    cipher = FF1(KEY)
    with pytest.raises(DomainError):
        cipher.encrypt_int(0, domain=999_999)
    with pytest.raises(DomainError):
        cipher.decrypt_int(0, domain=999_999)

    relaxed = FF1(KEY, allow_small_domain=True)
    # The relaxed floor is exactly 100.
    for x in (0, 42, 99):
        y = relaxed.encrypt_int(x, domain=100)
        assert 0 <= y < 100
        assert relaxed.decrypt_int(y, domain=100) == x
    with pytest.raises(DomainError):
        relaxed.encrypt_int(0, domain=99)
