"""Input validation: keys, alphabets, domains, tweaks."""

import pytest

from ffx import FF1, AlphabetError, DomainError, FFXError, KeyLengthError

KEY = bytes(range(16))


class TestKeys:
    @pytest.mark.parametrize("length", [0, 1, 15, 17, 23, 25, 31, 33, 48])
    def test_bad_key_lengths(self, length):
        with pytest.raises(KeyLengthError):
            FF1(bytes(length), radix=10)

    @pytest.mark.parametrize("length", [16, 24, 32])
    def test_good_key_lengths(self, length):
        FF1(bytes(length), radix=10)

    def test_key_must_be_bytes(self):
        with pytest.raises(TypeError):
            FF1("0" * 16, radix=10)

    def test_key_length_error_is_value_error(self):
        with pytest.raises(ValueError):
            FF1(bytes(15), radix=10)
        with pytest.raises(FFXError):
            FF1(bytes(15), radix=10)


class TestAlphabetConfig:
    def test_radix_and_alphabet_together(self):
        with pytest.raises(AlphabetError):
            FF1(KEY, radix=10, alphabet="0123456789")

    @pytest.mark.parametrize("radix", [-1, 0, 1, 37, 100])
    def test_radix_out_of_range(self, radix):
        with pytest.raises(AlphabetError):
            FF1(KEY, radix=radix)

    @pytest.mark.parametrize("alphabet", ["", "a", "aa", "abca"])
    def test_bad_alphabets(self, alphabet):
        with pytest.raises(AlphabetError):
            FF1(KEY, alphabet=alphabet)

    def test_alphabet_too_large(self):
        with pytest.raises(AlphabetError):
            FF1(KEY, alphabet="".join(map(chr, range(65537))))

    def test_alphabet_at_limit(self):
        FF1(KEY, alphabet="".join(map(chr, range(65536))))

    def test_integer_only_instance_rejects_strings(self):
        cipher = FF1(KEY)
        with pytest.raises(AlphabetError, match="radix= or alphabet="):
            cipher.encrypt("0123456789")
        with pytest.raises(AlphabetError, match="radix= or alphabet="):
            cipher.decrypt("0123456789")

    def test_message_outside_alphabet(self):
        cipher = FF1(KEY, radix=10)
        with pytest.raises(AlphabetError):
            cipher.encrypt("01234x6789")
        with pytest.raises(AlphabetError):
            cipher.decrypt("01234x6789")

    def test_case_sensitive_no_normalization(self):
        cipher = FF1(KEY, radix=36)
        with pytest.raises(AlphabetError):
            cipher.encrypt("ABCDEF")  # alphabet is lowercase

    def test_message_must_be_str(self):
        cipher = FF1(KEY, radix=10)
        with pytest.raises(TypeError):
            cipher.encrypt(123456789)


class TestDomainGating:
    def test_below_default_floor(self):
        cipher = FF1(KEY, radix=10)
        with pytest.raises(DomainError):
            cipher.encrypt("12345")  # 10**5 < 1_000_000
        assert len(cipher.encrypt("123456")) == 6  # 10**6 is allowed

    def test_small_domain_opt_in(self):
        relaxed = FF1(KEY, radix=10, allow_small_domain=True)
        ciphertext = relaxed.encrypt("42")  # 10**2 == 100, at the floor
        assert relaxed.decrypt(ciphertext) == "42"
        with pytest.raises(DomainError):
            FF1(KEY, radix=2, allow_small_domain=True).encrypt("010101")  # 64 < 100

    def test_minimum_two_numerals(self):
        relaxed = FF1(KEY, alphabet="".join(map(chr, range(256))), allow_small_domain=True)
        with pytest.raises(DomainError):
            relaxed.encrypt("\x01")  # domain 256 is fine, but n == 1


class TestTweaks:
    @pytest.mark.parametrize("tweak", ["text", 0, 1.5, [1, 2], None])
    def test_tweak_type_errors(self, tweak):
        cipher = FF1(KEY, radix=10)
        with pytest.raises(TypeError):
            cipher.encrypt("123456", tweak=tweak)
        with pytest.raises(TypeError):
            cipher.decrypt("123456", tweak=tweak)
        with pytest.raises(TypeError):
            cipher.encrypt_int(0, domain=10**6, tweak=tweak)

    def test_bytearray_tweak_accepted(self):
        cipher = FF1(KEY, radix=10)
        assert cipher.encrypt("123456", tweak=bytearray(b"tw")) == cipher.encrypt(
            "123456", tweak=b"tw"
        )
