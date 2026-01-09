"""Tests for FFX encryption and decryption."""

import pytest
import ffx
from ffx import FFXInteger


class TestEncryptDecryptRoundtrip:
    """Test that decrypt(encrypt(x)) == x."""

    def test_binary_roundtrip(self, binary_encrypter):
        """Encrypt and decrypt binary message."""
        tweak = FFXInteger('0' * 8, radix=2, blocksize=8)
        plaintext = FFXInteger('10101010', radix=2, blocksize=8)

        ciphertext = binary_encrypter.encrypt(tweak, plaintext)
        decrypted = binary_encrypter.decrypt(tweak, ciphertext)

        assert decrypted == plaintext

    def test_decimal_roundtrip(self, decimal_encrypter):
        """Encrypt and decrypt decimal message."""
        tweak = FFXInteger('1234567890', radix=10, blocksize=10)
        plaintext = FFXInteger('9876543210', radix=10, blocksize=10)

        ciphertext = decimal_encrypter.encrypt(tweak, plaintext)
        decrypted = decimal_encrypter.decrypt(tweak, ciphertext)

        assert decrypted == plaintext

    def test_hex_roundtrip(self, hex_encrypter):
        """Encrypt and decrypt hexadecimal message."""
        tweak = FFXInteger('DEADBEEF', radix=16, blocksize=8)
        plaintext = FFXInteger('CAFEBABE', radix=16, blocksize=8)

        ciphertext = hex_encrypter.encrypt(tweak, plaintext)
        decrypted = hex_encrypter.decrypt(tweak, ciphertext)

        assert decrypted == plaintext


class TestTweakBehavior:
    """Test tweak (associated data) behavior."""

    def test_zero_tweak(self, decimal_encrypter):
        """Zero tweak is valid."""
        plaintext = FFXInteger('0123456789', radix=10, blocksize=10)

        ciphertext = decimal_encrypter.encrypt(0, plaintext)
        decrypted = decimal_encrypter.decrypt(0, ciphertext)

        assert decrypted == plaintext

    def test_different_tweaks_produce_different_ciphertexts(self, decimal_encrypter):
        """Same plaintext with different tweaks produces different ciphertexts."""
        plaintext = FFXInteger('0123456789', radix=10, blocksize=10)
        tweak1 = FFXInteger('1111111111', radix=10, blocksize=10)
        tweak2 = FFXInteger('2222222222', radix=10, blocksize=10)

        ciphertext1 = decimal_encrypter.encrypt(tweak1, plaintext)
        ciphertext2 = decimal_encrypter.encrypt(tweak2, plaintext)

        assert ciphertext1 != ciphertext2

    def test_wrong_tweak_produces_wrong_plaintext(self, decimal_encrypter):
        """Decrypting with wrong tweak doesn't recover plaintext."""
        plaintext = FFXInteger('0123456789', radix=10, blocksize=10)
        tweak1 = FFXInteger('1111111111', radix=10, blocksize=10)
        tweak2 = FFXInteger('2222222222', radix=10, blocksize=10)

        ciphertext = decimal_encrypter.encrypt(tweak1, plaintext)
        wrong_decrypted = decimal_encrypter.decrypt(tweak2, ciphertext)

        assert wrong_decrypted != plaintext


class TestFormatPreservation:
    """Test that encryption preserves format."""

    def test_preserves_length(self, decimal_encrypter):
        """Ciphertext has same length as plaintext."""
        plaintext = FFXInteger('0123456789', radix=10, blocksize=10)

        ciphertext = decimal_encrypter.encrypt(0, plaintext)

        assert len(ciphertext) == len(plaintext)

    def test_preserves_radix(self, decimal_encrypter):
        """Ciphertext uses same character set as plaintext."""
        plaintext = FFXInteger('0123456789', radix=10, blocksize=10)

        ciphertext = decimal_encrypter.encrypt(0, plaintext)

        # All characters should be decimal digits
        assert all(c in '0123456789' for c in str(ciphertext))

    @pytest.mark.parametrize("length", [4, 8, 12, 16, 20])
    def test_various_lengths(self, decimal_encrypter, length):
        """Format preservation works for various lengths."""
        plaintext = FFXInteger('1' * length, radix=10, blocksize=length)

        ciphertext = decimal_encrypter.encrypt(0, plaintext)
        decrypted = decimal_encrypter.decrypt(0, ciphertext)

        assert len(ciphertext) == length
        assert decrypted == plaintext
