"""Tests for edge cases and bug fixes.

Each test references the GitHub issue it validates, where applicable.
"""

import pytest
import ffx
from ffx import FFXInteger


class TestLongToBytes:
    """Tests for long_to_bytes utility function."""

    def test_power_of_two(self):
        """Powers of 2 should produce correct byte length.
        
        Regression test for GitHub Issue #5.
        65536 = 0x10000 should be 3 bytes, not 2.
        """
        result = ffx.long_to_bytes(65536)
        
        assert result == b'\x01\x00\x00'
        assert len(result) == 3

    @pytest.mark.parametrize('value,expected_bytes', [
        (0, b'\x00'),
        (1, b'\x01'),
        (255, b'\xff'),
        (256, b'\x01\x00'),
        (65535, b'\xff\xff'),
        (65536, b'\x01\x00\x00'),
        (16777215, b'\xff\xff\xff'),
        (16777216, b'\x01\x00\x00\x00'),
    ])
    def test_various_values(self, value, expected_bytes):
        """Various integer values convert correctly to bytes."""
        assert ffx.long_to_bytes(value) == expected_bytes


class TestPowerOfTwoInPlaintext:
    """Tests for encryption with powers of 2 in plaintext.
    
    Regression tests for GitHub Issue #5.
    """

    def test_65536_in_plaintext(self, standard_key):
        """Encrypt plaintext containing 65536 (power of 2)."""
        ffx_obj = ffx.new(standard_key.to_bytes(16), radix=10)
        
        plain = FFXInteger('0000065536', radix=10)
        tweak = FFXInteger('0000000000', radix=10)

        ciphertext = ffx_obj.encrypt(tweak, plain)
        decrypted = ffx_obj.decrypt(tweak, ciphertext)

        assert decrypted == plain

    @pytest.mark.parametrize('power', [8, 16, 24, 32])
    def test_various_powers_of_two(self, standard_key, power):
        """Encryption works with various powers of 2."""
        value = 2 ** power
        value_str = str(value).zfill(12)  # Pad to 12 digits
        
        ffx_obj = ffx.new(standard_key.to_bytes(16), radix=10)
        plain = FFXInteger(value_str, radix=10, blocksize=12)
        
        ciphertext = ffx_obj.encrypt(0, plain)
        decrypted = ffx_obj.decrypt(0, ciphertext)

        assert decrypted == plain


class TestLeadingNullBytes:
    """Tests for keys and values with leading null bytes.
    
    Regression tests for GitHub Issue #2.
    """

    def test_all_zero_key_length(self):
        """All-zero key should have correct byte length."""
        key = FFXInteger('0' * 128, radix=2, blocksize=128)
        
        assert len(key.to_bytes()) == 16

    def test_all_zero_key_explicit_length(self):
        """All-zero key with explicit length parameter."""
        key = FFXInteger('0' * 128, radix=2, blocksize=128)
        
        assert len(key.to_bytes(16)) == 16

    def test_key_with_leading_zeros_encrypts(self):
        """Key with leading null bytes can still encrypt."""
        key = FFXInteger('00' + 'FF' * 15, radix=16, blocksize=32)
        ffx_obj = ffx.new(key.to_bytes(16), radix=10)
        
        plain = FFXInteger('1234567890', radix=10, blocksize=10)
        ciphertext = ffx_obj.encrypt(0, plain)
        decrypted = ffx_obj.decrypt(0, ciphertext)

        assert decrypted == plain


class TestLongMessages:
    """Tests for messages longer than typical block sizes."""

    def test_48_char_hex_message(self):
        """48-character hex message (192 bits)."""
        key = FFXInteger('0' * 32, radix=16, blocksize=32)
        ffx_obj = ffx.new(key.to_bytes(16), radix=16)
        
        plain = FFXInteger('0' * 48, radix=16, blocksize=48)
        
        ciphertext = ffx_obj.encrypt(0, plain)
        decrypted = ffx_obj.decrypt(0, ciphertext)

        assert str(ciphertext) == 'ddb77d3be91a8e255fca9389a3d48da2b4476919744febea'
        assert decrypted == plain

    def test_49_char_hex_message(self):
        """49-character hex message (tests Y expansion boundary)."""
        key = FFXInteger('0' * 32, radix=16, blocksize=32)
        ffx_obj = ffx.new(key.to_bytes(16), radix=16)
        
        plain = FFXInteger('0' * 49, radix=16, blocksize=49)
        
        ciphertext = ffx_obj.encrypt(0, plain)
        decrypted = ffx_obj.decrypt(0, ciphertext)

        assert str(ciphertext) == '1f7b9459d22b2bee17d5b5616e03241467767c9dcbc424c21'
        assert decrypted == plain

    @pytest.mark.parametrize('length', [32, 64, 96, 128])
    def test_various_long_messages(self, length):
        """Encryption works for various long message lengths."""
        key = FFXInteger('0' * 32, radix=16, blocksize=32)
        ffx_obj = ffx.new(key.to_bytes(16), radix=16)
        
        plain = FFXInteger('A' * length, radix=16, blocksize=length)
        
        ciphertext = ffx_obj.encrypt(0, plain)
        decrypted = ffx_obj.decrypt(0, ciphertext)

        assert len(ciphertext) == length
        assert decrypted == plain


class TestMinimumMessageSize:
    """Tests for minimum message sizes."""

    def test_2_char_decimal(self, standard_key):
        """Minimum practical message: 2 decimal digits."""
        ffx_obj = ffx.new(standard_key.to_bytes(16), radix=10)
        
        plain = FFXInteger('42', radix=10, blocksize=2)
        
        ciphertext = ffx_obj.encrypt(0, plain)
        decrypted = ffx_obj.decrypt(0, ciphertext)

        assert len(ciphertext) == 2
        assert decrypted == plain

    def test_2_char_binary(self):
        """Minimum message: 2 binary digits."""
        key = FFXInteger('0' * 128, radix=2, blocksize=128)
        ffx_obj = ffx.new(key.to_bytes(16), radix=2)
        
        plain = FFXInteger('11', radix=2, blocksize=2)
        
        ciphertext = ffx_obj.encrypt(0, plain)
        decrypted = ffx_obj.decrypt(0, ciphertext)

        assert len(ciphertext) == 2
        assert decrypted == plain
