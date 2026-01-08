#!/usr/bin/env python3
"""Unit tests for FFX implementation.

These tests include validation against the official Voltage Security test vectors
from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
"""

import pytest

import ffx
from ffx import FFXInteger


class TestFFXInteger:
    """Tests for FFXInteger class."""

    def test_addition_binary(self):
        """Test binary addition of FFXIntegers."""
        X = FFXInteger('1')
        Y = FFXInteger('1')

        assert X + Y == 2
        assert X + Y == FFXInteger('10')

    def test_addition_with_leading_zeros(self):
        """Test addition preserves values with leading zeros."""
        X = FFXInteger('000')
        Y = FFXInteger('111')

        assert X + Y == 7
        assert X + Y == FFXInteger('111')

    def test_string_concatenation(self):
        """Test string representation concatenation."""
        X = FFXInteger('000')
        Y = FFXInteger('111')

        assert str(X) + str(Y) == '000111'

    def test_to_bytes_zero(self):
        """Test conversion of zero to bytes."""
        X = FFXInteger('000')
        assert X.to_bytes() == b'\x00'

    def test_to_bytes_max_8bit(self):
        """Test conversion of 255 (0xFF) to bytes."""
        X = FFXInteger('11111111')
        assert X.to_bytes() == b'\xFF'

    def test_to_bytes_hex_radix(self):
        """Test conversion from hex radix to bytes."""
        X = FFXInteger('FF', radix=16)
        assert X.to_bytes() == b'\xFF'

    def test_blocksize_padding(self):
        """Test that blocksize correctly pads the representation."""
        for blocksize in range(1, 129):
            X = FFXInteger('0', radix=2, blocksize=blocksize)
            assert len(X) == blocksize


class TestFFXEncryption:
    """Tests for FFX encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that decrypt(encrypt(x)) == x."""
        radix = 2
        K = FFXInteger('0' * 8, radix=radix, blocksize=128)
        T = FFXInteger('0' * 8, radix=radix, blocksize=8)
        M1 = FFXInteger('0' * 8, radix=radix, blocksize=8)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        M2 = ffx_obj.decrypt(T, C)

        assert M1 == M2


class TestOfficialVectors:
    """Tests against official Voltage Security test vectors."""

    @pytest.fixture
    def key(self):
        """The common key used in all official test vectors."""
        return FFXInteger(
            '2b7e151628aed2a6abf7158809cf4f3c',
            radix=16, 
            blocksize=32
        )

    def test_vector_1(self, key):
        """Test vector 1: radix=10, with tweak."""
        radix = 10
        T = FFXInteger('9876543210', radix=radix, blocksize=10)
        M1 = FFXInteger('0123456789', radix=radix, blocksize=10)

        ffx_obj = ffx.new(key.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        assert C == '6124200773'
        M2 = ffx_obj.decrypt(T, C)
        assert M1 == M2

    def test_vector_2(self, key):
        """Test vector 2: radix=10, no tweak."""
        radix = 10
        T = 0
        M1 = FFXInteger('0123456789', radix=radix, blocksize=10)

        ffx_obj = ffx.new(key.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        assert C == '2433477484'
        M2 = ffx_obj.decrypt(T, C)
        assert M1 == M2

    def test_vector_3(self, key):
        """Test vector 3: radix=10, 6-digit message."""
        radix = 10
        T = FFXInteger('2718281828', radix=radix, blocksize=10)
        M1 = FFXInteger('314159', radix=radix, blocksize=6)

        ffx_obj = ffx.new(key.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        assert C == '535005'
        M2 = ffx_obj.decrypt(T, C)
        assert M1 == M2

    def test_vector_4(self, key):
        """Test vector 4: radix=10, 9-digit message."""
        radix = 10
        T = FFXInteger('7777777', radix=radix, blocksize=7)
        M1 = FFXInteger('999999999', radix=radix, blocksize=9)

        ffx_obj = ffx.new(key.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        assert C == '658229573'
        M2 = ffx_obj.decrypt(T, C)
        assert M1 == M2

    def test_vector_5(self, key):
        """Test vector 5: radix=36 (alphanumeric)."""
        radix = 36
        T = FFXInteger('TQF9J5QDAGSCSPB1', radix=radix, blocksize=16)
        M1 = FFXInteger('C4XPWULBM3M863JH', radix=radix, blocksize=16)

        ffx_obj = ffx.new(key.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        assert str(C).upper() == 'C8AQ3U846ZWH6QZP'
        M2 = ffx_obj.decrypt(T, C)
        assert M1 == M2


class TestEdgeCases:
    """Tests for edge cases and bug fixes."""

    def test_long_to_bytes_power_of_two(self):
        """Test long_to_bytes with powers of 2 (Issue #5)."""
        assert ffx.long_to_bytes(65536) == b'\x01\x00\x00'

    def test_plaintext_power_of_two(self):
        """Test encryption with power of 2 in plaintext (Issue #5)."""
        plain = ffx.FFXInteger('0000065536', radix=10)
        tweak = ffx.FFXInteger('0000000000', radix=10)
        key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)

        ffx_obj = ffx.new(key.to_bytes(16), radix=10)
        ctxt = ffx_obj.encrypt(tweak, plain)
        assert ffx_obj.decrypt(tweak, ctxt) == plain

    def test_key_with_leading_null_byte_length(self):
        """Test key with leading null bytes has correct length (Issue #2)."""
        ffx_key = ffx.FFXInteger('0' * 128, radix=2, blocksize=128)
        assert len(ffx_key.to_bytes()) == 16

    def test_key_with_leading_null_byte_explicit_blocksize(self):
        """Test key with leading null bytes and explicit blocksize (Issue #2)."""
        ffx_key = ffx.FFXInteger('0' * 128, radix=2, blocksize=128)
        assert len(ffx_key.to_bytes(16)) == 16

    def test_y_expansion_48_chars(self):
        """Test Y expansion with 48-character hex message."""
        radix = 16
        K = FFXInteger('0' * 32, radix=radix, blocksize=32)
        T = 0
        M1 = FFXInteger('0' * 48, radix=radix, blocksize=48)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        assert C == 'ddb77d3be91a8e255fca9389a3d48da2b4476919744febea'
        M2 = ffx_obj.decrypt(T, C)
        assert M1 == M2

    def test_y_expansion_49_chars(self):
        """Test Y expansion with 49-character hex message."""
        radix = 16
        K = FFXInteger('0' * 32, radix=radix, blocksize=32)
        T = 0
        M1 = FFXInteger('0' * 49, radix=radix, blocksize=49)

        ffx_obj = ffx.new(K.to_bytes(16), radix)
        C = ffx_obj.encrypt(T, M1)
        assert C == '1f7b9459d22b2bee17d5b5616e03241467767c9dcbc424c21'
        M2 = ffx_obj.decrypt(T, C)
        assert M1 == M2
