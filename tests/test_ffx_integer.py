"""Tests for FFXInteger class."""

import pytest
from ffx import FFXInteger


class TestArithmetic:
    """Test arithmetic operations on FFXInteger."""

    def test_add_two_ones(self):
        """1 + 1 = 2 in binary."""
        x = FFXInteger('1')
        y = FFXInteger('1')
        
        assert x + y == 2
        assert x + y == FFXInteger('10')

    def test_add_with_leading_zeros(self):
        """Leading zeros don't affect numeric value."""
        x = FFXInteger('000')
        y = FFXInteger('111')
        
        assert x + y == 7
        assert x + y == FFXInteger('111')


class TestStringRepresentation:
    """Test string conversion and concatenation."""

    def test_string_concatenation(self):
        """String representations can be concatenated."""
        x = FFXInteger('000')
        y = FFXInteger('111')
        
        assert str(x) + str(y) == '000111'

    def test_string_preserves_leading_zeros(self):
        """String representation preserves leading zeros."""
        x = FFXInteger('00001', radix=2, blocksize=5)
        
        assert str(x) == '00001'
        assert len(str(x)) == 5


class TestByteConversion:
    """Test conversion to bytes."""

    def test_zero_to_bytes(self):
        """Zero converts to single null byte."""
        x = FFXInteger('000')
        
        assert x.to_bytes() == b'\x00'

    def test_255_to_bytes(self):
        """255 (11111111 binary) converts to 0xFF."""
        x = FFXInteger('11111111')
        
        assert x.to_bytes() == b'\xFF'

    def test_hex_ff_to_bytes(self):
        """0xFF in hex radix converts to 0xFF byte."""
        x = FFXInteger('FF', radix=16)
        
        assert x.to_bytes() == b'\xFF'

    def test_to_bytes_with_length(self):
        """to_bytes(n) pads to n bytes."""
        x = FFXInteger('FF', radix=16)
        
        assert x.to_bytes(4) == b'\x00\x00\x00\xFF'


class TestBlocksize:
    """Test blocksize (output length) behavior."""

    @pytest.mark.parametrize("blocksize", range(1, 65))
    def test_blocksize_determines_length(self, blocksize):
        """Blocksize determines the string length."""
        x = FFXInteger('0', radix=2, blocksize=blocksize)
        
        assert len(x) == blocksize

    def test_blocksize_pads_with_zeros(self):
        """Blocksize pads output with leading zeros."""
        x = FFXInteger('1', radix=10, blocksize=5)
        
        assert str(x) == '00001'

    def test_blocksize_minimum_not_maximum(self):
        """Blocksize is minimum length, not maximum."""
        x = FFXInteger('12345', radix=10, blocksize=3)
        
        assert str(x) == '12345'
        assert len(x) == 5


class TestRadix:
    """Test different radix (base) values."""

    def test_binary_radix(self):
        """Radix 2 uses binary digits."""
        x = FFXInteger('1010', radix=2)
        
        assert x.to_int() == 10

    def test_decimal_radix(self):
        """Radix 10 uses decimal digits."""
        x = FFXInteger('42', radix=10)
        
        assert x.to_int() == 42

    def test_hex_radix(self):
        """Radix 16 uses hexadecimal digits."""
        x = FFXInteger('FF', radix=16)
        
        assert x.to_int() == 255

    def test_base36_radix(self):
        """Radix 36 uses 0-9 and a-z."""
        x = FFXInteger('Z', radix=36)
        
        assert x.to_int() == 35
