"""Shared pytest fixtures for FFX tests."""

import pytest
import ffx


@pytest.fixture
def standard_key():
    """The standard 128-bit AES key used in official NIST test vectors.
    
    Key: 2b7e151628aed2a6abf7158809cf4f3c (hex)
    """
    return ffx.FFXInteger(
        '2b7e151628aed2a6abf7158809cf4f3c',
        radix=16,
        blocksize=32
    )


@pytest.fixture
def zero_key():
    """A 128-bit key of all zeros."""
    return ffx.FFXInteger('0' * 128, radix=2, blocksize=128)


@pytest.fixture
def decimal_encrypter(standard_key):
    """FFX encrypter configured for decimal digits (radix=10)."""
    return ffx.new(standard_key.to_bytes(16), radix=10)


@pytest.fixture
def binary_encrypter(zero_key):
    """FFX encrypter configured for binary (radix=2)."""
    return ffx.new(zero_key.to_bytes(16), radix=2)


@pytest.fixture
def hex_encrypter(zero_key):
    """FFX encrypter configured for hexadecimal (radix=16)."""
    return ffx.new(zero_key.to_bytes(16), radix=16)
