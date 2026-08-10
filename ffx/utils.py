"""Utility functions for FFX operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .integer import FFXInteger


def long_to_bytes(n: int | 'FFXInteger', blocksize: int = 1) -> bytes:
    """Convert an integer to bytes representation.
    
    Args:
        n: Integer to convert (or FFXInteger)
        blocksize: Minimum output length (will be padded with zero bytes)
    
    Returns:
        Bytes representation of n, padded to blocksize
    """
    # Import here to avoid circular dependency
    from .integer import FFXInteger

    if isinstance(n, FFXInteger):
        return n.to_bytes()

    # Minimal big-endian length, then round up to a multiple of blocksize
    # (zero-padded on the left). Native int.to_bytes is much faster than
    # routing through gmpy2.digits + bytes.fromhex.
    length = 1 if n == 0 else (n.bit_length() + 7) // 8
    if blocksize > 0 and (length % blocksize) != 0:
        length += blocksize - (length % blocksize)

    return n.to_bytes(length, 'big')


def bytes_to_long(byte_string: bytes) -> int:
    """Convert bytes to integer representation.
    
    Args:
        byte_string: Bytes to convert
    
    Returns:
        Integer representation
    """
    return int.from_bytes(byte_string, byteorder='big')
