"""Utility functions for FFX operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

import gmpy2

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
    
    if n == 0:
        byte_string = b'\x00'
    else:
        hex_string = gmpy2.digits(n, 16)
        if len(hex_string) % 2:
            hex_string = '0' + hex_string
        byte_string = bytes.fromhex(hex_string)
    
    if blocksize > 0 and (len(byte_string) % blocksize) != 0:
        byte_string = b'\x00' * (blocksize - (len(byte_string) % blocksize)) + byte_string
    
    return byte_string


def bytes_to_long(byte_string: bytes) -> int:
    """Convert bytes to integer representation.
    
    Args:
        byte_string: Bytes to convert
    
    Returns:
        Integer representation
    """
    return int.from_bytes(byte_string, byteorder='big')
