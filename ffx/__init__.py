"""
FFX - Format Preserving Encryption

A Python implementation of The FFX Mode of Operation for Format-Preserving Encryption.
Based on the NIST proposal: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf

This implementation uses FFX-A2 with:
- Maximally-balanced Feistel structure
- 10 rounds (constant, independent of message size)
- AES-128 as the underlying block cipher

Example:
    >>> import ffx
    >>> key = ffx.FFXInteger('2b7e151628aed2a6abf7158809cf4f3c', radix=16, blocksize=32)
    >>> encrypter = ffx.new(key.to_bytes(16), radix=10)
    >>> plaintext = ffx.FFXInteger('0123456789', radix=10, blocksize=10)
    >>> ciphertext = encrypter.encrypt(0, plaintext)
    >>> encrypter.decrypt(0, ciphertext) == plaintext
    True
"""

from .exceptions import (
    FFXException,
    InvalidRadixException,
    UnknownTypeException,
)
from .integer import FFXInteger
from .encrypter import FFXEncrypter
from .utils import long_to_bytes, bytes_to_long


__all__ = [
    # Factory function
    'new',
    # Classes
    'FFXInteger',
    'FFXEncrypter',
    # Exceptions
    'FFXException',
    'InvalidRadixException',
    'UnknownTypeException',
    # Utilities
    'long_to_bytes',
    'bytes_to_long',
]

__version__ = '0.1.0'


def new(key: bytes, radix: int) -> FFXEncrypter:
    """Create a new FFX encrypter with the given key and radix.
    
    This is the main entry point for creating an FFX encrypter.
    
    Args:
        key: 16-byte AES-128 key
        radix: Base for the message alphabet (2-36)
    
    Returns:
        FFXEncrypter instance ready for encryption/decryption
    
    Raises:
        InvalidRadixException: If radix is not in range 2-36
    
    Example:
        >>> import ffx
        >>> key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        >>> encrypter = ffx.new(key, radix=10)
    """
    return FFXEncrypter(key, radix)
