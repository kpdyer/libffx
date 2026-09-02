"""
ffx - NIST SP 800-38G FF1 format-preserving encryption.

Format-preserving encryption encrypts data while preserving its format:
a 16-digit number encrypts to another 16-digit number, a DNA string over
"ACGT" encrypts to another DNA string of the same length.

Example:
    >>> from ffx import FF1
    >>> cipher = FF1(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
    ...              radix=10)
    >>> ciphertext = cipher.encrypt("0123456789")
    >>> ciphertext
    '2433477484'
    >>> cipher.decrypt(ciphertext)
    '0123456789'
"""

from .exceptions import (
    AlphabetError,
    DomainError,
    FFXError,
    KeyLengthError,
)
from .ff1 import FF1

__all__ = [
    "FF1",
    "FFXError",
    "KeyLengthError",
    "AlphabetError",
    "DomainError",
    "__version__",
]

__version__ = "2.0.1"
