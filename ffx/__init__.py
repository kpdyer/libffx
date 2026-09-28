"""
ffx - NIST SP 800-38G FF1 format-preserving encryption.

Format-preserving encryption encrypts data while preserving its format:
a 16-digit number encrypts to another 16-digit number, a DNA string over
"ACGT" encrypts to another DNA string of the same length. See :class:`FF1`
for the API and an example.
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
