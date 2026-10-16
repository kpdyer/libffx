"""Exception hierarchy for the ffx package.

Every validation error raised by the package is an :class:`FFXError`,
which is a :class:`ValueError`. Arguments of the wrong *type* (a non-bytes
key or tweak, a non-str message, a non-int radix, domain, or value) raise
:class:`TypeError` instead, following the usual Python convention.
"""


class FFXError(ValueError):
    """Base class for the validation errors raised by the ffx package."""


class KeyLengthError(FFXError):
    """Raised when the AES key is not exactly 16, 24, or 32 bytes."""


class AlphabetError(FFXError):
    """Raised for an invalid radix/alphabet configuration, or when a
    message contains characters outside the instance's alphabet."""


class DomainError(FFXError):
    """Raised when a message, integer, or tweak falls outside the permitted
    domain (message too short, domain below the minimum, value out of
    range, or tweak of 2**32 bytes or more)."""
