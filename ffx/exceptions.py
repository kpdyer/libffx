"""Exception hierarchy for the ffx package."""


class FFXError(Exception):
    """Base class for all errors raised by the ffx package."""


class KeyLengthError(FFXError, ValueError):
    """Raised when the AES key is not exactly 16, 24, or 32 bytes."""


class AlphabetError(FFXError, ValueError):
    """Raised for an invalid radix/alphabet configuration, or when a
    message contains characters outside the instance's alphabet."""


class DomainError(FFXError, ValueError):
    """Raised when a message or integer falls outside the permitted domain
    (too short, domain below the minimum, or value out of range)."""
