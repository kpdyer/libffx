"""Custom exceptions for the FFX library."""


class FFXException(Exception):
    """Base exception for FFX errors."""
    pass


class UnknownTypeException(FFXException):
    """Raised when an unsupported type is passed to FFXInteger."""
    pass


class InvalidRadixException(FFXException):
    """Raised when an invalid radix is specified (must be 2-36)."""
    pass
