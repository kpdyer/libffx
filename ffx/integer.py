"""FFXInteger class for format-preserving encryption operations."""

from __future__ import annotations

import math
from typing import Union

import gmpy2

from .exceptions import UnknownTypeException
from .utils import long_to_bytes


class FFXInteger:
    """Integer representation for FFX operations with a specific radix and blocksize.
    
    This class represents an integer in a given radix with optional zero-padding
    to a specified blocksize. It provides arithmetic operations and conversions
    needed for the FFX algorithm.
    
    Attributes:
        _x: String representation in the given radix
        _radix: The base for representation (2-36)
        _blocksize: Minimum length of string representation
    
    Example:
        >>> x = FFXInteger('1234', radix=10, blocksize=6)
        >>> str(x)
        '001234'
        >>> x.to_int()
        1234
    """
    
    _gmpy_mpz_type = type(gmpy2.mpz(0))
    _gmpy_mpfr_type = type(gmpy2.mpfr(0))

    def __init__(
        self, 
        x: Union[int, str, 'FFXInteger', float], 
        radix: int = 2, 
        blocksize: int | None = None
    ):
        """Initialize an FFXInteger.
        
        Args:
            x: Value to convert (int, str representation in radix, or FFXInteger)
            radix: Base for string representation (2-36)
            blocksize: Minimum length of string representation (zero-padded)
        
        Raises:
            UnknownTypeException: If x is an unsupported type
        """
        x_type = type(x)
        
        if x_type in (self._gmpy_mpz_type, int):
            self._x = gmpy2.digits(x, radix)
        elif x_type is FFXInteger:
            self._x = x._x
        elif x_type is str:
            self._x = x
        elif x_type in (float, self._gmpy_mpfr_type):
            self._x = gmpy2.digits(gmpy2.mpz(x), radix)
        else:
            raise UnknownTypeException(f"Unsupported type: {type(x)}")

        self._radix = radix
        if blocksize:
            self._blocksize = max(blocksize, len(self._x))
            self._x = '0' * (blocksize - len(self._x)) + self._x
        else:
            self._blocksize = None

        self._as_bytes: bytes | None = None
        self._as_int: int | None = None
        self._len: int | None = None

    def __add__(self, other: Union['FFXInteger', int]) -> int:
        result = self.to_int()
        if isinstance(other, FFXInteger):
            result += other.to_int()
        else:
            result += other
        return result

    def __radd__(self, other: int) -> int:
        return other + self.to_int()

    def __sub__(self, other: Union['FFXInteger', int]) -> int:
        result = self.to_int()
        if isinstance(other, FFXInteger):
            result -= other.to_int()
        else:
            result -= other
        return result

    def __rsub__(self, other: int) -> int:
        return other - self.to_int()

    def __mod__(self, other: Union['FFXInteger', int]) -> int:
        result = self.to_int()
        if isinstance(other, FFXInteger):
            result %= other.to_int()
        else:
            result %= other
        return result

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FFXInteger):
            return self.to_int() == other.to_int()
        elif isinstance(other, str):
            return self._x == other
        elif isinstance(other, int):
            return self.to_int() == other
        elif other is None:
            return False
        else:
            raise UnknownTypeException(f"Cannot compare FFXInteger with {type(other)}")

    def __hash__(self) -> int:
        return hash(self.to_int())

    def __len__(self) -> int:
        if self._len is None:
            self._len = len(self._x)
        return self._len

    def __getitem__(self, key: Union[int, slice]) -> 'FFXInteger':
        if isinstance(key, slice):
            sliced = self._x[key]
            return FFXInteger(sliced, self._radix, len(sliced))
        return FFXInteger(self._x[key], self._radix, 1)

    def __str__(self) -> str:
        return self._x

    def __repr__(self) -> str:
        return f"FFXInteger('{self._x}', radix={self._radix}, blocksize={self._blocksize})"

    def to_int(self) -> int:
        """Convert to integer.
        
        Returns:
            The integer value of this FFXInteger
        """
        if self._as_int is None:
            self._as_int = int(self._x, self._radix)
        return self._as_int

    def to_bytes(self, blocksize: int | None = None) -> bytes:
        """Convert to bytes representation.
        
        Args:
            blocksize: Override the output size in bytes
        
        Returns:
            Bytes representation
        """
        if blocksize is None and self._blocksize is not None:
            blocksize = int(math.ceil((self._radix ** self._blocksize - 1).bit_length() / 8))
        
        if self._as_bytes is None or blocksize is not None:
            if blocksize is None:
                blocksize = 1
                if self.to_int() > 0:
                    blocksize = (self.to_int().bit_length() + 7) // 8
            result = long_to_bytes(self.to_int(), blocksize=blocksize)
            if self._as_bytes is None:
                self._as_bytes = result
            return result
        
        return self._as_bytes

    def to_str(self) -> str:
        """Return string representation in the current radix.
        
        Returns:
            String representation
        """
        return self._x
