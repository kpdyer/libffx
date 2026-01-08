"""
FFX - Format Preserving Encryption

A Python implementation of The FFX Mode of Operation for Format-Preserving Encryption.
Based on the NIST proposal: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf

This implementation uses FFX-A2 with:
- Maximally-balanced Feistel structure
- 10 rounds (constant, independent of message size)
- AES-128 as the underlying block cipher
"""

from __future__ import annotations

import math
import string
from typing import Union

import gmpy2

from Crypto.Cipher import AES

__all__ = ['new', 'FFXInteger', 'FFXEncrypter', 'InvalidRadixException', 'UnknownTypeException']


def new(key: bytes, radix: int) -> FFXEncrypter:
    """Create a new FFX encrypter with the given key and radix.
    
    Args:
        key: 16-byte AES key
        radix: Base for the message alphabet (2-36)
    
    Returns:
        FFXEncrypter instance
    """
    return FFXEncrypter(key, radix)


class UnknownTypeException(Exception):
    """Raised when an unsupported type is passed to FFXInteger."""
    pass


class InvalidRadixException(Exception):
    """Raised when an invalid radix is specified (must be 2-36)."""
    pass


def long_to_bytes(n: int, blocksize: int = 1) -> bytes:
    """Convert an integer to bytes representation.
    
    Args:
        n: Integer to convert
        blocksize: Minimum output length (will be padded with zero bytes)
    
    Returns:
        Bytes representation of n, padded to blocksize
    """
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


class FFXInteger:
    """Integer representation for FFX operations with a specific radix and blocksize.
    
    This class represents an integer in a given radix with optional zero-padding
    to a specified blocksize.
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
        """Convert to integer."""
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
        """Return string representation in the current radix."""
        return self._x


class FFXEncrypter:
    """FFX Mode of Operation Encrypter.
    
    Implements the FFX-A2 algorithm for format-preserving encryption.
    """
    
    # Number of Feistel rounds (constant per FFX-A2 spec)
    NUM_ROUNDS = 10

    def __init__(self, key: bytes, radix: int):
        """Initialize the FFX encrypter.
        
        Args:
            key: 16-byte AES-128 key
            radix: Base for the message alphabet (2-36)
        
        Raises:
            InvalidRadixException: If radix is not in range 2-36
        """
        if radix not in range(2, 37):
            raise InvalidRadixException(f"Radix must be between 2 and 36, got {radix}")

        self._radix = gmpy2.mpz(radix)
        self._chars = (string.digits + string.ascii_lowercase)[:radix]
        
        self._key = key
        self._ecb = AES.new(key, AES.MODE_ECB)
        self._P_cache: dict[int, bytes] = {}

    @staticmethod
    def _is_even(n: int) -> bool:
        """Check if n is even."""
        return (n & 1) == 0

    def _add_mod(self, x: FFXInteger, y: int) -> FFXInteger:
        """Add x + y modulo radix^blocksize."""
        result = (x + y) % (x._radix ** x._blocksize)
        return FFXInteger(result, radix=int(self._radix), blocksize=x._blocksize)

    def _sub_mod(self, x: FFXInteger, y: int) -> FFXInteger:
        """Subtract x - y modulo radix^blocksize."""
        result = (x - y) % (x._radix ** x._blocksize)
        return FFXInteger(result, radix=int(self._radix), blocksize=x._blocksize)

    @staticmethod
    def _split(n: int) -> int:
        """Calculate the split point for Feistel network (maximally-balanced)."""
        return n // 2

    def _F(self, n: int, tweak: Union[FFXInteger, int], i: int, b: FFXInteger) -> int:
        """The round function F for the Feistel network.
        
        Implements the PRF per FFX-A2 specification.
        
        Args:
            n: Total message length
            tweak: The tweak value
            i: Round number
            b: Right half of the current state
        
        Returns:
            Output of the round function
        """
        if tweak == 0:
            t = 0
        else:
            t = len(tweak)

        beta = math.ceil(n / 2.0)
        b_bytes = int(math.ceil(math.ceil(beta * math.log(int(self._radix), 2)) / 8.0))
        d = 4 * int(math.ceil(b_bytes / 4.0))

        if self._is_even(i):
            m = n // 2
        else:
            m = int(math.ceil(n / 2.0))

        # Build P (cached per message length)
        if n not in self._P_cache:
            P = b'\x01'  # vers
            P += b'\x02'  # method
            P += b'\x01'  # addition
            P += long_to_bytes(int(self._radix), 3)
            P += b'\x0a'  # always ten rounds
            P += long_to_bytes(self._split(n) % 256, 1)
            P += long_to_bytes(n, 4)
            P += long_to_bytes(t, 4)
            self._P_cache[n] = P

        # Build Q
        if tweak == 0:
            Q = b''
        else:
            Q = str(tweak).encode('latin-1')
        
        Q += b'\x00' * (((-1 * t) - b_bytes - 1) % 16)
        Q += long_to_bytes(i, blocksize=1)
        
        b_as_bytes = long_to_bytes(b)
        Q += b'\x00' * (b_bytes - len(b_as_bytes))
        Q += b_as_bytes[-b_bytes:] if b_bytes > 0 else b''

        cbc = AES.new(self._key, AES.MODE_CBC, b'\x00' * 16)

        assert len(self._P_cache[n]) % 16 == 0
        assert len(Q) % 16 == 0

        Y = cbc.encrypt(self._P_cache[n] + Q)[-16:]

        # Extend Y if needed
        j = 1
        TMP = Y
        while len(TMP) < (d + 4):
            Y_len = len(Y)
            X_val = bytes_to_long(Y) ^ j
            TMP += self._ecb.encrypt(long_to_bytes(X_val, blocksize=Y_len))
            j += 1

        y = bytes_to_long(TMP[:(d + 4)])
        z = y % (int(self._radix) ** m)

        return z

    def encrypt(self, tweak: Union[FFXInteger, int], plaintext: FFXInteger) -> FFXInteger:
        """Encrypt a plaintext using FFX.
        
        Args:
            tweak: The tweak value (can be FFXInteger or 0 for no tweak)
            plaintext: The message to encrypt as FFXInteger
        
        Returns:
            Encrypted message as FFXInteger
        """
        n = len(plaintext)
        l = self._split(n)
        
        A = plaintext[:l]
        B = plaintext[l:]
        
        for i in range(self.NUM_ROUNDS):
            C = self._add_mod(A, self._F(n, tweak, i, B))
            A = B
            B = C

        return FFXInteger(str(A) + str(B), radix=int(self._radix))

    def decrypt(self, tweak: Union[FFXInteger, int], ciphertext: FFXInteger) -> FFXInteger:
        """Decrypt a ciphertext using FFX.
        
        Args:
            tweak: The tweak value (must match the one used for encryption)
            ciphertext: The encrypted message as FFXInteger
        
        Returns:
            Decrypted message as FFXInteger
        """
        n = len(ciphertext)
        l = self._split(n)
        
        A = ciphertext[:l]
        B = ciphertext[l:]
        
        for i in range(self.NUM_ROUNDS - 1, -1, -1):
            C = B
            B = A
            A = self._sub_mod(C, self._F(n, tweak, i, B))

        return FFXInteger(str(A) + str(B), radix=int(self._radix))