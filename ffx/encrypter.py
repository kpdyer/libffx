"""FFX Encrypter implementing the FFX-A2 algorithm."""

from __future__ import annotations

import math
import string
from typing import Union

import gmpy2

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

from .exceptions import InvalidRadixException
from .integer import FFXInteger
from .utils import long_to_bytes, bytes_to_long


class FFXEncrypter:
    """FFX Mode of Operation Encrypter.
    
    Implements the FFX-A2 algorithm for format-preserving encryption as specified in:
    http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf
    
    The algorithm uses:
    - AES-128 as the underlying block cipher
    - Maximally-balanced Feistel structure
    - 10 rounds (constant, independent of message size)
    
    Attributes:
        NUM_ROUNDS: Number of Feistel rounds (10 per spec)
    
    Example:
        >>> key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        >>> ffx = FFXEncrypter(key, radix=10)
        >>> plain = FFXInteger('0123456789', radix=10, blocksize=10)
        >>> cipher = ffx.encrypt(0, plain)
        >>> ffx.decrypt(0, cipher) == plain
        True
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
        self._radix_int = int(radix)
        self._chars = (string.digits + string.ascii_lowercase)[:radix]

        self._key = key
        self._ecb = AES.new(key, AES.MODE_ECB)
        # Per-(message-length, tweak-length) cache of the constant round
        # parameters and the constant CBC-MAC prefix E(P). Keyed by (n, t)
        # because P encodes both n and the tweak length t (in characters).
        self._param_cache: dict[tuple[int, int], tuple] = {}

    def _add_mod(self, x: FFXInteger, y: int) -> FFXInteger:
        """Add x + y modulo radix^blocksize."""
        result = (x + y) % (x._radix ** x._blocksize)
        return FFXInteger(result, radix=self._radix_int, blocksize=x._blocksize)

    def _sub_mod(self, x: FFXInteger, y: int) -> FFXInteger:
        """Subtract x - y modulo radix^blocksize."""
        result = (x - y) % (x._radix ** x._blocksize)
        return FFXInteger(result, radix=self._radix_int, blocksize=x._blocksize)

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
        radix = self._radix_int
        t = 0 if tweak == 0 else len(tweak)

        # Constant per (message length n, tweak length t): the round
        # parameters, the block P, and its CBC-MAC prefix E(P). P is always a
        # single 16-byte block, so with the zero IV its CBC-MAC contribution is
        # exactly E(P); caching it removes one AES block op per round.
        params = self._param_cache.get((n, t))
        if params is None:
            beta = math.ceil(n / 2.0)
            b_bytes = int(math.ceil(math.ceil(beta * math.log(radix, 2)) / 8.0))
            d = 4 * int(math.ceil(b_bytes / 4.0))
            m_even = n // 2
            m_odd = int(math.ceil(n / 2.0))
            mod_even = radix ** m_even
            mod_odd = radix ** m_odd

            P = b'\x01'  # vers
            P += b'\x02'  # method
            P += b'\x01'  # addition
            P += long_to_bytes(radix, 3)
            P += b'\x0a'  # always ten rounds
            P += long_to_bytes(self._split(n) % 256, 1)
            P += long_to_bytes(n, 4)
            P += long_to_bytes(t, 4)
            assert len(P) % 16 == 0
            ep = self._ecb.encrypt(P)

            params = (b_bytes, d, mod_even, mod_odd, ep)
            self._param_cache[(n, t)] = params

        b_bytes, d, mod_even, mod_odd, ep = params
        if (i & 1) == 0:
            mod = mod_even
        else:
            mod = mod_odd

        # Build Q (varies every round via i and b)
        if tweak == 0:
            Q = b''
        else:
            Q = str(tweak).encode('latin-1')

        Q += b'\x00' * (((-1 * t) - b_bytes - 1) % 16)
        Q += long_to_bytes(i, blocksize=1)

        b_as_bytes = long_to_bytes(b)
        Q += b'\x00' * (b_bytes - len(b_as_bytes))
        Q += b_as_bytes[-b_bytes:] if b_bytes > 0 else b''

        assert len(Q) % 16 == 0

        # CBC-MAC of (P + Q) with a zero IV, reusing the persistent ECB cipher
        # instead of constructing a fresh CBC cipher object every call. Start
        # the chain from the cached E(P), then fold in each 16-byte Q block.
        prev = ep
        for off in range(0, len(Q), 16):
            prev = self._ecb.encrypt(strxor(Q[off:off + 16], prev))
        Y = prev

        # Extend Y if needed
        j = 1
        TMP = Y
        need = d + 4
        while len(TMP) < need:
            X_val = bytes_to_long(Y) ^ j
            TMP += self._ecb.encrypt(long_to_bytes(X_val, blocksize=len(Y)))
            j += 1

        y = bytes_to_long(TMP[:need])
        return y % mod

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

        return FFXInteger(str(A) + str(B), radix=self._radix_int)

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

        return FFXInteger(str(A) + str(B), radix=self._radix_int)
