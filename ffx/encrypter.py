"""FFX Encrypter implementing the FFX-A2 algorithm."""

from __future__ import annotations

import math
import string
from typing import NamedTuple, Union

import gmpy2

from Crypto.Cipher import AES

from .exceptions import InvalidRadixException
from .integer import FFXInteger
from .utils import long_to_bytes


class _FParams(NamedTuple):
    """Cached, (n, t)-dependent parameters for the round function ``_F``.

    Everything here is a pure function of the message length ``n``, tweak
    length ``t``, the radix and the key, so it is computed once per distinct
    (n, t) and reused across rounds and calls.
    """

    P: bytes          # fixed 16-byte header block
    e_p: int          # AES(P) as an int: the CBC-MAC chain value after block P
    b_bytes: int      # width, in bytes, of the b field appended to Q
    d4: int           # d + 4: number of MAC bytes consumed before reduction
    q_zero_pad: int   # zero bytes between the tweak and the round byte in Q
    b_mask: int       # (1 << 8*b_bytes) - 1, to take b's low b_bytes bytes
    mod_even: int     # radix ** (n // 2), used on even rounds
    mod_odd: int      # radix ** ceil(n / 2), used on odd rounds


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

    # For a CBC-MAC over this many 16-byte blocks or fewer, folding the blocks
    # through the persistent ECB cipher in Python beats constructing a fresh
    # AES-CBC object (which re-runs the AES key schedule). Above this size the
    # per-block Python overhead dominates and the C CBC path is faster; the
    # crossover is between 3 and 4 blocks in practice.
    _MAC_INLINE_MAX_BLOCKS = 3

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

        self._radix = radix
        self._chars = (string.digits + string.ascii_lowercase)[:radix]

        self._key = key
        self._ecb = AES.new(key, AES.MODE_ECB)
        # Per-(message length, tweak length) parameter cache. Everything stored
        # here depends only on n, t and the (fixed) radix and key, so it is
        # computed once and reused across the 10 Feistel rounds and across every
        # call that shares the same (n, t).
        self._P_cache: dict[tuple[int, int], _FParams] = {}

    @staticmethod
    def _split(n: int) -> int:
        """Calculate the split point for Feistel network (maximally-balanced)."""
        return n // 2

    def _build_params(self, n: int, t: int) -> '_FParams':
        """Compute the (n, t)-dependent parameters for the round function.

        This runs once per distinct (message length, tweak length) pair; the
        result is cached and reused across all 10 Feistel rounds and every later
        call with the same shape. It folds together the block-count/precision
        math (previously recomputed every round via ``math.log``/``math.ceil``),
        the fixed header block ``P`` and its AES image ``E(P)``, the constant
        Q-padding length, and the per-parity output moduli.
        """
        radix = self._radix

        beta = math.ceil(n / 2.0)
        b_bytes = int(math.ceil(math.ceil(beta * math.log(radix, 2)) / 8.0))
        d = 4 * int(math.ceil(b_bytes / 4.0))

        # P is the fixed 16-byte header block for this (n, t). Because it never
        # changes for a given (n, t, key), its CBC-MAC first-block image E(P) is
        # also fixed and can be precomputed once here.
        P = (
            b'\x01\x02\x01'
            + long_to_bytes(radix, 3)
            + b'\x0a'  # always ten rounds
            + long_to_bytes(self._split(n) % 256, 1)
            + long_to_bytes(n, 4)
            + long_to_bytes(t, 4)
        )
        assert len(P) == 16
        e_p = int.from_bytes(self._ecb.encrypt(P), 'big')

        # Number of zero bytes inserted between the tweak and the round byte so
        # that len(Q) is a multiple of 16 (P is already one whole block).
        q_zero_pad = ((-1 * t) - b_bytes - 1) % 16

        m_even = n // 2
        m_odd = int(math.ceil(n / 2.0))

        return _FParams(
            P=P,
            e_p=e_p,
            b_bytes=b_bytes,
            d4=d + 4,
            q_zero_pad=q_zero_pad,
            b_mask=(1 << (8 * b_bytes)) - 1,
            mod_even=radix ** m_even,
            mod_odd=radix ** m_odd,
        )

    def _prepare(
        self, n: int, tweak: Union[FFXInteger, int]
    ) -> tuple[int, '_FParams', bytes]:
        """Resolve the round-invariant state for one encrypt/decrypt call.

        The tweak length ``t``, the cached ``_FParams`` for ``(n, t)`` and the
        constant Q prefix (the tweak bytes plus the fixed zero padding) do not
        change across the 10 Feistel rounds, so they are computed once here
        rather than rebuilt on every round as the old ``_F`` did.
        """
        t = 0 if tweak == 0 else len(tweak)

        cache_key = (n, t)
        params = self._P_cache.get(cache_key)
        if params is None:
            params = self._build_params(n, t)
            self._P_cache[cache_key] = params

        if t:
            q_prefix = str(tweak).encode('latin-1') + b'\x00' * params.q_zero_pad
        else:
            q_prefix = b'\x00' * params.q_zero_pad

        return t, params, q_prefix

    def _F(self, params: '_FParams', q_prefix: bytes, i: int, b_int: int) -> int:
        """The round function F for the Feistel network.

        Implements the PRF per FFX-A2 specification. All state that depends only
        on ``(n, t)`` arrives pre-computed in ``params``/``q_prefix`` (see
        :meth:`_prepare`); this method only does the per-round work.

        Args:
            params: Cached (n, t)-dependent parameters.
            q_prefix: Tweak bytes plus fixed zero padding (round-invariant).
            i: Round number.
            b_int: Integer value of the right half of the current state.

        Returns:
            Output of the round function.
        """
        # Build Q: the round-invariant prefix, the round byte, and b as a
        # fixed-width big-endian field (its low b_bytes bytes, left zero-padded).
        b_bytes = params.b_bytes
        if b_bytes:
            Q = q_prefix + bytes((i,)) + (b_int & params.b_mask).to_bytes(b_bytes, 'big')
        else:
            Q = q_prefix + bytes((i,))

        # CBC-MAC of P || Q with a zero IV; we only need the final block. P is a
        # single block whose image E(P) is cached, so we start the chain from it
        # and fold in the Q blocks. For short payloads, folding through the
        # persistent ECB cipher avoids rebuilding an AES-CBC object (and its key
        # schedule) every round; for long payloads the C CBC path wins.
        ecb_encrypt = self._ecb.encrypt
        if (len(Q) >> 4) + 1 <= self._MAC_INLINE_MAX_BLOCKS:
            y_int = params.e_p
            for off in range(0, len(Q), 16):
                blk = int.from_bytes(Q[off:off + 16], 'big') ^ y_int
                y_int = int.from_bytes(ecb_encrypt(blk.to_bytes(16, 'big')), 'big')
        else:
            cbc = AES.new(self._key, AES.MODE_CBC, b'\x00' * 16)
            y_int = int.from_bytes(cbc.encrypt(params.P + Q)[-16:], 'big')

        # Extend the 16-byte MAC output up to d+4 bytes if more precision is
        # needed, then reduce modulo radix^m for this round's parity. The
        # extension blocks E(Y ^ j) are mutually independent, so they are
        # concatenated and encrypted in a single ECB call rather than one call
        # per block.
        d4 = params.d4
        if d4 <= 16:
            y = y_int >> (8 * (16 - d4))
        else:
            extra_blocks = -(-(d4 - 16) // 16)
            buf = b''.join(
                (y_int ^ j).to_bytes(16, 'big') for j in range(1, extra_blocks + 1)
            )
            TMP = y_int.to_bytes(16, 'big') + ecb_encrypt(buf)
            y = int.from_bytes(TMP[:d4], 'big')

        return y % (params.mod_even if (i & 1) == 0 else params.mod_odd)

    def _to_digits(self, value: int, width: int) -> str:
        """Render ``value`` as a radix string, left zero-padded to ``width``."""
        if width <= 0:
            return ''
        s = gmpy2.digits(value, self._radix)
        if len(s) < width:
            return '0' * (width - len(s)) + s
        return s

    def encrypt(self, tweak: Union[FFXInteger, int], plaintext: FFXInteger) -> FFXInteger:
        """Encrypt a plaintext using FFX.

        Args:
            tweak: The tweak value (can be FFXInteger or 0 for no tweak)
            plaintext: The message to encrypt as FFXInteger

        Returns:
            Encrypted message as FFXInteger
        """
        n = len(plaintext)
        l = n // 2
        radix = self._radix

        # Run the Feistel network on the raw integer halves; only the final
        # result is turned back into an FFXInteger. This avoids constructing a
        # padded-string FFXInteger (and re-parsing it) on every round.
        s = plaintext._x
        a = int(s[:l], radix) if l else 0
        b = int(s[l:], radix)

        _, params, q_prefix = self._prepare(n, tweak)
        mod_even, mod_odd = params.mod_even, params.mod_odd

        for i in range(self.NUM_ROUNDS):
            c = (a + self._F(params, q_prefix, i, b)) % (mod_even if (i & 1) == 0 else mod_odd)
            a, b = b, c

        return FFXInteger(self._to_digits(a, l) + self._to_digits(b, n - l), radix=radix)

    def decrypt(self, tweak: Union[FFXInteger, int], ciphertext: FFXInteger) -> FFXInteger:
        """Decrypt a ciphertext using FFX.

        Args:
            tweak: The tweak value (must match the one used for encryption)
            ciphertext: The encrypted message as FFXInteger

        Returns:
            Decrypted message as FFXInteger
        """
        n = len(ciphertext)
        l = n // 2
        radix = self._radix

        s = ciphertext._x
        a = int(s[:l], radix) if l else 0
        b = int(s[l:], radix)

        _, params, q_prefix = self._prepare(n, tweak)
        mod_even, mod_odd = params.mod_even, params.mod_odd

        for i in range(self.NUM_ROUNDS - 1, -1, -1):
            c = b
            b = a
            a = (c - self._F(params, q_prefix, i, b)) % (mod_even if (i & 1) == 0 else mod_odd)

        return FFXInteger(self._to_digits(a, l) + self._to_digits(b, n - l), radix=radix)
