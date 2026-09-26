"""NIST SP 800-38G FF1 format-preserving encryption.

Implements Algorithm 7 (FF1.Encrypt) and Algorithm 8 (FF1.Decrypt) of
NIST SP 800-38G with AES-128/192/256 as the underlying block cipher.

FF1 is a 10-round Feistel network over numeral strings in an arbitrary
radix. The round function is an AES-CBC-MAC (zero IV) over a fixed header
block P and a per-round block sequence Q, extended with counter-mode-style
blocks when more output bytes are needed.

This module also provides an integer-domain construction (``encrypt_int`` /
``decrypt_int``): FF1 over radix-2 numeral strings of minimal length for
the domain, with cycle walking to stay inside the domain. That construction
is a wire contract; do not change it.
"""

from __future__ import annotations

import string
from collections.abc import Callable
from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import AlphabetError, DomainError, KeyLengthError

#: Default numerals for radix-N instances (radix 2..36), per the FFX
#: convention: digits then lowercase letters.
_BASE36_ALPHABET = string.digits + string.ascii_lowercase

#: format() specs that render the radix-N alphabets they are keyed by.
_FORMAT_SPECS = {2: "b", 8: "o", 10: "d", 16: "x"}

_NUM_ROUNDS = 10

#: Minimum domain size (radix**n or the integer domain N) per
#: Draft SP 800-38G Rev 1.
_MIN_DOMAIN = 1_000_000

#: Relaxed minimum domain size (the original SP 800-38G floor), opted into
#: with allow_small_domain=True.
_MIN_DOMAIN_SMALL = 100

_MAX_ALPHABET = 65536

_MAX_TWEAK_BYTES = 2 ** 32  # exclusive: len(tweak) must be < 2**32

#: Maximum message length (numeral characters) for the string API and
#: maximum Feistel-state bit length for the integer API. SP 800-38G sets
#: no maximum, but the NUM/STR conversions are superlinear in n, so without
#: a cap a caller-supplied long message can burn unbounded CPU in one call
#: (seconds for a 512 KiB input). 8192 numerals keeps the worst
#: case under a fraction of a second while covering every practical
#: format-preserving use.
_MAX_MESSAGE_LEN = 2 ** 13

#: Numeral strings longer than this are converted half by half, which is
#: much faster than one numeral at a time. It is also well under 640, the
#: lowest limit sys.set_int_max_str_digits() accepts, so int() and format()
#: never hit that limit.
_SPLIT_LEN = 64

#: Largest number of AES blocks handed to the shared ECB context in one
#: update() call. cryptography releases the GIL while encrypting a buffer
#: of 2048 bytes or more, and its CipherContext stays exclusively borrowed
#: until the call returns, so a second thread using the same context in
#: that window fails with RuntimeError("Already borrowed"). Keeping every
#: call below the threshold is what makes one FF1 instance safe to share
#: between threads; ECB blocks are independent, so splitting is exact.
_ECB_MAX_BLOCKS_PER_CALL = 127  # 127 * 16 = 2032 bytes


class _FParams(NamedTuple):
    """Cached, (radix, n, t)-dependent parameters for the round function.

    Everything here is a pure function of the radix, the message length
    ``n``, the tweak length ``t``, and the key, so it is computed once per
    distinct (radix, n, t) and reused across rounds and calls.
    """

    e_p: int          # AES(P) as an int: the CBC-MAC chain value after block P
    b_bytes: int      # width, in bytes, of the NUM(B) field appended to Q
    d: int            # number of S bytes consumed before reduction (SP 800-38G d)
    q_zero_pad: int   # zero bytes between the tweak and the round byte in Q
    mod_even: int     # radix ** u, the modulus on even rounds
    mod_odd: int      # radix ** v, the modulus on odd rounds


class _Numerals(NamedTuple):
    """The numeral alphabet of a string-API instance, with the
    SP 800-38G NUM/STR conversions over it. Integer-only instances
    (no radix/alphabet) have none."""

    alphabet: str
    radix: int
    char_to_digit: dict[str, int]
    format_spec: str | None  # for radix 2, 8, 10, 16: format() and int() handle it

    def to_int(self, s: str) -> int:
        """NUM_radix(s): fold a numeral string to an integer."""
        if len(s) > _SPLIT_LEN:
            k = len(s) // 2
            scale: int = self.radix ** k
            return self.to_int(s[:-k]) * scale + self.to_int(s[-k:])
        # Only alphabet characters survive strip(), so int() never sees the
        # signs, spaces, underscores, or uppercase it would also accept.
        if self.format_spec and not s.strip(self.alphabet):
            return int(s, self.radix)
        radix = self.radix
        lookup = self.char_to_digit
        x = 0
        try:
            for ch in s:
                x = x * radix + lookup[ch]
        except KeyError as exc:
            bad = exc.args[0]
            raise AlphabetError(
                f"character {bad!r} is not in the alphabet"
            ) from None
        return x

    def to_str(self, x: int, width: int) -> str:
        """STR_radix(x, width): unfold an integer to a fixed-width numeral
        string."""
        if width > _SPLIT_LEN:
            k = width // 2
            high, low = divmod(x, self.radix ** k)
            return self.to_str(high, width - k) + self.to_str(low, k)
        if self.format_spec is not None:
            return format(x, self.format_spec).zfill(width)
        radix = self.radix
        alphabet = self.alphabet
        out: list[str] = []
        for _ in range(width):
            x, digit = divmod(x, radix)
            out.append(alphabet[digit])
        return "".join(reversed(out))


class FF1:
    """NIST SP 800-38G FF1 format-preserving encryption.

    Args:
        key: AES key; exactly 16, 24, or 32 bytes (AES-128/192/256).
        radix: Base for the message alphabet, 2-36. The alphabet is
            ``"0123456789abcdefghijklmnopqrstuvwxyz"[:radix]``.
        alphabet: Explicit alphabet string (any unique Unicode characters,
            length 2-65536). At most one of ``radix``/``alphabet`` may be
            given; with neither, only ``encrypt_int``/``decrypt_int`` work.
        allow_small_domain: Relax the minimum domain size from 1,000,000
            (Draft SP 800-38G Rev 1) to 100 (original SP 800-38G).

    Instances keep no per-call state and may be shared between threads.

    Messages are limited to 8192 numerals and integer domains to
    ``2**8192``; larger values raise :class:`DomainError`.

    Example:
        >>> cipher = FF1(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        ...              radix=10)
        >>> cipher.encrypt("0123456789")
        '2433477484'
        >>> cipher.decrypt("2433477484")
        '0123456789'
    """

    # For a CBC-MAC over this many 16-byte blocks or fewer, folding the
    # blocks through the persistent ECB context in Python beats creating
    # a fresh AES-CBC context (which re-runs the AES key schedule). Above
    # this size the per-block Python overhead dominates and the C CBC path
    # is faster; the crossover is between 5 and 6 blocks in practice.
    _MAC_INLINE_MAX_BLOCKS = 5

    def __init__(
        self,
        key: bytes,
        *,
        radix: int | None = None,
        alphabet: str | None = None,
        allow_small_domain: bool = False,
    ):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f"key must be bytes, got {type(key).__name__}")
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise KeyLengthError(
                "key must be exactly 16, 24, or 32 bytes "
                f"(AES-128/192/256), got {len(key)}"
            )

        if radix is not None and alphabet is not None:
            raise AlphabetError("pass at most one of radix= and alphabet=")
        if radix is not None:
            if not isinstance(radix, int) or isinstance(radix, bool):
                raise TypeError(
                    f"radix must be an int, got {type(radix).__name__}"
                )
            if not 2 <= radix <= 36:
                raise AlphabetError(f"radix must be in [2, 36], got {radix}")
            alphabet = _BASE36_ALPHABET[:radix]
        elif alphabet is not None:
            if not isinstance(alphabet, str):
                raise TypeError(
                    f"alphabet must be a str, got {type(alphabet).__name__}"
                )
            if len(alphabet) < 2:
                raise AlphabetError(
                    "alphabet must contain at least 2 characters"
                )
            if len(alphabet) > _MAX_ALPHABET:
                raise AlphabetError(
                    f"alphabet must contain at most {_MAX_ALPHABET} characters"
                )
            if len(set(alphabet)) != len(alphabet):
                raise AlphabetError("alphabet characters must be unique")

        format_spec = _FORMAT_SPECS.get(radix) if radix is not None else None
        self._numerals = (
            _Numerals(
                alphabet,
                len(alphabet),
                {c: i for i, c in enumerate(alphabet)},
                format_spec,
            )
            if alphabet is not None
            else None
        )
        self._min_domain = (
            _MIN_DOMAIN_SMALL if allow_small_domain else _MIN_DOMAIN
        )

        # ECB here is the raw single-block AES primitive, which SP 800-38G
        # builds FF1 from (the CBC-MAC chain in F and the S-extension
        # blocks are each one-block CIPH_K calls). No multi-block data is
        # ever encrypted in ECB mode. The encryptor context is persistent:
        # ECB has no chaining state, so update() calls encrypt each aligned
        # block independently and the OpenSSL key schedule runs only once.
        aes = algorithms.AES(key)
        self._ecb_encrypt = Cipher(aes, modes.ECB()).encryptor().update
        # Cipher description for the long-MAC CBC path; encryptor() on it
        # creates a fresh zero-IV context per call.
        self._cbc_cipher = Cipher(aes, modes.CBC(b"\x00" * 16))
        # Per-(radix, message length, tweak length) parameter cache; see
        # _FParams. radix is part of the key because encrypt_int always
        # runs at radix 2, independent of the instance's alphabet.
        self._param_cache: dict[tuple[int, int, int], _FParams] = {}

    # ------------------------------------------------------------------
    # String API
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str, *, tweak: bytes = b"") -> str:
        """Encrypt a numeral string; returns a same-length string over the
        same alphabet."""
        return self._crypt_str(plaintext, tweak, encrypt=True)

    def decrypt(self, ciphertext: str, *, tweak: bytes = b"") -> str:
        """Decrypt a numeral string; inverse of :meth:`encrypt` for the
        same key and tweak."""
        return self._crypt_str(ciphertext, tweak, encrypt=False)

    def _crypt_str(self, message: str, tweak: bytes, *, encrypt: bool) -> str:
        tweak = self._check_tweak(tweak)
        numerals = self._numerals
        if numerals is None:
            raise AlphabetError(
                "this FF1 instance was built without a numeral alphabet; "
                "pass radix= or alphabet= to FF1() to work with strings"
            )
        if not isinstance(message, str):
            raise TypeError(
                f"message must be a str, got {type(message).__name__}"
            )

        radix = numerals.radix
        n = len(message)
        if n > _MAX_MESSAGE_LEN:
            raise DomainError(
                f"message of length {n} exceeds the maximum supported "
                f"length of {_MAX_MESSAGE_LEN} numerals"
            )
        if n < 2 or radix ** n < self._min_domain:
            raise DomainError(
                f"message of length {n} over radix {radix} gives a domain "
                f"below the minimum (need length >= 2 and radix**length >= "
                f"{self._min_domain})"
            )

        u = n // 2
        a = numerals.to_int(message[:u])
        b = numerals.to_int(message[u:])
        if encrypt:
            a, b = self._encrypt_core(radix, n, a, b, tweak)
        else:
            a, b = self._decrypt_core(radix, n, a, b, tweak)
        return numerals.to_str(a, u) + numerals.to_str(b, n - u)

    # ------------------------------------------------------------------
    # Integer API (normative wire contract; see module docstring)
    # ------------------------------------------------------------------

    def encrypt_int(self, x: int, *, domain: int, tweak: bytes = b"") -> int:
        """Encrypt an integer 0 <= x < domain to another integer in the
        same range, via FF1 at radix 2 over (domain-1).bit_length() bits
        with cycle walking."""
        tweak = self._check_tweak(tweak)
        n = self._check_int_args(x, domain)
        v = n - n // 2
        mask = (1 << v) - 1
        y = x
        while True:
            a, b = self._encrypt_core(2, n, y >> v, y & mask, tweak)
            y = (a << v) | b
            if y < domain:
                return y

    def decrypt_int(self, y: int, *, domain: int, tweak: bytes = b"") -> int:
        """Inverse of :meth:`encrypt_int` for the same key, domain, and
        tweak."""
        tweak = self._check_tweak(tweak)
        n = self._check_int_args(y, domain)
        v = n - n // 2
        mask = (1 << v) - 1
        x = y
        while True:
            a, b = self._decrypt_core(2, n, x >> v, x & mask, tweak)
            x = (a << v) | b
            if x < domain:
                return x

    def _check_int_args(self, x: int, domain: int) -> int:
        """Validate (x, domain) and return the bit length n of the Feistel
        state: the smallest n with 2**n >= domain."""
        if not isinstance(domain, int) or isinstance(domain, bool):
            raise TypeError(
                f"domain must be an int, got {type(domain).__name__}"
            )
        if domain < self._min_domain:
            raise DomainError(
                f"domain {domain} is below the minimum {self._min_domain}"
            )
        if not isinstance(x, int) or isinstance(x, bool):
            raise TypeError(f"value must be an int, got {type(x).__name__}")
        if not 0 <= x < domain:
            raise DomainError(f"value {x} is outside [0, {domain})")
        n = (domain - 1).bit_length()
        if n > _MAX_MESSAGE_LEN:
            raise DomainError(
                f"domain of {n} bits exceeds the maximum supported "
                f"domain of 2**{_MAX_MESSAGE_LEN}"
            )
        return n

    # ------------------------------------------------------------------
    # Shared validation
    # ------------------------------------------------------------------

    @staticmethod
    def _check_tweak(tweak: bytes) -> bytes:
        if not isinstance(tweak, (bytes, bytearray)):
            raise TypeError(
                f"tweak must be bytes, got {type(tweak).__name__}"
            )
        if len(tweak) >= _MAX_TWEAK_BYTES:
            raise DomainError("tweak must be shorter than 2**32 bytes")
        return bytes(tweak)

    # ------------------------------------------------------------------
    # FF1 core (SP 800-38G Algorithms 7 and 8)
    # ------------------------------------------------------------------

    def _params(self, radix: int, n: int, t: int) -> _FParams:
        cache_key = (radix, n, t)
        params = self._param_cache.get(cache_key)
        if params is not None:
            return params

        u = n // 2
        v = n - u
        # b = ceil(ceil(v * log2(radix)) / 8), computed exactly:
        # ceil(v * log2(radix)) == ceil(log2(radix**v)) == (radix**v - 1).bit_length()
        b_bytes = ((radix ** v - 1).bit_length() + 7) // 8
        d = 4 * ((b_bytes + 3) // 4) + 4

        # P is the fixed 16-byte header block for this (radix, n, t).
        # Because it never changes, its CBC-MAC first-block image AES(P) is
        # precomputed once here.
        P = (
            b"\x01\x02\x01"
            + radix.to_bytes(3, "big")
            + b"\x0a"                      # always ten rounds
            + bytes((u % 256,))
            + n.to_bytes(4, "big")
            + t.to_bytes(4, "big")
        )
        # codeql[py/weak-cryptographic-algorithm] One-block CIPH_K; see FF1.__init__.
        e_p = int.from_bytes(self._ecb_encrypt(P), "big")

        params = _FParams(
            e_p=e_p,
            b_bytes=b_bytes,
            d=d,
            # Zero bytes between the tweak and the round byte so that
            # len(Q) is a multiple of 16 (P is already one whole block).
            q_zero_pad=(-t - b_bytes - 1) % 16,
            mod_even=radix ** u,
            mod_odd=radix ** v,
        )
        self._param_cache[cache_key] = params
        return params

    def _cbc_mac(self, x: int, blocks: int) -> int:
        """The final block of the zero-IV AES-CBC-MAC over x encoded as
        ``blocks`` big-endian 16-byte blocks."""
        data = x.to_bytes(16 * blocks, "big")
        if blocks > self._MAC_INLINE_MAX_BLOCKS:
            return int.from_bytes(self._cbc_cipher.encryptor().update(data)[-16:], "big")
        r_int = 0
        for off in range(0, len(data), 16):
            blk = int.from_bytes(data[off:off + 16], "big") ^ r_int
            # codeql[py/weak-cryptographic-algorithm] One-block CIPH_K; see FF1.__init__.
            r_int = int.from_bytes(self._ecb_encrypt(blk.to_bytes(16, "big")), "big")
        return r_int

    def _round_function(
        self, params: _FParams, tweak: bytes
    ) -> Callable[[int, int], int]:
        """Return the FF1 round function for one call: F(i, NUM(B)) = y =
        NUM(S) for round i (not yet reduced modulo radix**m)."""
        # R = CBC-MAC_K(P || Q) with a zero IV, where
        # Q = tweak || zero pad || [i] || NUM(B) as b bytes. The chain value
        # after P is cached as AES(P), and the leading blocks of Q, which
        # hold only tweak bytes and padding, are folded in once per call.
        pad, b_bytes = params.q_zero_pad, params.b_bytes
        fixed = (len(tweak) + pad) // 16
        tail = (len(tweak) + pad + 1 + b_bytes) // 16 - fixed
        chain = params.e_p
        if fixed:
            prefix = tweak[:16 * fixed].ljust(16 * fixed, b"\x00")
            chain = self._cbc_mac(
                (chain << (128 * (fixed - 1))) ^ int.from_bytes(prefix, "big"), fixed
            )
        # The remaining blocks of Q, as one integer with the chain value
        # XORed into the first, are base ^ [i] ^ NUM(B): the rest of the
        # tweak, [i], and NUM(B) occupy disjoint bits.
        base = (
            int.from_bytes(tweak[16 * fixed:], "big") << (8 * (pad + 1 + b_bytes))
        ) ^ (chain << (128 * (tail - 1)))
        i_shift = 8 * b_bytes
        d = params.d
        ecb_encrypt = self._ecb_encrypt
        cbc_mac = self._cbc_mac

        def F(i: int, b: int) -> int:
            x = base ^ (i << i_shift) ^ b
            if tail == 1:
                r_int = int.from_bytes(ecb_encrypt(x.to_bytes(16, "big")), "big")
            else:
                r_int = cbc_mac(x, tail)

            # S = first d bytes of R || AES(R xor [1]) || AES(R xor [2]) || ...
            # The extension blocks are mutually independent, so they are
            # concatenated and encrypted in as few ECB calls as the per-call
            # size limit allows (a single call for any right half up to 2032
            # bytes, i.e. every practical message).
            if d <= 16:
                return r_int >> (8 * (16 - d))
            extra_blocks = -(-(d - 16) // 16)
            parts = [r_int.to_bytes(16, "big")]
            for start in range(1, extra_blocks + 1, _ECB_MAX_BLOCKS_PER_CALL):
                stop = min(start + _ECB_MAX_BLOCKS_PER_CALL, extra_blocks + 1)
                parts.append(ecb_encrypt(b"".join(
                    (r_int ^ j).to_bytes(16, "big") for j in range(start, stop)
                )))
            S = b"".join(parts)
            return int.from_bytes(S[:d], "big")

        return F

    def _encrypt_core(
        self, radix: int, n: int, a: int, b: int, tweak: bytes
    ) -> tuple[int, int]:
        """SP 800-38G Algorithm 7 on integer halves (a, b) = (NUM(A), NUM(B))."""
        params = self._params(radix, n, len(tweak))
        F = self._round_function(params, tweak)
        mod_even, mod_odd = params.mod_even, params.mod_odd
        for i in range(_NUM_ROUNDS):
            y = F(i, b)
            a, b = b, (a + y) % (mod_odd if i & 1 else mod_even)
        return a, b

    def _decrypt_core(
        self, radix: int, n: int, a: int, b: int, tweak: bytes
    ) -> tuple[int, int]:
        """SP 800-38G Algorithm 8 on integer halves (a, b) = (NUM(A), NUM(B))."""
        params = self._params(radix, n, len(tweak))
        F = self._round_function(params, tweak)
        mod_even, mod_odd = params.mod_even, params.mod_odd
        for i in range(_NUM_ROUNDS - 1, -1, -1):
            c, b = b, a
            y = F(i, b)
            a = (c - y) % (mod_odd if i & 1 else mod_even)
        return a, b
