import string
import math
import binascii

import gmpy as gmpy

from Crypto.Cipher import AES

_gmpy_mpz_type = type(gmpy.mpz(0))
_gmpy_mpf_type = type(gmpy.mpf(0))


def new(radix):
    return FFXEncrypter(radix)


class Bottom(Exception):
    pass


class UnknownTypeException(Exception):
    pass


class InvalidRadixException(Exception):
    pass


def long_to_bytes(N, blocksize=1):
    """Given an input integer ``N``, ``long_to_bytes`` returns the representation of ``N`` in bytes.
    If ``blocksize`` is greater than ``1`` then the output string will be right justified and then padded with zero-bytes,
    such that the return values length is a multiple of ``blocksize``.
    """

    bytestring = gmpy.digits(N, 16)
    bytestring = '0' + bytestring if (len(bytestring) % 2) != 0 else bytestring
    bytestring = binascii.unhexlify(bytestring)

    if blocksize > 0 and len(bytestring) % blocksize != 0:
        bytestring = '\x00' * \
            (blocksize - (len(bytestring) % blocksize)) + bytestring

    return bytestring


def bytes_to_long(bytestring):
    """Given a ``bytestring`` returns its integer representation ``N``.
    """

    bytestring = '\x00' + bytestring
    N = int(bytestring.encode('hex'), 16)
    return N


class FFXInteger(object):

    def __init__(self, x, radix=2, blocksize=None):
        _x_type = type(x)

        if _x_type in [int, long, _gmpy_mpz_type]:
            self._x = gmpy.digits(x, radix)
        elif _x_type in [float, _gmpy_mpf_type]:
            self._x = gmpy.digits(gmpy.mpz(x), radix)
        elif _x_type in [str]:
            self._x = x
        elif _x_type in [FFXInteger]:
            self._x = x._x
        else:
            raise UnknownTypeException(type(x))

        if blocksize:
            assert len(self._x) <= blocksize, (len(self._x), blocksize)
            self._x = '0' * (blocksize - len(self._x)) + self._x

        self._radix = radix
        self._blocksize = blocksize

        self._as_bytes = None
        self._as_int = None

    def __add__(self, other):
        assert other._radix == self._radix, (other._radix, self._radix)
        assert other._blocksize == self._blocksize, (other._blocksize,
                                                     self._blocksize)

        other = FFXInteger(other, self._radix, self._blocksize)

        retval = self.to_int()
        retval += other.to_int()
        retval = gmpy.digits(retval, self._radix)

        if self._blocksize != None:
            retval = string.rjust(retval, self._blocksize, '0')

        return FFXInteger(retval, self._radix, self._blocksize)

    def __eq__(self, other):
        if type(other) == FFXInteger:
            retval = self.to_int() == other.to_int()
        elif type(other) in [str]:
            retval = (self._x == other)
        elif type(other) in [int]:
            retval = (self.to_int() == other)
        else:
            raise UnknownTypeException()
        return retval

    def __len__(self):
        return len(self._x)

    def __getitem__(self, i):
        return FFXInteger(self._x[i], self._radix, 1)

    def __getslice__(self, i, j):
        return FFXInteger(self._x[i:j], self._radix, len(self._x[i:j]))

    def __str__(self):
        return self._x

    def to_int(self):
        if not self._as_int:
            self._as_int = gmpy.mpz(self._x, self._radix)
        return int(self._as_int)

    def to_bytes(self):
        if not self._as_bytes:
            blocksize = int(len(self._x) / 8.0)
            self._as_bytes = long_to_bytes(self.to_int(), blocksize=blocksize)
        return self._as_bytes

    def to_str(self):
        return self._x


class FFXEncrypter(object):

    def __init__(self, radix):
        if radix not in range(2, 26 + 26 + 10 + 1):
            raise InvalidRadixException()

        self._radix = gmpy.mpz(radix)
        self._chars = string.digits + string.ascii_lowercase
        self._chars = self._chars[:radix]
        _chars = []
        for c in self._chars:
            _chars.append(c)
        self._chars = _chars

        self._ecb = {}
        self._P = {}

    def AES_ECB(self, K, X):
        assert (len(X) % 16 == 0), (len(X))

        if not self._ecb.get(K):
            self._ecb[K] = AES.new(K, AES.MODE_ECB)

        return self._ecb[K].encrypt(X)

    def CBC_MAC(self, K, X):
        """TODO"""
        #assert (len(X) % 16 == 0), (len(X))

        Y = '\x00' * 16
        while len(X) > 0:
            Z = bytes_to_long(Y) ^ bytes_to_long(X[:16])
            Z = long_to_bytes(Z, 16)
            Y = self.AES_ECB(K.to_bytes(), Z)
            X = X[16:]

        return Y

    def isEven(self, n):
        return ((n % 2) == 0)

    def add(self, X, Y):
        assert X._radix == Y._radix, (X._radix, Y._radix)
        assert X._blocksize == Y._blocksize, (X._blocksize, Y._blocksize)

        retval = (X.to_int() + Y.to_int()) % (X._radix ** X._blocksize)

        return FFXInteger(retval, X._radix, X._blocksize)

    def sub(self, X, Y):
        assert X._radix == Y._radix, (X._radix, Y._radix)
        assert X._blocksize == Y._blocksize, (X._blocksize, Y._blocksize)

        retval = (X.to_int() - Y.to_int()) % (X._radix ** X._blocksize)

        return FFXInteger(retval, X._radix, X._blocksize)

    def rnds(self, n):
        return 10

    def split(self, n):
        """TODO"""
        return int(math.floor((n * 1.0) / 2))

    def F(self, K, n, T, i, B):
        if T == 0:
            t = 0
        else:
            t = len(T.to_str())

        beta = math.ceil(n / 2.0)
        b = int(math.ceil(beta * math.log(self._radix, 2) / 8.0))
        d = 4 * int(math.ceil(b / 4.0))

        if self.isEven(i):
            m = int(math.floor(n / 2.0))
        else:
            m = int(math.ceil(n / 2.0))

        if not self._P.get(n):
            P = '\x01'  # vers
            P += '\x02'  # method
            P += '\x01'  # addition
            P += long_to_bytes(self._radix, 3)
            P += long_to_bytes(self.rnds(n), 1)
            P += long_to_bytes(self.split(n), 1)
            P += long_to_bytes(n, 4)
            P += long_to_bytes(t, 4)
            self._P[n] = P

        if T == 0:
            Q = ''
        else:
            Q = T.to_str()
        Q += '\x00' * (((-1 * t) - b - 1) % 16)
        Q += long_to_bytes(i, blocksize=1)
        Q += '\x00' * (b - len(B.to_bytes())) + B.to_bytes()

        assert len(self._P[n]) == 16, len(self._P[n])
        #print [len(B.to_bytes()), b, t, Q]
        #assert len(Q) % 16 == 0, len(Q)

        Y = self.CBC_MAC(K, self._P[n] + Q)

        TMP = Y
        for i in range(self._radix):
            if len(TMP) >= (d + 4):
                break
            left = FFXInteger(bytes_to_long(Y),
                              radix=self._radix, blocksize=32)
            right = FFXInteger(
                self._chars[i] * len(left), radix=self._radix, blocksize=len(left))
            X = self.add(left, right)
            TMP += self.AES_ECB(K.to_bytes(), X.to_bytes())
        TMP = TMP[:(d + 4)]

        y = bytes_to_long(TMP)
        z = y % (self._radix ** m)

        return FFXInteger(z, radix=self._radix, blocksize=m)

    def encrypt(self, K, T, X):
        retval = ''

        n = len(X)
        l = self.split(n)
        r = self.rnds(n)
        A = X[:l]
        B = X[l:]
        for i in range(r):
            C = self.add(A, self.F(K, n, T, i, B))
            A = B
            B = C

        retval = FFXInteger(str(A) + str(B), radix=self._radix,
                            blocksize=len(A) + len(B))

        return retval

    def decrypt(self, K, T, Y):
        retval = ''

        n = len(Y)
        l = self.split(n)
        r = self.rnds(n)

        A = Y[:l]
        B = Y[l:]
        for i in range(r - 1, -1, -1):
            C = B
            B = A
            A = self.sub(C, self.F(K, n, T, i, B))

        retval = FFXInteger(str(A) + str(B), radix=self._radix,
                            blocksize=len(A) + len(B))

        return retval
