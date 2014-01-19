import math
import md5
import string

import gmpy
import Crypto

from Crypto.Cipher import AES

CHARS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
RADIX = len(CHARS)
ZERO_BIT = '0'
bits = 8


def new():
    return FFXEncrypter()


class Bottom(Exception):
    pass


class UnknownTypeException(Exception):
    pass


class FFXInteger(object):

    def __init__(self, x, radix=RADIX, blocksize=None):
        if type(x) in [int, long]:
            self._x = gmpy.digits(x, radix)
        elif type(x) in [str]:
            self._x = x
        elif type(x) in [FFXInteger]:
            self._x = x.to_str()
        else:
            raise UnknownTypeException(type(x))

        self._len = len(self._x)
        self._radix = radix
        self._blocksize = blocksize

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
        # print [type(other), other]the weepies
        if type(other) == FFXInteger:
            retval = self.to_int() == other.to_int()
        elif type(other) in [str]:
            retval = self._x == other
        else:
            raise UnknownTypeException()
        return retval

    def __len__(self):
        return len(self._x)

    def __getitem__(self, i):
        #print [self._x, i]
        return FFXInteger(self._x[i], self._radix, 1)

    def __getslice__(self, i, j):
        #print ['i','j',i,j]
        return FFXInteger(self._x[i:j], self._radix, len(self._x[i:j]))

    def __repr__(self):
        return self._x

    def __str__(self):
        return self._x

    def to_int(self):
        return int(self._x, self._radix)

    def to_bytes(self):
        _cur_len = len(self._x)
        num_bytes = int(_cur_len / 8.0)
        retval = long_to_bytes(self.to_int(), num_bytes)
        return retval

    def to_str(self):
        retval = str(self._x)
        if self._blocksize is not None:
            retval = string.rjust(self._x, self._blocksize, ZERO_BIT)
        return retval


def bytes_to_long(X):
    return Crypto.Util.number.bytes_to_long(X)


def long_to_bytes(n, blocksize=0):
    return Crypto.Util.number.long_to_bytes(n, blocksize)


############
class FFXEncrypter(object):

    def AES_ECB(self, K, X):
        assert (len(X) % 16 == 0)
        ecb_enc_K1 = AES.new(K, AES.MODE_ECB)
        return ecb_enc_K1.encrypt(X)

    def CBC_MAC(self, K, X):
        """TODO"""
        assert(len(X) % 16 == 0)
        m = md5.new()
        m.update(X)
        return m.digest()

    def isEven(self, n):
        return ((n % 2) == 0)

    def xor(self, X, Y, chars, plus=True):
        assert X._radix == Y._radix, (X._radix, Y._radix)
        assert X._blocksize == Y._blocksize, (X._blocksize, Y._blocksize)

        if len(X) > len(Y):
            X_str = str(X)
            Y_str = string.rjust(Y.to_str(), len(X), ZERO_BIT)
        elif len(Y) > len(X):
            X_str = string.rjust(X.to_str(), len(Y), ZERO_BIT)
            Y_str = str(Y)
        else:
            X_str = str(X)
            Y_str = str(Y)
        retval = ''

        for i in range(len(X_str)):
            assert X_str[i] in chars
            assert Y_str[i] in chars
            retchar = chars.index(X_str[i])
            if plus:
                retchar += chars.index(Y_str[i])
            else:
                retchar -= chars.index(Y_str[i])
            retchar %= len(chars)
            retchar = chars[retchar]
            retval += retchar

        return FFXInteger(retval, X._radix, X._blocksize)

    def add(self, X, Y, chars=CHARS):
        return self.xor(X, Y, chars, True)

    def sub(self, X, Y, chars=CHARS):
        return self.xor(X, Y, chars, False)

    def rnds(self, n):
        """TODO"""
        if n >= 8 and n <= 9:
            retval = 36
        if n >= 10 and n <= 13:
            retval = 30
        if n >= 14 and n <= 19:
            retval = 24
        if n >= 20 and n <= 31:
            retval = 18
        if n >= 32 and n <= 128:
            retval = 12
        return retval

    def split(self, n):
        """TODO"""
        return int(math.floor((n * 1.0) / 2))

    def F(self, K, n, T, i, B):
        vers = 1
        method = 2
        addition = 1
        t = len(T)
        beta = math.ceil(n / 2.0)
        b = int(math.ceil(beta * math.log(RADIX, 2) / 8.0))
        d = 4 * int(math.ceil(b / 4.0))
        if self.isEven(i):
            m = int(math.floor(n / 2.0))
        else:
            m = int(math.ceil(n / 2.0))

        P = long_to_bytes(vers, 1)
        P += long_to_bytes(method, 1)
        P += long_to_bytes(addition, 1)
        P += long_to_bytes(RADIX, 3)
        P += long_to_bytes(self.rnds(n), 1)
        P += long_to_bytes(self.split(n), 1)
        P += long_to_bytes(n, 4)
        P += long_to_bytes(t, 4)

        assert len(P) == 16

        #print ['T',T]
        Q = T.to_str()
        Q += FFXInteger(ZERO_BIT, radix=RADIX,
                        blocksize=(((-1 * len(T)) - 1) % 16) * 8).to_str()
        Q += FFXInteger(i, radix=RADIX, blocksize=1).to_str()
        Q += FFXInteger(B, radix=RADIX, blocksize=b).to_str()

        Q = FFXInteger(Q, radix=RADIX)
        Q = Q.to_bytes()

        Y = self.CBC_MAC(K, P + Q)
        TMP = Y
        for i in range(1, RADIX + 1):
            TMP += self.AES_ECB(K.to_bytes(), Y + str(i) * 16)
        TMP = TMP[:d + 4]
        #print [d, len(TMP)]

        y = int(TMP.encode('hex'), base=16)
        #y = FFXInteger(Y,radix=RADIX,blocksize=m)
        z = y % (RADIX ** m)

        return FFXInteger(z, radix=RADIX, blocksize=m)

    def encrypt(self, K, T, X):
        """assertions"""
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
        retval = FFXInteger(str(A) + str(B), radix=RADIX,
                            blocksize=len(A) + len(B))
        return retval

    def decrypt(self, K, T, Y):
        """assertions"""
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

        retval = FFXInteger(str(A) + str(B), radix=RADIX,
                            blocksize=len(A) + len(B))

        return retval
