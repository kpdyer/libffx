import md5
import math
import string
import random
import unittest

import Crypto.Util.number
import gmpy

from Crypto.Cipher import AES
import FFX

CHARS = FFX.CHARS
bits = FFX.bits
RADIX = FFX.RADIX


def random_int(length, chars=CHARS):
    retval = ''
    for i in range(length):
        retval += random.choice(chars)
    return retval


def main():
    for i in range(2 ** 16):
        K = random_int(128, ['0', '1'])
        T = random_int(bits)
        M1 = random_int(bits)

        K = string.rjust(K, 128, '0')  # must be 128 bits, no matter what
        T = string.rjust(T, bits, '0')
        M1 = string.rjust(M1, bits, '0')

        K = FFX.FFXInteger(K, radix=2, blocksize=128)
        T = FFX.FFXInteger(T, radix=RADIX, blocksize=bits)
        M1 = FFX.FFXInteger(M1, radix=RADIX, blocksize=bits)

        ffx = FFX.new()
        C = ffx.encrypt(K, T, M1)
        M2 = ffx.decrypt(K, T, C)

        print ['K,T,M1,C,M2', K, T, M1, C, M2]

        assert M1 == M2

if __name__ == "__main__":
    main()
