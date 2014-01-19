#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import FFX
from FFX import FFXInteger


class TestFFX(unittest.TestCase):

    def testFFXInteger1(self):
        X = FFXInteger('1')
        Y = FFXInteger('1')

        self.assertEquals(X + Y, 2)
        self.assertEquals(X + Y, '10')
        self.assertEquals(X + Y, FFXInteger('10'))

    def testFFXInteger2(self):
        X = FFXInteger('000')
        Y = FFXInteger('111')

        self.assertEquals(X + Y, 7)
        self.assertEquals(X + Y, '111')
        self.assertEquals(X + Y, FFXInteger('111'))

    def testFFXInteger3(self):
        X = FFXInteger('000')
        Y = FFXInteger('111')

        self.assertEquals(str(X) + str(Y), '000111')

    def testFFXInteger4(self):
        X = FFXInteger('000')

        self.assertEquals(X.to_bytes(), '\x00')

    def testFFXInteger5(self):
        X = FFXInteger('11111111')

        self.assertEquals(X.to_bytes(), '\xFF')

    def testFFXInteger6(self):
        X = FFXInteger('FF', radix=16)

        self.assertEquals(X.to_bytes(), '\xFF')

    def testFFXInteger3(self):
        for blocksize in range(1, 129):
            X = FFXInteger('0', radix=2, blocksize=blocksize)
            self.assertEquals(len(X), blocksize)

    def testFFXEncrypt1(self):
        radix = 2
        K = FFXInteger('0' * 8, radix=radix, blocksize=128)
        T = FFXInteger('0' * 8, radix=radix, blocksize=8)
        M1 = FFXInteger('0' * 8, radix=radix, blocksize=8)

        ffx = FFX.new(radix)
        C = ffx.encrypt(K, T, M1)
        M2 = ffx.decrypt(K, T, C)

        self.assertEquals(M1, M2)

if __name__ == '__main__':
    unittest.main()
