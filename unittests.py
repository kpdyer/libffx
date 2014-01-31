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
        self.assertEquals(X + Y, FFXInteger('10'))

    def testFFXInteger2(self):
        X = FFXInteger('000')
        Y = FFXInteger('111')

        self.assertEquals(X + Y, 7)
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

        ffx = FFX.new(K.to_bytes(16), radix)
        C = ffx.encrypt(T, M1)
        M2 = ffx.decrypt(T, C)

        self.assertEquals(M1, M2)

    def testVector1(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('9876543210', radix=radix, blocksize=10)
        M1 = FFXInteger('0123456789', radix=radix, blocksize=10)

        ffx = FFX.new(K.to_bytes(16), radix)
        C = ffx.encrypt(T, M1)
        self.assertEquals(C, '6124200773')
        M2 = ffx.decrypt(T, C)

        self.assertEquals(M1, M2)

        print ''
        print 'TEST VECTOR #1: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C)

    def testVector2(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = 0  # FFXInteger(0, radix=radix, blocksize=2)
        M1 = FFXInteger('0123456789', radix=radix, blocksize=10)

        ffx = FFX.new(K.to_bytes(16), radix)
        C = ffx.encrypt(T, M1)
        self.assertEquals(C, '2433477484')
        M2 = ffx.decrypt(T, C)

        self.assertEquals(M1, M2)

        print ''
        print 'TEST VECTOR #2: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C)

    def testVector3(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('2718281828', radix=radix, blocksize=10)
        M1 = FFXInteger('314159', radix=radix, blocksize=6)

        ffx = FFX.new(K.to_bytes(16), radix)
        C = ffx.encrypt(T, M1)
        self.assertEquals(C, '535005')
        M2 = ffx.decrypt(T, C)

        self.assertEquals(M1, M2)

        print ''
        print 'TEST VECTOR #3: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C)

    def testVector4(self):
        # see aes-ffx-vectors.txt

        radix = 10
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('7777777', radix=radix, blocksize=7)
        M1 = FFXInteger('999999999', radix=radix, blocksize=9)

        ffx = FFX.new(K.to_bytes(16), radix)
        C = ffx.encrypt(T, M1)
        self.assertEquals(C, '658229573')
        M2 = ffx.decrypt(T, C)

        self.assertEquals(M1, M2)

        print ''
        print 'TEST VECTOR #4: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C)

    def testVector5(self):
        # see aes-ffx-vectors.txt

        radix = 36
        K = FFXInteger('2b7e151628aed2a6abf7158809cf4f3c',
                       radix=16, blocksize=32)
        T = FFXInteger('TQF9J5QDAGSCSPB1', radix=radix, blocksize=16)
        M1 = FFXInteger('C4XPWULBM3M863JH', radix=radix, blocksize=16)

        ffx = FFX.new(K.to_bytes(16), radix)
        C = ffx.encrypt(T, M1)
        self.assertEquals(str(C).upper(), 'C8AQ3U846ZWH6QZP')
        M2 = ffx.decrypt(T, C)

        self.assertEquals(M1, M2)

        print ''
        print 'TEST VECTOR #5: radix=' + str(radix) + ', input=' + str(M1) + ', tweak=' + str(T) + ', encrypted=' + str(C)


if __name__ == '__main__':
    unittest.main()
