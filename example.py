#!/usr/bin/env python
# -*- coding: utf-8 -*-

import FFX


radix = 2
blocksize = 2 ** 10

ffx = FFX.new(radix=radix)

K = FFX.FFXInteger('0' * 128, radix=radix, blocksize=128)
T = FFX.FFXInteger('0' * blocksize, radix=radix, blocksize=blocksize)
X = FFX.FFXInteger('0' * blocksize, radix=radix, blocksize=blocksize)

C = ffx.encrypt(K, T, X)
Y = ffx.decrypt(K, T, C)

print X
print C
print Y
