#!/usr/bin/env python
# -*- coding: utf-8 -*-

import FFX

ffx = FFX.new(radix=2)

K = FFX.FFXInteger('0' * 128, radix=2, blocksize=128)
T = FFX.FFXInteger('0' * 8, radix=2, blocksize=8)
X = FFX.FFXInteger('0' * 8, radix=2, blocksize=8)

C = ffx.encrypt(K, T, X)
Y = ffx.decrypt(K, T, C)

print X
print C
print Y
