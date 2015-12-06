#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ffx


radix = 2
blocksize = 2 ** 10

K = ffx.FFXInteger('0' * 128, radix=radix, blocksize=128)
T = ffx.FFXInteger('0' * blocksize, radix=radix, blocksize=blocksize)
X = ffx.FFXInteger('0' * blocksize, radix=radix, blocksize=blocksize)

ffx_obj = ffx.new(K.to_bytes(16), radix=radix)

C = ffx_obj.encrypt(T, X)
Y = ffx_obj.decrypt(T, C)

print X
print C
print Y
