#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
import time
import random
import string
import argparse

import ffx
from ffx import FFXInteger
from six.moves import range


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--radix", type=int, default=2)
    parser.add_argument("--tweaksize", type=int, default=8)
    parser.add_argument("--messagesize", type=int, default=32)
    parser.add_argument("--trials", type=int, default=10, required=False)
    args = parser.parse_args()

    radix = args.radix
    tweaksize = args.tweaksize
    messagesize = args.messagesize
    trials = args.trials

    keysize = 128
    K = random.randint(0, 2 ** keysize - 1)
    K = FFXInteger(K, radix=2, blocksize=keysize)

    print(
        'RADIX={}, TWEAKSIZE={}, MESSAGESIZE={}, KEY={:x}'.format(
            radix,
            tweaksize,
            messagesize,
            K.to_int()
        )
    )

    ffx_obj = ffx.new(K.to_bytes(), radix)
    for i in range(1, trials):
        T = random.randint(0, radix ** tweaksize - 1)
        T = FFXInteger(T, radix=radix, blocksize=tweaksize)

        M1 = random.randint(0, radix ** messagesize - 1)
        M1 = FFXInteger(M1, radix=radix, blocksize=messagesize)

        start = time.time()
        C = ffx_obj.encrypt(T, M1)
        encrypt_cost = time.time() - start
        encrypt_cost *= 1000.0

        start = time.time()
        M2 = ffx_obj.decrypt(T, C)
        decrypt_cost = time.time() - start
        decrypt_cost *= 1000.0

        assert M1 == M2

        print(
            'test #{} SUCCESS: (encrypt_cost={} ms, decrypt_cost={} ms, tweak={}, plaintext={}, ciphertext={})'.format(
                i,
                round(encrypt_cost, 1),
                round(decrypt_cost, 1),
                T,
                M1,
                C,
            )
        )


if __name__ == "__main__":
    main()
