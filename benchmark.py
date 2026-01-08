#!/usr/bin/env python3
"""Benchmark script for FFX encryption/decryption performance."""

import argparse
import random
import time

import ffx 
from ffx import FFXInteger


def main():
    parser = argparse.ArgumentParser(description="Benchmark FFX encryption/decryption")
    parser.add_argument("--radix", type=int, default=2, help="Radix for FFX (2-36)")
    parser.add_argument("--tweaksize", type=int, default=8, help="Size of tweak in radix digits")
    parser.add_argument("--messagesize", type=int, default=32, help="Size of message in radix digits")
    parser.add_argument("--trials", type=int, default=10, help="Number of trials to run")
    args = parser.parse_args()

    radix = args.radix
    tweaksize = args.tweaksize
    messagesize = args.messagesize
    trials = args.trials

    # Generate random key
    keysize = 128
    K = random.randint(0, 2 ** keysize - 1)
    K = FFXInteger(K, radix=2, blocksize=keysize)

    banner = [
        f'RADIX={radix}',
        f'TWEAKSIZE={tweaksize}',
        f'MESSAGESIZE={messagesize}',
        f'KEY=0x{K.to_int():x}'
              ]
    print(', '.join(banner))

    ffx_obj = ffx.new(K.to_bytes(), radix)
    
    for i in range(1, trials):
        # Generate random tweak
        T = random.randint(0, radix ** tweaksize - 1)
        T = FFXInteger(T, radix=radix, blocksize=tweaksize)

        # Generate random message
        M1 = random.randint(0, radix ** messagesize - 1)
        M1 = FFXInteger(M1, radix=radix, blocksize=messagesize) 

        # Benchmark encryption
        start = time.perf_counter()
        C = ffx_obj.encrypt(T, M1)
        encrypt_cost = (time.perf_counter() - start) * 1000.0

        # Benchmark decryption
        start = time.perf_counter()
        M2 = ffx_obj.decrypt(T, C)
        decrypt_cost = (time.perf_counter() - start) * 1000.0

        # Verify correctness
        assert M1 == M2, f"Decryption failed: {M1} != {M2}"

        trial_num = str(i).zfill(len(str(trials - 1)))
        results = [
            f'encrypt_cost={encrypt_cost:.1f}ms',
            f'decrypt_cost={decrypt_cost:.1f}ms',
            f'tweak={T}',
            f'plaintext={M1}',
            f'ciphertext={C}',
                    ]
        print(f'test #{trial_num} SUCCESS: ({", ".join(results)})')


if __name__ == "__main__":
    main()
