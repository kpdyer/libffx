#!/usr/bin/env python3
"""Example usage of the FFX library."""

import ffx


def main():
    # Set up parameters
radix = 2
    blocksize = 2 ** 10  # 1024 bits

    # Create key, tweak, and message
K = ffx.FFXInteger('0' * 128, radix=radix, blocksize=128)
T = ffx.FFXInteger('0' * blocksize, radix=radix, blocksize=blocksize)
X = ffx.FFXInteger('0' * blocksize, radix=radix, blocksize=blocksize)

    # Create FFX encrypter
ffx_obj = ffx.new(K.to_bytes(16), radix=radix)

    # Encrypt and decrypt
C = ffx_obj.encrypt(T, X)
Y = ffx_obj.decrypt(T, C)

    print(f"Plaintext:  {X}")
    print(f"Ciphertext: {C}")
    print(f"Decrypted:  {Y}")
    print(f"\nRoundtrip successful: {X == Y}")


if __name__ == "__main__":
    main()
