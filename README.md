FFX
===

[![Build Status](https://travis-ci.org/kpdyer/libffx.svg?branch=master)](https://travis-ci.org/kpdyer/libffx)

This is a python implementation of The FFX Mode of Operation for Format-Preserving Encryption [1,2].

This implementation takes into consideration the addendum in [2]. This implementation has been tested to work with message sizes in {2,...,128} and radix values of {2,...,62}. It uses maximally-balanced Feistel with a constant of 10 rounds, indepdenent of messages size, as per [2].


* [1] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf
* [2] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf


Example Usage
-------------

```
>>> import ffx
>>>
>>> K = ffx.FFXInteger('0'*128, radix=2, blocksize=128)
>>> T = ffx.FFXInteger('0'*8,   radix=2, blocksize=8)
>>> X = ffx.FFXInteger('0'*8,   radix=2, blocksize=8)
>>>
>>> ffxObj = ffx.new(K, radix=2)
>>>
>>> C = ffxObj.encrypt(T, X)
>>> Y = ffxObj.decrypt(T, C)
>>>
>>> print X
00000000
>>> print C
10100010
>>> print Y
00000000
```

Unit Tests / Test Vectors
-------------------------
We have our own unit tests.
In addition, Voltage has provided test vectors, which we've used to validate our implementation: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt

```
$ python unittests.py
TEST VECTOR #1: radix=10, input=0123456789, tweak=9876543210, encrypted=6124200773
TEST VECTOR #2: radix=10, input=0123456789, tweak=0, encrypted=2433477484
TEST VECTOR #3: radix=10, input=314159, tweak=2718281828, encrypted=535005
TEST VECTOR #4: radix=10, input=999999999, tweak=7777777, encrypted=658229573
TEST VECTOR #5: radix=36, input=C4XPWULBM3M863JH, tweak=TQF9J5QDAGSCSPB1, encrypted=c8aq3u846zwh6qzp
----------------------------------------------------------------------
Ran 12 tests in 0.006s

OK
```


Benchmarks
----------

```
$ python benchmark.py --radix 2 --tweaksize 8 --messagesize 8
RADIX=2, TWEAKSIZE=8, MESSAGESIZE=8, KEY=0x7fab9cfe5f0b2f4b61fc18fc018e1d66L
test #1 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.4ms, tweak=00011000, plaintext=11110110, ciphertext=00000101)
test #2 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.4ms, tweak=10101101, plaintext=01100001, ciphertext=01101001)
test #3 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.4ms, tweak=10111100, plaintext=10011111, ciphertext=11010111)
test #4 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.3ms, tweak=00010000, plaintext=11101011, ciphertext=11010110)
test #5 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.4ms, tweak=01100111, plaintext=11111101, ciphertext=01010100)
test #6 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.3ms, tweak=00010110, plaintext=01111001, ciphertext=01110101)
test #7 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.3ms, tweak=10000010, plaintext=00001110, ciphertext=10011101)
test #8 SUCCESS: (encrypt_cost=0.3ms, decrypt_cost=0.4ms, tweak=01001000, plaintext=11011111, ciphertext=11110110)
test #9 SUCCESS: (encrypt_cost=0.4ms, decrypt_cost=0.3ms, tweak=00110111, plaintext=01001101, ciphertext=10010110)
```

```
$ python benchmark.py --radix 16 --tweaksize 32 --messagesize 32
RADIX=16, TWEAKSIZE=32, MESSAGESIZE=32, KEY=0xa8751544df84f7140eaf36ffe3484cc4L
test #1 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.5ms, tweak=47043403a1e3d0eac42a22cd89a43afd, plaintext=245ad41b48838606173a85083717ef69, ciphertext=79aaa17eaf64fe2d7ecba00dac466898)
test #2 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.5ms, tweak=1c2d16e0a9e6776117b9cb5d8bcb27e2, plaintext=017c5d0daabe6504e201568bb87a241e, ciphertext=513b96b8ade2d315866a16f3784d141a)
test #3 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.5ms, tweak=9b3857a1f0cfa8cf2046b53447956af5, plaintext=df18342e3b7331d26b6c978a5dc82e27, ciphertext=a83571857193ec41d13583d935c869e9)
test #4 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.5ms, tweak=274a3c9963a994e25f7f1c12135f0632, plaintext=46fbade6a0e4e98676d52ce03f25b50b, ciphertext=83cfcda35e960c1af2d29b4d4ebdc915)
test #5 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.5ms, tweak=84efb2f650923859d42fa00a8c1382c0, plaintext=fc1ee6ec0ad9fc02a04a167904a25412, ciphertext=24430ca362114c7c484985c394afb68d)
test #6 SUCCESS: (encrypt_cost=0.6ms, decrypt_cost=0.5ms, tweak=3287ca9835f976eaaddff4029aeb6eac, plaintext=a12305da848fddd2a6b563a6a6510d6a, ciphertext=281b14ff14f954c8391801db948e4ff1)
test #7 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.5ms, tweak=4b969bd2495c36179d305b4e6cff8d3b, plaintext=015fb0ded9f8949a287dbb9f2f87f79a, ciphertext=07a45a4a7c7b0a0c78b9b5c936cf29a1)
test #8 SUCCESS: (encrypt_cost=0.5ms, decrypt_cost=0.5ms, tweak=69b55befdfbdacf7bf12e2cb057b723a, plaintext=8874128c934082f202f8963c4c0ee5e4, ciphertext=0e642513e36016bc670615529b06be15)
test #9 SUCCESS: (encrypt_cost=0.6ms, decrypt_cost=0.6ms, tweak=e9e74053084efa895f8a74e90349fc90, plaintext=0bc76a380dd83942db3dccb3ed4918dd, ciphertext=5786d6bd86642052786f89f3521ca68d)
```

Author
------

Kevin P. Dyer (kdyer@cs.pdx.edu)
