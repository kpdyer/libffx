FFX
===


Example Usage
-------------

```
>>> import FFX
>>>
>>> ffx = FFX.new(radix=2)
>>>
>>> K = FFX.FFXInteger('0'*128, radix=2, blocksize=128)
>>> T = FFX.FFXInteger('0'*8, radix=2, blocksize=8)
>>> M = FFX.FFXInteger('0'*8, radix=2, blocksize=8)
>>>
>>> print M
0000000
>>> C = ffx.encrypt(K, T, M)
>>> print C
00010111
>>> ffx.decrypt(K, T, C)
00000000
```


Benchmarks
----------

```
$ python benchmark.py --radix 2 --tweaksize 8 --messagesize 8
RADIX=2, TWEAKSIZE=8, MESSAGESIZE=8, KEY=0xa4482fcbe4bbd5dc4046b9aaccdeec4L
test #01 SUCCESS: (tweak=11110011, plaintext=01111000, ciphertext=11010101, encrypt_cost=3.8ms, decrypt_cost=3.0ms)
test #02 SUCCESS: (tweak=11110001, plaintext=10000110, ciphertext=10111010, encrypt_cost=2.9ms, decrypt_cost=2.9ms)
test #03 SUCCESS: (tweak=11000001, plaintext=11100101, ciphertext=01100100, encrypt_cost=2.9ms, decrypt_cost=2.9ms)
test #04 SUCCESS: (tweak=11000100, plaintext=01000110, ciphertext=01001010, encrypt_cost=2.9ms, decrypt_cost=2.9ms)
test #05 SUCCESS: (tweak=11011101, plaintext=10000111, ciphertext=01000011, encrypt_cost=3.1ms, decrypt_cost=2.9ms)
test #06 SUCCESS: (tweak=10011101, plaintext=11011111, ciphertext=00010101, encrypt_cost=3.1ms, decrypt_cost=2.9ms)
test #07 SUCCESS: (tweak=10110011, plaintext=01111110, ciphertext=00001011, encrypt_cost=2.8ms, decrypt_cost=2.8ms)
test #08 SUCCESS: (tweak=01000001, plaintext=01000111, ciphertext=10111110, encrypt_cost=2.9ms, decrypt_cost=2.9ms)
test #09 SUCCESS: (tweak=00000010, plaintext=10111000, ciphertext=01100010, encrypt_cost=2.8ms, decrypt_cost=2.8ms)
test #10 SUCCESS: (tweak=00100100, plaintext=10001111, ciphertext=00110011, encrypt_cost=2.8ms, decrypt_cost=3.0ms)
```

```
$ python benchmark.py --radix 2 --tweaksize 9 --messagesize 9
RADIX=2, TWEAKSIZE=9, MESSAGESIZE=9, KEY=0xae8ed35eaa4731e118c340f31ebdc57aL
test #01 SUCCESS: (tweak=111000011, plaintext=001100011, ciphertext=110111101, encrypt_cost=3.1ms, decrypt_cost=2.8ms)
test #02 SUCCESS: (tweak=101101000, plaintext=111101011, ciphertext=101000000, encrypt_cost=2.8ms, decrypt_cost=2.8ms)
test #03 SUCCESS: (tweak=010010010, plaintext=110001100, ciphertext=100110101, encrypt_cost=2.8ms, decrypt_cost=2.8ms)
test #04 SUCCESS: (tweak=010010010, plaintext=001100000, ciphertext=001010111, encrypt_cost=2.9ms, decrypt_cost=2.9ms)
test #05 SUCCESS: (tweak=001100110, plaintext=011100111, ciphertext=000111011, encrypt_cost=3.0ms, decrypt_cost=3.2ms)
test #06 SUCCESS: (tweak=111001010, plaintext=000011011, ciphertext=110111110, encrypt_cost=2.8ms, decrypt_cost=2.8ms)
test #07 SUCCESS: (tweak=110001011, plaintext=010111100, ciphertext=011110011, encrypt_cost=2.8ms, decrypt_cost=2.8ms)
test #08 SUCCESS: (tweak=010011000, plaintext=111011110, ciphertext=110010101, encrypt_cost=2.8ms, decrypt_cost=2.8ms)
test #09 SUCCESS: (tweak=100000001, plaintext=111011100, ciphertext=011110011, encrypt_cost=2.8ms, decrypt_cost=3.0ms)
test #10 SUCCESS: (tweak=010001011, plaintext=001010101, ciphertext=101000110, encrypt_cost=2.9ms, decrypt_cost=3.1ms)
```

```
$ python benchmark.py --radix 16 --tweaksize 8 --messagesize 8
RADIX=16, TWEAKSIZE=8, MESSAGESIZE=8, KEY=0xb19740861b7c1b304b8c564d139c09dL
test #01 SUCCESS: (tweak=6c310f89, plaintext=be5e53e4, ciphertext=03544af0, encrypt_cost=8.7ms, decrypt_cost=8.2ms)
test #02 SUCCESS: (tweak=116c3e57, plaintext=19df2bf8, ciphertext=d62ccb93, encrypt_cost=8.4ms, decrypt_cost=8.9ms)
test #03 SUCCESS: (tweak=bfc200c9, plaintext=6203aad5, ciphertext=2f4168a2, encrypt_cost=8.0ms, decrypt_cost=8.2ms)
test #04 SUCCESS: (tweak=7ae9dfdb, plaintext=0f417964, ciphertext=a90917df, encrypt_cost=8.8ms, decrypt_cost=8.3ms)
test #05 SUCCESS: (tweak=3a1ccccb, plaintext=ca9f7bd4, ciphertext=79441674, encrypt_cost=8.2ms, decrypt_cost=8.3ms)
test #06 SUCCESS: (tweak=43dd68eb, plaintext=2ff3cc3e, ciphertext=53207a23, encrypt_cost=8.7ms, decrypt_cost=8.2ms)
test #07 SUCCESS: (tweak=18c8677f, plaintext=8d0096ae, ciphertext=17b21da1, encrypt_cost=8.2ms, decrypt_cost=8.6ms)
test #08 SUCCESS: (tweak=096886ba, plaintext=19481ec3, ciphertext=167182ee, encrypt_cost=8.4ms, decrypt_cost=8.2ms)
test #09 SUCCESS: (tweak=47ed4185, plaintext=6ba2a57d, ciphertext=1ea7bec2, encrypt_cost=8.2ms, decrypt_cost=8.9ms)
test #10 SUCCESS: (tweak=3ea10457, plaintext=c0f976af, ciphertext=cb78bd5a, encrypt_cost=8.1ms, decrypt_cost=8.1ms)
```
