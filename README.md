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

```

```
$ python benchmark.py --radix 2 --tweaksize 9 --messagesize 9


```

```
$ python benchmark.py --radix 16 --tweaksize 8 --messagesize 8

```
