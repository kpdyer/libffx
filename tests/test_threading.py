"""One FF1 instance shared between threads.

A ``cryptography`` cipher context raises ``RuntimeError: Already borrowed``
if two threads use it at once: on free-threaded Python for any call, and
with the GIL for buffers of 2048 bytes or more. FF1 gives each thread its
own context; CI runs these tests on a free-threaded build too.
"""

import random
import threading

from ffx import FF1

KEY = bytes(range(16))
BIG_ALPHABET = "".join(map(chr, range(65536)))


def run_in_threads(work, n_threads=8):
    errors = []

    def worker():
        try:
            work()
        except BaseException as exc:  # noqa: BLE001 - surface everything
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[0]


def test_shared_instance_short_messages():
    cipher = FF1(KEY, radix=10)
    plaintext = "4111111111111111"
    expected = cipher.encrypt(plaintext, tweak=b"t")

    def work():
        for _ in range(500):
            assert cipher.encrypt(plaintext, tweak=b"t") == expected
            assert cipher.decrypt(expected, tweak=b"t") == plaintext

    run_in_threads(work)


def test_shared_instance_long_messages():
    # radix 65536, n = 2200: d = 2204, so each round's S-extension is one
    # 2192-byte ECB call, which cryptography makes with the GIL released.
    cipher = FF1(KEY, alphabet=BIG_ALPHABET)
    rng = random.Random(2200)
    plaintext = "".join(rng.choices(BIG_ALPHABET, k=2200))
    expected = cipher.encrypt(plaintext, tweak=b"long")

    def work():
        for _ in range(5):
            assert cipher.encrypt(plaintext, tweak=b"long") == expected
            assert cipher.decrypt(expected, tweak=b"long") == plaintext

    run_in_threads(work)
