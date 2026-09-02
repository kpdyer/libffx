"""One FF1 instance shared between threads.

FF1 keeps no per-call state, but every call goes through one persistent
AES-ECB context from ``cryptography``. That backend releases the GIL while
encrypting a buffer of 2048 bytes or more and holds an exclusive borrow on
the context until the call returns, so a second thread using the same
context in that window fails with ``RuntimeError: Already borrowed``. The
library therefore never hands the shared context a buffer that large; the
only place that could is the S-extension step for wide right halves, which
is split into calls of at most 127 blocks (2032 bytes).
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


def test_ecb_calls_stay_below_gil_release_threshold():
    """Deterministic form of the invariant: record every buffer handed to
    the shared ECB context while encrypting a message whose S-extension
    would otherwise be a single 4400-byte call, and check none reaches
    2048 bytes."""
    cipher = FF1(KEY, alphabet=BIG_ALPHABET)
    sizes = []
    real_ecb_encrypt = cipher._ecb_encrypt

    def recording_ecb_encrypt(buf):
        sizes.append(len(buf))
        return real_ecb_encrypt(buf)

    cipher._ecb_encrypt = recording_ecb_encrypt
    rng = random.Random(4400)
    plaintext = "".join(rng.choices(BIG_ALPHABET, k=4400))  # d = 4404
    assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext
    assert max(sizes) >= 1024, "the S-extension path was not exercised"
    assert max(sizes) < 2048


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
    # radix 65536, n = 2200: d = 2204, so each round's S-extension covers
    # 137 blocks and takes the chunked path.
    cipher = FF1(KEY, alphabet=BIG_ALPHABET)
    rng = random.Random(2200)
    plaintext = "".join(rng.choices(BIG_ALPHABET, k=2200))
    expected = cipher.encrypt(plaintext, tweak=b"long")

    def work():
        for _ in range(5):
            assert cipher.encrypt(plaintext, tweak=b"long") == expected
            assert cipher.decrypt(expected, tweak=b"long") == plaintext

    run_in_threads(work)
