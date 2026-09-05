#!/usr/bin/env python3
"""Time FF1 encryption and decryption, checking every round-trip.

Run a representative sweep with `python benchmark.py`, or select one case:
    python benchmark.py --radix 10 --tweaksize 10 --messagesize 16 --seed 42

Inputs are generated before timing. Warmup uses at most --iterations samples;
--warmup 0 disables it. A seed reproduces keys and inputs, not measured timings.
"""

import argparse
import random
import statistics
import time

from ffx import FF1

BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"

# (radix, tweak size in bytes, message size, label) used by the default sweep.
SWEEP_CONFIGS = [
    (2, 8, 32, "binary, 32-bit"),
    (10, 0, 9, "decimal SSN (no tweak)"),
    (10, 10, 9, "decimal SSN"),
    (10, 10, 16, "decimal credit card"),
    (16, 8, 16, "hex, 16-digit"),
    (36, 16, 16, "base36, 16-char"),
    (10, 10, 64, "decimal, 64-digit"),
]


def time_config(cipher, radix, tweaksize, messagesize, iterations, warmup, *, rng):
    """Time one configuration.

    Returns a dict with encrypt/decrypt latency stats (microseconds) and
    throughput (ops/sec). Raises AssertionError if any round-trip fails.
    """
    # Pre-generate inputs so timing excludes RNG / object construction.
    alphabet = BASE36[:radix]
    samples = [
        (rng.randbytes(tweaksize), "".join(rng.choice(alphabet) for _ in range(messagesize)))
        for _ in range(iterations)
    ]

    # Warmup: build the per-length parameter cache and prime the interpreter.
    for tweak, msg in samples[:warmup]:
        cipher.decrypt(cipher.encrypt(msg, tweak=tweak), tweak=tweak)

    enc_times, dec_times = [], []
    enc_total = dec_total = 0.0
    for tweak, msg in samples:
        start = time.perf_counter()
        ciphertext = cipher.encrypt(msg, tweak=tweak)
        dt = time.perf_counter() - start
        enc_times.append(dt * 1e6)
        enc_total += dt

        start = time.perf_counter()
        plain = cipher.decrypt(ciphertext, tweak=tweak)
        dt = time.perf_counter() - start
        dec_times.append(dt * 1e6)
        dec_total += dt

        assert plain == msg, f"round-trip failed: {msg} != {plain}"

    def stats(times, total):
        ordered = sorted(times)
        p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
        return {
            "median_us": statistics.median(times),
            "min_us": ordered[0],
            "p95_us": p95,
            "ops_per_sec": len(times) / total if total else float("inf"),
        }

    return {"encrypt": stats(enc_times, enc_total), "decrypt": stats(dec_times, dec_total)}


def _print_row(label, radix, tweaksize, messagesize, result):
    e, d = result["encrypt"], result["decrypt"]
    print(
        f"{label:24s} r={radix:<2d} t={tweaksize:<3d} n={messagesize:<3d} | "
        f"enc {e['median_us']:6.1f}us (min {e['min_us']:5.1f}, p95 {e['p95_us']:6.1f}) "
        f"{e['ops_per_sec']:8,.0f}/s | "
        f"dec {d['median_us']:6.1f}us {d['ops_per_sec']:8,.0f}/s"
    )


def main():
    parser = argparse.ArgumentParser(description="Benchmark FF1 encryption/decryption")
    parser.add_argument("--radix", type=int, help="Radix for FF1 (2-36); single-config mode")
    parser.add_argument("--tweaksize", type=int, help="Tweak size in bytes (default: 8); single-config mode")
    parser.add_argument("--messagesize", type=int, help="Message size in radix digits; single-config mode")
    parser.add_argument("--iterations", type=int, default=5000, help="Timed iterations per config")
    parser.add_argument("--warmup", type=int, default=200, help="Warmup iterations per config")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducibility")
    args = parser.parse_args()

    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    if args.warmup < 0:
        parser.error("--warmup must be nonnegative")
    if args.tweaksize is not None and args.tweaksize < 0:
        parser.error("--tweaksize must be nonnegative")

    rng = random.Random(args.seed)
    key = rng.getrandbits(128).to_bytes(16, "big")
    print(f"KEY=0x{key.hex()}  iterations={args.iterations}  warmup={args.warmup}")
    print("-" * 100)

    single = any(value is not None for value in (args.radix, args.messagesize, args.tweaksize))
    if single:
        radix = args.radix if args.radix is not None else 10
        messagesize = args.messagesize if args.messagesize is not None else 16
        tweaksize = args.tweaksize if args.tweaksize is not None else 8
        configs = [(radix, tweaksize, messagesize, f"radix{radix}")]
    else:
        configs = SWEEP_CONFIGS

    for radix, tweaksize, messagesize, label in configs:
        cipher = FF1(key, radix=radix, allow_small_domain=True)
        result = time_config(
            cipher, radix, tweaksize, messagesize, args.iterations, args.warmup, rng=rng
        )
        _print_row(label, radix, tweaksize, messagesize, result)


if __name__ == "__main__":
    main()
