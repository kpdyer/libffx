#!/usr/bin/env python3
"""Benchmark script for FFX encryption/decryption performance.

Two modes:

* Sweep (default): time a set of representative (radix, message size)
  configurations and print a comparison table.

      python benchmark.py

* Single config: pass --radix / --messagesize / --tweaksize to time one
  configuration in detail.

      python benchmark.py --radix 10 --tweaksize 10 --messagesize 16

Each configuration is warmed up before timing (the first call to a given
message/tweak length builds a small parameter cache), then every op is timed
individually so we can report the median, min, and p95 latency alongside
throughput. All results are validated with an encrypt/decrypt round-trip.
"""

import argparse
import random
import statistics
import time

import ffx
from ffx import FFXInteger


# (radix, tweak size, message size, label) used by the default sweep.
SWEEP_CONFIGS = [
    (2, 8, 32, "binary, 32-bit"),
    (10, 0, 9, "decimal SSN (no tweak)"),
    (10, 10, 9, "decimal SSN"),
    (10, 10, 16, "decimal credit card"),
    (16, 8, 16, "hex, 16-digit"),
    (36, 16, 16, "base36, 16-char"),
    (10, 10, 64, "decimal, 64-digit"),
]


def _random_ffx(radix, size):
    """Random FFXInteger with `size` digits in the given radix."""
    value = random.randint(0, radix ** size - 1)
    return FFXInteger(value, radix=radix, blocksize=size)


def time_config(ffx_obj, radix, tweaksize, messagesize, iterations, warmup):
    """Time one configuration.

    Returns a dict with encrypt/decrypt latency stats (microseconds) and
    throughput (ops/sec). Raises AssertionError if any round-trip fails.
    """
    # Pre-generate inputs so timing excludes RNG / object construction.
    samples = []
    for _ in range(iterations):
        if tweaksize > 0:
            tweak = _random_ffx(radix, tweaksize)
        else:
            tweak = 0
        samples.append((tweak, _random_ffx(radix, messagesize)))

    # Warmup: build the per-length parameter cache and prime the interpreter.
    for tweak, msg in samples[: max(1, min(warmup, len(samples)))]:
        ffx_obj.decrypt(tweak, ffx_obj.encrypt(tweak, msg))

    enc_times, dec_times = [], []
    enc_total = dec_total = 0.0
    for tweak, msg in samples:
        start = time.perf_counter()
        cipher = ffx_obj.encrypt(tweak, msg)
        dt = time.perf_counter() - start
        enc_times.append(dt * 1e6)
        enc_total += dt

        start = time.perf_counter()
        plain = ffx_obj.decrypt(tweak, cipher)
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
    parser = argparse.ArgumentParser(description="Benchmark FFX encryption/decryption")
    parser.add_argument("--radix", type=int, help="Radix for FFX (2-36); single-config mode")
    parser.add_argument("--tweaksize", type=int, default=8, help="Tweak size in radix digits")
    parser.add_argument("--messagesize", type=int, help="Message size in radix digits; single-config mode")
    parser.add_argument("--iterations", type=int, default=5000, help="Timed iterations per config")
    parser.add_argument("--warmup", type=int, default=200, help="Warmup iterations per config")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # Random 128-bit key.
    key = FFXInteger(random.randint(0, 2 ** 128 - 1), radix=2, blocksize=128)
    print(f"KEY=0x{key.to_int():032x}  iterations={args.iterations}  warmup={args.warmup}")
    print("-" * 100)

    single = args.radix is not None or args.messagesize is not None
    if single:
        radix = args.radix if args.radix is not None else 10
        messagesize = args.messagesize if args.messagesize is not None else 16
        configs = [(radix, args.tweaksize, messagesize, f"radix{radix}")]
    else:
        configs = SWEEP_CONFIGS

    for radix, tweaksize, messagesize, label in configs:
        ffx_obj = ffx.new(key.to_bytes(16), radix)
        result = time_config(ffx_obj, radix, tweaksize, messagesize, args.iterations, args.warmup)
        _print_row(label, radix, tweaksize, messagesize, result)


if __name__ == "__main__":
    main()
