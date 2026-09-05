"""Check benchmark CLI reproducibility, warmup counts, and input errors."""

import sys

import pytest

import benchmark
from ffx import FF1


@pytest.mark.parametrize("warmup", [0, 2, 10])
def test_seeded_inputs_and_warmup(monkeypatch, warmup):
    runs = []

    class RecordingFF1(FF1):
        def __init__(self, key, **kwargs):
            super().__init__(key, **kwargs)
            self.calls = []
            runs.append((key, self.calls))

        def encrypt(self, plaintext, *, tweak=b""):
            self.calls.append((plaintext, tweak))
            return super().encrypt(plaintext, tweak=tweak)

    monkeypatch.setattr(benchmark, "FF1", RecordingFF1)
    monkeypatch.setattr(sys, "argv", [
        "benchmark.py", "--seed", "123", "--iterations", "3",
        "--warmup", str(warmup), "--tweaksize", "0",
    ])
    benchmark.main()
    benchmark.main()

    # --tweaksize alone selects one configuration; the seed covers all its inputs.
    assert len(runs) == 2
    assert runs[0] == runs[1]
    calls = runs[0][1]
    assert len(calls) == 3 + min(warmup, 3)
    assert all(tweak == b"" for _, tweak in calls)


@pytest.mark.parametrize("option,value", [
    ("--iterations", "0"), ("--iterations", "-1"),
    ("--warmup", "-1"), ("--tweaksize", "-1"),
])
def test_invalid_counts(monkeypatch, capsys, option, value):
    monkeypatch.setattr(sys, "argv", ["benchmark.py", option, value])
    with pytest.raises(SystemExit) as exc:
        benchmark.main()
    assert exc.value.code == 2
    assert option in capsys.readouterr().err
