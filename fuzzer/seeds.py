"""Heuristic seed generator for the TLV fuzzer.

Not an actual LLM call (no network access from the fuzz loop, and fuzzing
should stay deterministic/offline) — instead it encodes the same priors an
LLM would suggest when asked "what inputs are likely to find bugs in a
length-prefixed binary parser": boundary lengths, type-specific edge cases,
and known-interesting byte patterns. Each seed is a raw TLV frame:
[type:1][len:1][value: len bytes].
"""
from __future__ import annotations

import random

CMD_ECHO, CMD_SET_OFFSET, CMD_READ_MEM, CMD_PING = 0x01, 0x02, 0x03, 0x04
ALL_TYPES = (CMD_ECHO, CMD_SET_OFFSET, CMD_READ_MEM, CMD_PING)

INTERESTING_LENGTHS = (0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 63, 64, 127,
                        128, 200, 254, 255)
INTERESTING_ADDRS = (
    0x00000000, 0x00004000, 0x00004200, 0x1FFFFFFF,
    0x20000000, 0x2000FFFC, 0x40000000, 0x4000C000,
    0xE000ED00, 0xFFFFFFFF,
)
FILL_BYTES = (0x00, 0x41, 0xAA, 0xFF, 0x80, 0x7F)


def _frame(type_byte: int, value: bytes) -> bytes:
    return bytes([type_byte & 0xFF, len(value) & 0xFF]) + value


def seed_corpus() -> list[bytes]:
    """A deterministic, reasonably broad starting corpus."""
    seeds: list[bytes] = []

    # Baseline happy-path frames.
    seeds.append(_frame(CMD_PING, b""))
    seeds.append(_frame(CMD_ECHO, b"hello"))

    # Boundary lengths against the ECHO/SET_OFFSET fixed-size stack buffers.
    for t in (CMD_ECHO, CMD_SET_OFFSET):
        for n in INTERESTING_LENGTHS:
            for fb in FILL_BYTES:
                seeds.append(_frame(t, bytes([fb]) * n))

    # len==0 specifically targets the SET_OFFSET integer underflow.
    seeds.append(_frame(CMD_SET_OFFSET, b""))

    # READ_MEM at every interesting address, plus too-short frames.
    for addr in INTERESTING_ADDRS:
        value = addr.to_bytes(4, "little")
        seeds.append(_frame(CMD_READ_MEM, value))
    seeds.append(_frame(CMD_READ_MEM, b"\x00"))       # short frame, len<4
    seeds.append(_frame(CMD_READ_MEM, b"\x00\x00\x00"))

    # Unknown command type.
    seeds.append(_frame(0xEE, b"?"))

    # De-duplicate while preserving order.
    seen, out = set(), []
    for s in seeds:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def random_seed(rng: random.Random) -> bytes:
    """One freshly-synthesized seed, used to top up the corpus during a run."""
    t = rng.choice(ALL_TYPES)
    if t == CMD_READ_MEM and rng.random() < 0.7:
        addr = rng.choice(INTERESTING_ADDRS)
        return _frame(t, addr.to_bytes(4, "little"))
    n = rng.choice(INTERESTING_LENGTHS)
    fb = rng.choice(FILL_BYTES)
    return _frame(t, bytes([fb]) * n)
