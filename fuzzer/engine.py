#!/usr/bin/env python3
"""Coverage-guided-by-proxy mutation fuzzer for the app's TLV command parser.

True branch coverage isn't available without instrumenting the Cortex-M
binary, so this engine uses a cheap, honest proxy signal instead: each run's
UART transcript + crash registers are hashed into a "behavior signature"
(see `signature()`), and an input is kept in the corpus only when it
produces output the engine hasn't seen before. That rewards inputs that
reach new code paths without requiring real coverage instrumentation.

Usage:
    python3 -m fuzzer.engine --iterations 300
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path

from fuzzer.qemu_target import QemuTarget
from fuzzer.seeds import random_seed, seed_corpus

ROOT = Path(__file__).resolve().parent.parent
CRASH_DIR = ROOT / "crashes"


def signature(result) -> str:
    """Collapse a run to a short behavior fingerprint: crash state + the
    first fault PC (if any) + which [APP]/[FAULT] lines appeared, ignoring
    the specific data bytes that were echoed back."""
    lines = [l.split(":", 1)[0].split("@")[0].strip()
             for l in result.output.splitlines()
             if l.startswith("[APP]") or l.startswith("[FAULT]") or l.startswith("[BOOT]")]
    pc = result.registers.get("PC")
    key = "|".join(lines) + f"|pc={pc:08x}" if pc is not None else "|".join(lines)
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def mutate(data: bytes, rng: random.Random) -> bytes:
    """Apply one or more cheap byte-level mutations to a TLV frame."""
    if len(data) < 2:
        return data
    b = bytearray(data)
    choice = rng.random()

    if choice < 0.25:
        # Bit flip at a random position.
        i = rng.randrange(len(b))
        b[i] ^= 1 << rng.randrange(8)
    elif choice < 0.45:
        # Lie about the length byte relative to the actual value size.
        b[1] = rng.randrange(256)
    elif choice < 0.65:
        # Splice in an interesting constant word (address-like or all-1s/0s).
        i = rng.randrange(max(1, len(b) - 3))
        word = rng.choice([0x00000000, 0xFFFFFFFF, 0x20000000, 0x40000000,
                            0xE000ED00, 0x41414141])
        for j, byte in enumerate(word.to_bytes(4, "little")):
            if i + j < len(b):
                b[i + j] = byte
    elif choice < 0.85:
        # Truncate or extend the value payload.
        if rng.random() < 0.5 and len(b) > 3:
            b = b[:rng.randrange(2, len(b))]
        else:
            b.extend(rng.randrange(256) for _ in range(rng.randrange(1, 32)))
        b[1] = min(len(b) - 2, 255) if len(b) > 2 else 0
    else:
        # Randomize the command type byte.
        b[0] = rng.randrange(256)

    return bytes(b)


def save_crash(frame: bytes, result, sig: str, idx: int) -> Path:
    CRASH_DIR.mkdir(exist_ok=True)
    raw_path = CRASH_DIR / f"crash_{idx:04d}_{sig}.bin"
    meta_path = CRASH_DIR / f"crash_{idx:04d}_{sig}.json"
    raw_path.write_bytes(frame)
    meta = {
        "signature": sig,
        "frame_hex": frame.hex(),
        "type_byte": frame[0] if frame else None,
        "len_byte": frame[1] if len(frame) > 1 else None,
        "registers": result.registers,
        "output": result.output,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    return raw_path


def run(iterations: int, image: Path, seed: int, qemu_timeout: float) -> dict:
    rng = random.Random(seed)
    target = QemuTarget(str(image), qemu_timeout_s=qemu_timeout)

    corpus = seed_corpus()
    seen_sigs: set[str] = set()
    crashes: list[dict] = []
    stats = {"iterations": 0, "executions": 0, "crashes": 0,
              "unique_behaviors": 0, "corpus_size": len(corpus)}

    for i in range(iterations):
        if rng.random() < 0.15 or not corpus:
            frame = random_seed(rng)
        else:
            base = rng.choice(corpus)
            frame = mutate(base, rng)
            if rng.random() < 0.2:
                frame = mutate(frame, rng)

        result = target.send_raw(frame)
        stats["executions"] += 1
        sig = signature(result)

        if sig not in seen_sigs:
            seen_sigs.add(sig)
            corpus.append(frame)
            stats["corpus_size"] = len(corpus)

        if result.crashed:
            stats["crashes"] += 1
            path = save_crash(frame, result, sig, stats["crashes"])
            crashes.append({"path": str(path), "signature": sig,
                             "pc": result.registers.get("PC")})
            print(f"[{i+1}/{iterations}] CRASH sig={sig} "
                  f"pc={result.registers.get('PC', 0):#010x} -> {path.name}")
        elif (i + 1) % 10 == 0:
            print(f"[{i+1}/{iterations}] execs={stats['executions']} "
                  f"corpus={stats['corpus_size']} crashes={stats['crashes']}")

        stats["iterations"] = i + 1

    stats["unique_behaviors"] = len(seen_sigs)
    stats["crash_list"] = crashes
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", default=str(ROOT / "build" / "flash.bin"))
    ap.add_argument("--iterations", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--qemu-timeout", type=float, default=3.0)
    args = ap.parse_args()

    if not Path(args.image).exists():
        print(f"error: {args.image} not found; run `make` first")
        return 1

    t0 = time.time()
    stats = run(args.iterations, Path(args.image), args.seed, args.qemu_timeout)
    stats["elapsed_s"] = round(time.time() - t0, 1)
    print(json.dumps({k: v for k, v in stats.items() if k != "crash_list"},
                      indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
