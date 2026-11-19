"""Fuzzer regression tests: the three intentional parser vulnerabilities
must be reachable and reproducible, and the engine's crash plumbing must
work end-to-end. Kept short (few QEMU boots) since each boot takes ~4s
under `timeout 5s qemu-system-arm ... -nographic`.
"""
import json

from fuzzer.engine import mutate, run, save_crash, signature
from fuzzer.qemu_target import QemuTarget
from fuzzer.seeds import seed_corpus


def test_seed_corpus_nonempty():
    corpus = seed_corpus()
    assert len(corpus) > 20
    assert all(len(f) >= 2 for f in corpus)


def test_mutate_is_deterministic_per_seed():
    import random
    data = bytes([0x01, 10]) + b"A" * 10
    r1, r2 = random.Random(5), random.Random(5)
    assert mutate(data, r1) == mutate(data, r2)


def test_echo_overflow_crashes(build):
    target = QemuTarget(str(build / "flash.bin"), qemu_timeout_s=2.5)
    result = target.send_frame(0x01, b"A" * 48)  # CMD_ECHO, way past 16-byte buf
    assert result.crashed
    assert result.registers.get("PC") == 0x41414140 or \
           result.registers.get("LR") == 0x41414141


def test_read_mem_leaks_header_mac(build):
    """VULN-3 is a confidentiality bug, not (on this QEMU machine model,
    which reads unmapped memory as zero rather than bus-faulting) a crash:
    an unauthenticated UART client can read any mapped address, including
    the signed header's MAC bytes, with no permission check at all."""
    target = QemuTarget(str(build / "flash.bin"), qemu_timeout_s=2.5)
    header_mac_addr = 0x4000 + 16  # app_header_t.mac[0:4]
    result = target.send_frame(0x03, header_mac_addr.to_bytes(4, "little"))
    actual = (build / "flash.bin").read_bytes()[header_mac_addr:header_mac_addr + 4]
    assert actual.hex() in result.output.replace(" ", "").lower()


def test_set_offset_underflow_does_not_hang(build):
    target = QemuTarget(str(build / "flash.bin"), qemu_timeout_s=2.5)
    result = target.send_frame(0x02, b"")  # len=0 -> count underflows to 255
    assert not result.timed_out


def test_ping_is_safe(build):
    target = QemuTarget(str(build / "flash.bin"), qemu_timeout_s=2.5)
    result = target.send_frame(0x04, b"")
    assert not result.crashed
    assert "[APP] PONG" in result.output


def test_engine_short_run_saves_crash(build, tmp_path, monkeypatch):
    import fuzzer.engine as engine
    monkeypatch.setattr(engine, "CRASH_DIR", tmp_path)
    stats = engine.run(iterations=6, image=build / "flash.bin", seed=42,
                        qemu_timeout=2.5)
    assert stats["executions"] == 6
    assert stats["unique_behaviors"] >= 1
    if stats["crashes"]:
        saved = list(tmp_path.glob("crash_*.json"))
        assert saved
        meta = json.loads(saved[0].read_text())
        assert "registers" in meta and "frame_hex" in meta
