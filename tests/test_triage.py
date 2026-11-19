"""tools/triage_crash.py: unit tests against synthetic crash metadata (no
QEMU boot needed, so this runs fast)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.triage_crash import load_crashes, render_report  # noqa: E402


def _write_crash(d: Path, idx: int, type_byte: int, pc=None, lr=None):
    frame = bytes([type_byte, 2, 0xAA, 0xBB])
    meta = {
        "signature": f"sig{idx}",
        "frame_hex": frame.hex(),
        "type_byte": type_byte,
        "len_byte": 2,
        "registers": {k: v for k, v in (("PC", pc), ("LR", lr)) if v is not None},
        "output": "[FAULT] HardFault\n",
    }
    (d / f"crash_{idx:04d}_sig{idx}.bin").write_bytes(frame)
    (d / f"crash_{idx:04d}_sig{idx}.json").write_text(json.dumps(meta))


def test_load_crashes_reads_all_metadata(tmp_path):
    _write_crash(tmp_path, 1, 0x01, pc=0x41414141)
    _write_crash(tmp_path, 2, 0x03)
    crashes = load_crashes(tmp_path)
    assert len(crashes) == 2
    assert {c["type_byte"] for c in crashes} == {0x01, 0x03}


def test_render_report_covers_all_three_vulns(tmp_path):
    _write_crash(tmp_path, 1, 0x01, pc=0x41414141, lr=0x41414141)
    _write_crash(tmp_path, 2, 0x02)
    _write_crash(tmp_path, 3, 0x03)
    crashes = load_crashes(tmp_path)
    report = render_report(crashes)
    assert "VULN-1" in report and "Stack buffer overflow" in report
    assert "VULN-2" in report and "Integer underflow" in report
    assert "VULN-3" in report and "arbitrary memory read" in report
    assert "0x41414141" in report


def test_render_report_handles_empty_crashes():
    report = render_report([])
    assert "0** crash sample" in report
    assert "VULN-1" in report  # known vulns always listed, even with 0 samples
