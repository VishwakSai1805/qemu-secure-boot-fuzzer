#!/usr/bin/env python3
"""Triage saved fuzzer crashes and generate reports/vulnerability_report.md.

Reads every `crashes/crash_*.json` produced by `fuzzer.engine`, classifies
each by the command type that triggered it and by fault signature (bad PC,
bad LR, invalid instruction, etc.), deduplicates by behavior signature, and
writes a single markdown report summarizing findings with reproduction
steps.

Usage:
    python3 tools/triage_crash.py
    python3 tools/triage_crash.py --crashes-dir crashes --out reports/vulnerability_report.md
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CMD_NAMES = {
    0x01: "CMD_ECHO",
    0x02: "CMD_SET_OFFSET",
    0x03: "CMD_READ_MEM",
    0x04: "CMD_PING",
}

KNOWN_VULNS = {
    0x01: {
        "id": "VULN-1",
        "title": "Stack buffer overflow in CMD_ECHO",
        "cwe": "CWE-121: Stack-based Buffer Overflow",
        "location": "app/parser.c: echo_cmd()",
        "root_cause": (
            "`echo_cmd` copies the attacker-supplied `len` bytes (0-255) "
            "into a fixed 16-byte stack buffer `uint8_t buf[16]` with no "
            "bounds check, overwriting adjacent stack contents including "
            "the saved return address."
        ),
        "impact": (
            "An attacker who controls UART0 input can corrupt the return "
            "address and redirect execution (observed: PC/LR loaded "
            "directly from attacker-controlled bytes), a classic path to "
            "remote code execution on a bare-metal target with no DEP/ASLR/"
            "stack canaries."
        ),
        "fix": (
            "Clamp `len` to `sizeof(buf) - 1` before copying (or reject "
            "frames with len > 16), and compile with `-fstack-protector-"
            "all` plus a Cortex-M MPU stack guard region."
        ),
    },
    0x02: {
        "id": "VULN-2",
        "title": "Integer underflow in CMD_SET_OFFSET",
        "cwe": "CWE-191: Integer Underflow (Wrap or Wraparound)",
        "location": "app/parser.c: set_offset_cmd()",
        "root_cause": (
            "`count = (uint8_t)(len - 1)` is computed without first "
            "checking `len >= 1`. When `len == 0` this wraps to 255, "
            "producing a loop bound far larger than the actual (empty) "
            "value buffer and reading out of bounds."
        ),
        "impact": (
            "Out-of-bounds read of stack/adjacent memory feeding into "
            "`stage[]`; on this target it corrupts a local array without "
            "crashing, but on a different stack layout the same underflow "
            "can read attacker-inaccessible memory into attacker-visible "
            "state or write past the stage buffer."
        ),
        "fix": (
            "Reject `len == 0` for this command explicitly, or compute the "
            "count as a signed/range-checked value: "
            "`uint16_t count = len ? len - 1 : 0;`."
        ),
    },
    0x03: {
        "id": "VULN-3",
        "title": "Unauthenticated arbitrary memory read in CMD_READ_MEM",
        "cwe": "CWE-284: Improper Access Control / CWE-125: Out-of-Bounds Read",
        "location": "app/parser.c: read_mem_cmd()",
        "root_cause": (
            "The 32-bit address is taken directly from the attacker's TLV "
            "frame with no allow-list, range check, or authentication, and "
            "4 bytes at that address are echoed back over UART0."
        ),
        "impact": (
            "Confidentiality break: any party who can reach UART0 can dump "
            "arbitrary mapped memory, including the signed image header's "
            "MAC and any secrets resident in flash or SRAM, with no "
            "protocol-level authorization. (On this QEMU machine model, "
            "unmapped addresses read back as zero rather than bus-faulting, "
            "so this behaves as a pure information-disclosure bug here "
            "rather than a crash — real silicon with an active bus-fault "
            "region would also HardFault on invalid addresses.)"
        ),
        "fix": (
            "Remove this command from any production build, or restrict it "
            "to a signed allow-list of addresses behind an authenticated "
            "debug-unlock flow."
        ),
    },
}


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_crashes(crash_dir: Path) -> list[dict]:
    crashes = []
    for meta_path in sorted(crash_dir.glob("crash_*.json")):
        try:
            meta = json.loads(meta_path.read_text())
        except json.JSONDecodeError:
            continue
        meta["_path"] = _rel(meta_path)
        meta["_bin_path"] = _rel(meta_path.with_suffix(".bin"))
        crashes.append(meta)
    return crashes


def classify(crash: dict) -> int | None:
    """Best-effort mapping from a saved crash back to the command type that
    produced it (the raw frame's first byte)."""
    t = crash.get("type_byte")
    if t in KNOWN_VULNS:
        return t
    return None


def group_by_signature(crashes: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for c in crashes:
        groups[c.get("signature", "unknown")].append(c)
    return groups


def render_report(crashes: list[dict]) -> str:
    groups = group_by_signature(crashes)
    by_cmd: dict[int, list[dict]] = defaultdict(list)
    unclassified = []
    for sig, items in groups.items():
        rep = items[0]
        cmd = classify(rep)
        if cmd is not None:
            by_cmd[cmd].append(rep)
        else:
            unclassified.append(rep)

    lines = [
        "# Vulnerability Report",
        "",
        "Auto-generated by `tools/triage_crash.py` from saved fuzzer crash "
        f"reproducers. **{len(crashes)}** crash sample(s) across "
        f"**{len(groups)}** unique behavior signature(s).",
        "",
        "> Target: ARM Cortex-M3 (`lm3s6965evb`) running the app firmware "
        "in `app/`. All vulnerabilities are intentional training targets "
        "introduced in Milestone 2 (see `SPEC.md`). Confined to QEMU.",
        "",
        "## Summary",
        "",
        "| ID | Title | Severity | CWE |",
        "|----|-------|----------|-----|",
    ]
    severity = {0x01: "Critical", 0x02: "Medium", 0x03: "High"}
    for cmd, info in sorted(KNOWN_VULNS.items()):
        found = "✅ found by fuzzer" if by_cmd.get(cmd) else "not triggered this run"
        lines.append(
            f"| {info['id']} | {info['title']} | {severity.get(cmd, '?')} "
            f"| {info['cwe'].split(':')[0]} | "
        )
    lines[-len(KNOWN_VULNS):] = [l.rstrip(" |") + " |" for l in lines[-len(KNOWN_VULNS):]]

    lines += ["", "## Findings", ""]
    for cmd, info in sorted(KNOWN_VULNS.items()):
        samples = by_cmd.get(cmd, [])
        lines += [
            f"### {info['id']}: {info['title']}",
            "",
            f"- **Command**: `{CMD_NAMES.get(cmd, hex(cmd))}` (type byte `{hex(cmd)}`)",
            f"- **Location**: `{info['location']}`",
            f"- **CWE**: {info['cwe']}",
            f"- **Root cause**: {info['root_cause']}",
            f"- **Impact**: {info['impact']}",
            f"- **Fix**: {info['fix']}",
            f"- **Fuzzer samples this run**: {len(samples)}",
        ]
        for s in samples[:3]:
            regs = s.get("registers", {})
            pc = regs.get("PC")
            lr = regs.get("LR")
            frame_hex = s.get("frame_hex", "")
            if len(frame_hex) > 64:
                frame_hex = frame_hex[:64] + f"...({len(frame_hex)//2} bytes)"
            lines.append(
                f"  - `{s['_bin_path']}` — frame `{frame_hex}`"
                + (f", PC=`{pc:#010x}`" if pc is not None else "")
                + (f", LR=`{lr:#010x}`" if lr is not None else "")
            )
        lines.append("")

    if unclassified:
        lines += ["## Other crashes (unclassified)", ""]
        for s in unclassified[:10]:
            lines.append(f"- `{s['_bin_path']}` — signature `{s.get('signature')}`, "
                          f"frame `{s.get('frame_hex', '')}`")
        lines.append("")

    lines += [
        "## Reproduction",
        "",
        "Each crash's `.bin` file is the raw TLV frame (`[type][len][value...]`) "
        "that triggered it. Replay any of them directly against the target:",
        "",
        "```python",
        "from fuzzer.qemu_target import QemuTarget",
        "t = QemuTarget('build/flash.bin')",
        "frame = open('crashes/<crash_file>.bin', 'rb').read()",
        "result = t.send_raw(frame)",
        "print(result.output)",
        "```",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--crashes-dir", default=str(ROOT / "crashes"))
    ap.add_argument("--out", default=str(ROOT / "reports" / "vulnerability_report.md"))
    args = ap.parse_args()

    crash_dir = Path(args.crashes_dir)
    crashes = load_crashes(crash_dir)
    report = render_report(crashes)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    print(f"wrote {out_path} ({len(crashes)} crash samples, "
          f"{len(group_by_signature(crashes))} unique signatures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
