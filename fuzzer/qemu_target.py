"""Drives one QEMU `lm3s6965evb` instance over a pty-backed serial port and
sends it raw TLV frames, the way `tests/test_boot.py` drives boot images but
interactive and long-lived for fuzzing.

Always launched as `timeout <N>s qemu-system-arm ... -nographic`, matching
the project rule in CLAUDE.md.
"""
from __future__ import annotations

import os
import pty
import re
import select
import subprocess
import time
import tty
from dataclasses import dataclass, field

FAULT_RE = re.compile(r"\[FAULT\] (\w+)=([0-9a-fA-F]+)")


@dataclass
class RunResult:
    output: str
    crashed: bool
    registers: dict = field(default_factory=dict)
    timed_out: bool = False


class QemuTarget:
    """One-shot QEMU session: boot the signed image, send a single TLV
    frame, collect output until the app halts, faults, or times out."""

    def __init__(self, image_path: str, qemu_timeout_s: float = 3.0,
                 boot_settle_s: float = 0.8, machine: str = "lm3s6965evb"):
        self.image_path = image_path
        self.qemu_timeout_s = qemu_timeout_s
        self.boot_settle_s = boot_settle_s
        self.machine = machine

    def send_frame(self, type_byte: int, value: bytes) -> RunResult:
        frame = bytes([type_byte & 0xFF, len(value) & 0xFF]) + value
        return self.send_raw(frame)

    def send_raw(self, frame: bytes) -> RunResult:
        master, slave = pty.openpty()
        # Full raw mode on both ends: disables ICANON/ECHO (no line buffering
        # or echo of our binary TLV frames) *and* ISIG/IXON, which otherwise
        # swallow bytes like 0x03 (INTR) and 0x11/0x13 (XON/XOFF) as control
        # characters instead of forwarding them as data to QEMU's UART.
        for fd in (master, slave):
            tty.setraw(fd)
        timeout_s = int(self.qemu_timeout_s) + 2
        cmd = [
            "timeout", f"{timeout_s}s", "qemu-system-arm",
            "-M", self.machine, "-nographic", "-monitor", "none",
            "-serial", "stdio", "-kernel", self.image_path,
        ]
        proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                 close_fds=True)
        os.close(slave)
        out = b""
        try:
            time.sleep(self.boot_settle_s)
            os.write(master, frame)
            deadline = time.time() + self.qemu_timeout_s
            while time.time() < deadline:
                r, _, _ = select.select([master], [], [], 0.2)
                if r:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out += chunk
                    if b"[FAULT] HALT" in out:
                        break
                if proc.poll() is not None:
                    break
        finally:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            os.close(master)

        text = out.decode("latin-1", "replace").replace("\r", "")
        crashed = "[FAULT] HardFault" in text
        regs = {k: int(v, 16) for k, v in FAULT_RE.findall(text)}
        timed_out = "[APP] Ready" not in text and not crashed
        return RunResult(output=text, crashed=crashed, registers=regs,
                          timed_out=timed_out)
