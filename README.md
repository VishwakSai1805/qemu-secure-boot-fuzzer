# QEMU ARM Cortex-M3 Secure Bootloader & Coverage-Guided Mutation Fuzzer

A bare-metal secure boot chain for the ARM Cortex-M3 (`lm3s6965evb`, emulated
in QEMU) paired with a custom mutation fuzzer that drives the running target
over its own UART and automatically triages the crashes it finds.

Built end-to-end: linker scripts, startup/vector tables, a from-scratch C
SHA-256/HMAC implementation (no libc, no crypto library), an image signing
tool, a binary command parser with three realistic memory-safety bugs, a
fuzzer that mutates inputs against a live QEMU instance over a pty, and an
auto-generated vulnerability report — all exercised by 15 passing `pytest`
tests.

```
make && pytest -q --tb=short
```

## Why this project

Most "fuzzer" demos target a Linux userspace binary. This one targets a real
bare-metal boot chain: a signed firmware image, a Cortex-M3 exception model,
and a UART-based attack surface — the kind of target embedded security
engineers actually audit. The vulnerable firmware and the fuzzer that finds
its bugs are both written for this repository, and every crash in
`reports/vulnerability_report.md` is reproducible with one Python call.

## Architecture

```
┌─────────────────────────────── Flash (0x00000000) ───────────────────────────────┐
│                                                                                    │
│  ┌──────────────────────┐   ┌──────────────────┐   ┌─────────────────────────┐  │
│  │   Bootloader          │   │   App Header      │   │   App Payload           │  │
│  │   0x0000_0000         │   │   0x0000_4000      │   │   0x0000_4200           │  │
│  │   16 KiB               │   │   512 B           │   │   up to ~240 KiB        │  │
│  │                        │   │                    │   │                         │  │
│  │  Reset_Handler         │   │  magic "APP1"      │   │  vector table            │  │
│  │   └ copy .data         │   │  version           │   │  app_main()              │  │
│  │   └ zero .bss          │   │  payload_len        │   │   └ UART0 TLV parser     │  │
│  │   └ boot_main()        │   │  reserved           │   │        (3 intentional    │  │
│  │        │                │   │  mac[32] = HMAC-   │   │         vulnerabilities) │  │
│  │        ▼                │   │   SHA256(key,      │   │  HardFault_Handler       │  │
│  │  verify_image() ────────┼──▶│   header‖payload)  │◀──┼── reads this payload     │  │
│  │   └ check magic/len     │   └────────────────────┘   │   for its signature       │  │
│  │   └ HMAC-SHA256         │                             │                          │  │
│  │   └ constant-time cmp   │        MATCH ──────────────▶│  VTOR=0x4200, jump        │  │
│  │                          │        MISMATCH             │                          │  │
│  │   "[BOOT] PANIC:         │        └──────────▶ halt    │                          │  │
│  │    Invalid Signature"    │           (wfi loop,        │                          │  │
│  │                          │            fail-closed)      │                          │  │
│  └──────────────────────┘                                 └─────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘

      SRAM  0x2000_0000 .. 0x2000_FFFF (64 KiB)         UART0  0x4000_C000 (polled, no IRQ)
      stack grows down from 0x2001_0000                  DR +0x00 / FR +0x18 / CTL +0x30
```

### Boot sequence

```
 power-on
    │
    ▼
 Reset_Handler (bootloader)
    │  copy .data, zero .bss
    ▼
 boot_main()
    │
    ▼
 verify_image()
    │  magic == "APP1"?  len in range?  reserved == 0?
    │  HMAC-SHA256(dev_key, header[0:16] ‖ payload) == header.mac ?
    │
    ├── NO  ──▶ UART: "[BOOT] PANIC: Invalid Signature"  ──▶  wfi loop (halt, fail-closed)
    │
    └── YES ──▶ UART: "[BOOT] Signature OK, jumping to application"
                    │
                    ▼
                SCB->VTOR = 0x4200;  msr msp, vt[0];  bx vt[1]
                    │
                    ▼
                app_main()  ──▶  UART: "[APP] Ready"
                    │
                    ▼
                loop: read TLV frame [type:1][len:1][value] from UART0
                      └─▶ parser_handle_frame(type, len, value)
```

## Fuzzing architecture

```
 fuzzer/seeds.py                fuzzer/engine.py                  fuzzer/qemu_target.py
┌─────────────────┐            ┌─────────────────────┐           ┌───────────────────────┐
│ heuristic seed   │  corpus    │ mutate()              │  frame   │ QemuTarget.send_raw()   │
│ generator:       │──────────▶│  bit flips             │────────▶│  pty.openpty(), raw mode │
│  boundary lens    │            │  length lies           │           │  spawn:                 │
│  known addresses  │            │  address splicing      │           │   timeout 5s             │
│  type-byte fuzz   │            │  trunc/extend           │           │   qemu-system-arm        │
└─────────────────┘            └──────────┬──────────┘           │     -M lm3s6965evb      │
                                            │                       │     -nographic           │
                       keep if new          │ behavior              │     -kernel flash.bin    │
                       behavior signature   │ signature              └───────────┬─────────────┘
                       (UART transcript     ▼                                      │
                        + fault PC/LR    ┌─────────────────────┐                  │ UART transcript
                        hashed)          │ corpus (grows)        │◀─────────────────┘  + HardFault
                                          └─────────────────────┘                        register dump
                                                      │
                                                      │ on HardFault
                                                      ▼
                                          crashes/crash_NNNN_<sig>.bin   (raw TLV frame, replayable)
                                          crashes/crash_NNNN_<sig>.json  (registers + transcript)
                                                      │
                                                      ▼
                                      tools/triage_crash.py ──▶ reports/vulnerability_report.md
```

There's no real branch-coverage instrumentation on the Cortex-M3 binary, so
the engine uses an honest proxy signal instead: each run's UART transcript
plus any captured fault PC is hashed into a **behavior signature**, and an
input is kept in the corpus only when it produces a signature the engine
hasn't seen before. That's enough to reward inputs that reach new code paths
without needing a coverage-instrumented QEMU build.

## Memory map

| Region            | Address      | Size      | Notes                                     |
|--------------------|-------------|-----------|--------------------------------------------|
| Bootloader (FLASH)  | `0x00000000`| 16 KiB    | vector table, HMAC-SHA256 verify, jump      |
| App header (FLASH)  | `0x00004000`| 512 B     | magic/version/len/reserved/mac[32]          |
| App payload (FLASH) | `0x00004200`| ≤ ~240 KiB| app vector table + code (VTOR target)       |
| SRAM                | `0x20000000`| 64 KiB    | stack top `0x20010000`                      |
| UART0               | `0x4000C000`| —         | `DR` `+0x00`, `FR` `+0x18`, `CTL` `+0x30`    |

## Repository layout

```
bootloader/   secure bootloader: startup.c, main.c, bootloader.ld
app/          app firmware: startup.c, main.c, parser.{c,h}, fault.c, app.ld
common/       shared, dependency-free: sha256.{c,h}, uart.{c,h}, image.h
tools/        sign_image.py (build+sign flash image), triage_crash.py (crash → report)
fuzzer/       engine.py (mutation loop), seeds.py (seed generator), qemu_target.py (QEMU driver)
tests/        test_boot.py, test_fuzzer.py, test_triage.py
crashes/      saved crash reproducers (*.bin frame + *.json metadata)
reports/      vulnerability_report.md (auto-generated)
SPEC.md       architecture, memory map, test commands (detailed)
CLAUDE.md     project rules for AI-assisted development
```

## Build & test

```bash
sudo apt-get install -y gcc-arm-none-eabi gdb-multiarch qemu-system-arm \
                         python3-pytest python3-cryptography

make                    # bootloader.elf, app.elf, and the signed build/flash.bin
pytest -q --tb=short    # all 15 tests: boot, fuzzer, triage
```

QEMU is always invoked the same way, in tests, the fuzzer, and manual repro:

```bash
timeout 5s qemu-system-arm -M lm3s6965evb -nographic -monitor none \
    -serial stdio -kernel build/flash.bin
```

### Real test output

```
$ make
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -Os ... -T bootloader/bootloader.ld ... -o build/bootloader.elf
arm-none-eabi-objcopy -O binary build/bootloader.elf build/bootloader.bin
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -Os ... -T app/app.ld ... -o build/app.elf
arm-none-eabi-objcopy -O binary build/app.elf build/app.bin
python3 tools/sign_image.py --bootloader build/bootloader.bin --app build/app.bin -o build/flash.bin
wrote build/flash.bin: 18016 bytes, payload 1120 bytes

$ pytest -q --tb=short
...............                                                          [100%]
15 passed in 60.35s
```

```
$ arm-none-eabi-size build/bootloader.elf build/app.elf
   text    data     bss     dec     hex filename
   1668       0       0    1668     684 build/bootloader.elf
   1120       0       4    1124     464 build/app.elf
```

Signed boot, byte-exact:

```
$ timeout 5s qemu-system-arm -M lm3s6965evb -nographic -monitor none -serial stdio -kernel build/flash.bin
[BOOT] Verifying application image...
[BOOT] Signature OK, jumping to application
[APP] Ready
```

One bit flipped in the payload — fails closed:

```
[BOOT] Verifying application image...
[BOOT] PANIC: Invalid Signature
```
(QEMU then halts in a `wfi` loop until the 5s `timeout` kills it — this is
the intended fail-closed behavior, not a hang.)

## The vulnerable parser (Milestone 2)

`app/parser.c` implements a binary TLV command protocol over UART0 —
`[type:1][len:1][value: len bytes]` — with **three intentional,
documented vulnerabilities**, used as a fuzzing target:

| ID | Command | Bug | CWE |
|----|---------|-----|-----|
| VULN-1 | `CMD_ECHO` (`0x01`) | Stack buffer overflow — `len` (0–255) copied into a 16-byte stack buffer with no bound | CWE-121 |
| VULN-2 | `CMD_SET_OFFSET` (`0x02`) | Integer underflow — `len - 1` on `uint8_t` wraps to 255 when `len == 0` | CWE-191 |
| VULN-3 | `CMD_READ_MEM` (`0x03`) | Unauthenticated arbitrary memory read — attacker's 4-byte address is dereferenced directly, no allow-list | CWE-284 / CWE-125 |

Full root-cause analysis, impact, and fixes for each: see
[`reports/vulnerability_report.md`](reports/vulnerability_report.md),
regenerated from the saved crashes in `crashes/` by:

```bash
python3 -m fuzzer.engine --iterations 60     # mutate, boot QEMU, save crashes/
python3 tools/triage_crash.py                 # crashes/*.json -> reports/vulnerability_report.md
```

Example of what the fuzzer actually produced (`PC=0xaaaaaaaa` means the
return address was loaded straight out of attacker-controlled stack bytes):

```
[6/40] CRASH sig=6730ef01ed35c97a pc=0xaaaaaaaa -> crash_0001_6730ef01ed35c97a.bin
[8/40] CRASH sig=a000ee2473d1c60a pc=0x00000000 -> crash_0002_a000ee2473d1c60a.bin
[23/40] CRASH sig=9a4d8990db4e42c8 pc=0x80808080 -> crash_0003_9a4d8990db4e42c8.bin
{
  "iterations": 40,
  "executions": 40,
  "crashes": 3,
  "unique_behaviors": 16,
  "corpus_size": 249
}
```

Replay any saved crash directly:

```python
from fuzzer.qemu_target import QemuTarget
t = QemuTarget("build/flash.bin")
frame = open("crashes/crash_0001_6730ef01ed35c97a.bin", "rb").read()
print(t.send_raw(frame).output)
```

## What this demonstrates

- **Embedded security engineering**: a real Cortex-M boot chain (vector
  tables, `VTOR`, MSP/PC transfer), a from-scratch verified-boot
  implementation, and fail-closed behavior on tamper.
- **Applied cryptography**: SHA-256 and HMAC implemented directly from
  FIPS 180-4 / RFC 2104 with no external crypto dependency, cross-checked
  against Python's `hashlib`/`hmac` in CI.
- **Vulnerability research**: three distinct, realistic memory-safety bug
  classes (stack overflow, integer underflow, unauthenticated memory
  disclosure) with full root-cause writeups.
- **Fuzzing infrastructure**: a mutation engine that drives a live,
  interactive QEMU target over its own serial port (not a harness-only
  stub), with crash capture, deduplication by behavior signature, and
  automatic reporting — a small but complete fuzzing pipeline.

All vulnerable code is isolated to the `app/` training target, confined to
QEMU, and documented as intentional in `SPEC.md` and the vulnerability
report — standard practice for defensive security research and CTF-style
training material.
