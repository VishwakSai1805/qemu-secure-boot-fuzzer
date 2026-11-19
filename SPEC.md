# SPEC: QEMU Cortex-M3 Secure Bootloader & Coverage-Guided Fuzzer

## Target
QEMU `lm3s6965evb` (ARM Cortex-M3). Everything runs inside the emulator; the
vulnerable application is a **deliberately flawed training target**.

## Memory map
| Region            | Address      | Size   | Notes                                   |
|-------------------|--------------|--------|-----------------------------------------|
| Bootloader        | `0x00000000` | 16 KiB | vector table, HMAC-SHA256 verify, jump  |
| App header        | `0x00004000` | 512 B  | magic, version, length, MAC             |
| App payload       | `0x00004200` | <=240K | vector table first (VTOR target)        |
| SRAM              | `0x20000000` | 64 KiB | stack top `0x20010000`                  |
| UART0             | `0x4000C000` | -      | DR `+0x00`, FR `+0x18`, CTL `+0x30`     |

## Boot flow
1. Reset -> bootloader copies `.data`, zeroes `.bss`, inits UART0.
2. Validates header (magic, length bound, reserved==0).
3. Computes `HMAC-SHA256(key, header[0:16] || payload)` with the standalone C
   implementation in `common/sha256.c`; constant-time compare to header MAC.
4. Mismatch: prints `[BOOT] PANIC: Invalid Signature`, halts in `wfi` (fail closed).
5. Match: sets `VTOR=0x4200`, loads MSP/PC from the app vector table, app prints `[APP] Ready`.

## Image format (`common/image.h`, `tools/sign_image.py`)
`magic "APP1" | version | payload_len | reserved | mac[32] | 0xFF padding to 512 B`.
The dev key is public and for demonstration only.

## Milestone 2: App command parser and fuzzer
TLV frames over UART0 (`type:1 | len:1 | value`), with three intentional,
documented flaws (stack overflow, integer underflow, unauthenticated memory read).
`fuzzer/engine.py` mutates inputs, drives QEMU over pipes, captures HardFault
register dumps and stores reproducers in `crashes/`.

## Milestone 3: Triage and reporting
`tools/triage_crash.py` classifies saved crashes and writes `reports/vulnerability_report.md`.

## Test commands
```
make                       # build bootloader, app, signed build/flash.bin
pytest -q --tb=short       # all tests
pytest -q tests/test_boot.py
```
QEMU is always run as `timeout 5s qemu-system-arm -M lm3s6965evb -nographic ...`.
