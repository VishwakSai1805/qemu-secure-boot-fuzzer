# CLAUDE.md

Bare-metal Cortex-M3 secure bootloader + mutation fuzzer, run under QEMU
(`lm3s6965evb`). See `SPEC.md` for architecture and memory map.

## Rules
- Never read compiled artifacts (`build/`, `*.elf`, `*.bin`, `*.o`) into context.
- Always wrap QEMU: `timeout 5s qemu-system-arm -M lm3s6965evb -nographic ...`.
- The app's parser vulnerabilities are intentional training targets; do not "fix" them
  without updating `SPEC.md`, the fuzzer tests and the report.

## Layout
`bootloader/` `app/` `common/` (uart, sha256, image.h) `tools/` `fuzzer/` `tests/` `crashes/` `reports/`

## Commands
`make` | `pytest -q --tb=short` | `python3 -m fuzzer.engine` | `python3 tools/triage_crash.py`
