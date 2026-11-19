#!/usr/bin/env python3
"""Sign an application payload and assemble the full flash image.

Flash layout (lm3s6965evb): bootloader @0x0000, header @0x4000, payload @0x4200.
MAC = HMAC-SHA256(key, header[0:16] || payload), verified by the bootloader.
"""
import argparse, hashlib, hmac, struct, sys

MAGIC = 0x31505041
HEADER_ADDR, PAYLOAD_ADDR, FLASH_SIZE = 0x4000, 0x4200, 0x40000
DEV_KEY = bytes([0x51,0x45,0x4d,0x55,0x2d,0x4d,0x33,0x2d,0x44,0x45,0x56,0x2d,0x4b,0x45,0x59,0x21])


def build_header(payload: bytes, key: bytes = DEV_KEY, version: int = 1) -> bytes:
    head = struct.pack("<IIII", MAGIC, version, len(payload), 0)
    mac = hmac.new(key, head + payload, hashlib.sha256).digest()
    return (head + mac).ljust(PAYLOAD_ADDR - HEADER_ADDR, b"\xff")


def build_flash(bootloader: bytes, payload: bytes, key: bytes = DEV_KEY) -> bytes:
    if len(bootloader) > HEADER_ADDR:
        raise ValueError("bootloader exceeds 16 KiB region")
    if PAYLOAD_ADDR + len(payload) > FLASH_SIZE:
        raise ValueError("payload too large")
    img = bootloader.ljust(HEADER_ADDR, b"\xff") + build_header(payload, key) + payload
    return img


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bootloader", required=True)
    ap.add_argument("--app", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--key-hex", default=DEV_KEY.hex())
    a = ap.parse_args()
    with open(a.bootloader, "rb") as f: bl = f.read()
    with open(a.app, "rb") as f: app = f.read()
    img = build_flash(bl, app, bytes.fromhex(a.key_hex))
    with open(a.output, "wb") as f: f.write(img)
    print(f"wrote {a.output}: {len(img)} bytes, payload {len(app)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
