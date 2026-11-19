"""Secure-boot tests: always run QEMU under `timeout 5s ... -nographic`."""
import subprocess

PAYLOAD_OFFSET = 0x4200


def run_qemu(image_path, seconds=3):
    cmd = ["timeout", "5s", "qemu-system-arm", "-M", "lm3s6965evb",
           "-nographic", "-monitor", "none", "-serial", "stdio",
           "-kernel", str(image_path)]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        out = p.stdout
    except subprocess.TimeoutExpired as e:  # pragma: no cover
        out = e.stdout or b""
    return out.decode("latin-1").replace("\r", "")


def test_valid_image_boots(build):
    out = run_qemu(build / "flash.bin")
    assert "[BOOT] Signature OK" in out
    assert "[APP] Ready" in out
    assert "PANIC" not in out


def test_tampered_payload_halts(build, tmp_path):
    img = bytearray((build / "flash.bin").read_bytes())
    img[PAYLOAD_OFFSET + 0x60] ^= 0x01          # flip one bit in the payload
    bad = tmp_path / "tampered.bin"
    bad.write_bytes(img)
    out = run_qemu(bad)
    assert "[BOOT] PANIC: Invalid Signature" in out
    assert "[APP] Ready" not in out


def test_tampered_header_halts(build, tmp_path):
    img = bytearray((build / "flash.bin").read_bytes())
    img[0x4000 + 16] ^= 0x80                    # flip a bit in the MAC
    bad = tmp_path / "badmac.bin"
    bad.write_bytes(img)
    out = run_qemu(bad)
    assert "[BOOT] PANIC: Invalid Signature" in out
    assert "[APP] Ready" not in out


def test_blank_app_region_halts(build, tmp_path):
    img = (build / "flash.bin").read_bytes()[:0x4000]
    bad = tmp_path / "noapp.bin"
    bad.write_bytes(img)
    out = run_qemu(bad)
    assert "PANIC: Invalid Signature" in out


def test_sha256_matches_hashlib():
    import hashlib, hmac, sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
    import sign_image
    payload = b"x" * 100
    hdr = sign_image.build_header(payload)
    assert hdr[16:48] == hmac.new(sign_image.DEV_KEY, hdr[:16] + payload, hashlib.sha256).digest()
