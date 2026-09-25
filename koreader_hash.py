"""KOReader partialMD5 - Python port of koreader/frontend/util.lua partialMD5.

Twelve offsets, 1024-byte samples, MD5 over concatenation in offset order.
First offset is 0 (NOT 256) - LuaJIT's bit.lshift masks the shift count to
five bits so lshift(1024, -2) wraps to 0.

Verified against the seven golden vectors in
https://github.com/pid1/kosync-conformance/blob/main/vectors/vectors.json
(synthetic P(n) generator and sparse 1GiB case). See SPEC.md §8.
"""
import hashlib
from pathlib import Path

# [K-PUT-1] / [K-GET-1a] - route pattern only matches [A-Za-z0-9_]+, so the
# digest is always 32 lowercase hex characters in normal use.
OFFSETS = [
    0, 1024, 4096, 16384, 65536, 262144,
    1048576, 4194304, 16777216, 67108864, 268435456, 1073741824,
]
SAMPLE_SIZE = 1024


def partial_md5_bytes(data: bytes) -> str:
    """Compute KOReader's partialMD5 from an in-memory blob. Used for tests."""
    h = hashlib.md5()
    for off in OFFSETS:
        if off >= len(data):
            break
        chunk = data[off:off + SAMPLE_SIZE]
        h.update(chunk)
    return h.hexdigest()


def partial_md5(path: str | Path) -> str:
    """Compute KOReader's document hash from a file path. Returns 32-char lowercase hex."""
    p = Path(path)
    size = p.stat().st_size
    h = hashlib.md5()
    with p.open("rb") as f:
        for off in OFFSETS:
            if off >= size:
                break
            f.seek(off)
            chunk = f.read(SAMPLE_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ===== synthetic vector generator from vectors.json =====
# P(n)[i] = (i * 31 + (i >> 8)) mod 256
def _gen_pattern(n: int) -> bytes:
    return bytes(((i * 31 + (i >> 8)) & 0xff) for i in range(n))


def _self_test() -> bool:
    """Returns True iff every golden synthetic vector matches. Called at startup."""
    SYNTHETIC = [
        (500,     "21f0df72cce9bc7da8dae2512ee5feed"),
        (1024,    "f4cd1641040a17288bb6104d9e66bdb5"),
        (1025,    "170a888db01c00d8fc3e5d8d84de5838"),
        (2048,    "d0e59a0c7b893c3b8d6a9bddbd64e631"),
        (3000,    "d0e59a0c7b893c3b8d6a9bddbd64e631"),
        (200000,  "1784b150454ef4cf6780ceb94af0386f"),
        (1050000, "0fca5c751677ecbc2dcfe80ea75ace32"),
    ]
    for size, expected in SYNTHETIC:
        if partial_md5_bytes(_gen_pattern(size)) != expected:
            return False
    return True


_KOREADER_HASH_SELFTEST_OK = _self_test()
