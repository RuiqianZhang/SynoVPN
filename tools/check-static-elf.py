#!/usr/bin/env python3
"""Accept static ELF64 including static PIE; reject a dynamic interpreter."""
import pathlib, struct, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
if raw[:6] != b"\x7fELF\x02\x01":
    raise SystemExit("Expected little-endian ELF64")
offset = struct.unpack_from("<Q", raw, 32)[0]
size, count = struct.unpack_from("<HH", raw, 54)
if any(struct.unpack_from("<I", raw, offset + i * size)[0] == 3 for i in range(count)):
    raise SystemExit("Dynamic ELF interpreter is not permitted")
print("Static ELF64 verified (static PIE accepted)")
