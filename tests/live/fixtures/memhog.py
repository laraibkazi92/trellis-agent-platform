"""Memory probe: try to allocate well past the container's cgroup limit."""

import json
import sys

blocks = []
try:
    for _ in range(64):
        blocks.append(bytearray(16 * 1024 * 1024))
        blocks[-1][0] = 1
except MemoryError:
    json.dump({"result": "MemoryError", "allocated_mb": len(blocks) * 16}, sys.stdout)
    sys.stdout.write("\n")
    raise SystemExit(0)

json.dump({"result": "allocated", "allocated_mb": len(blocks) * 16}, sys.stdout)
sys.stdout.write("\n")
