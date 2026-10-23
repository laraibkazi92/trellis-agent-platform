"""Echo stdin back with the identity the container actually runs as.

Proves the workspace tool protocol (JSON in on stdin, JSON out on stdout) still
works unchanged under gVisor, and shows whether caller-declared env arrived.
"""

import json
import os
import sys

try:
    args = json.load(sys.stdin)
except ValueError:
    args = {}

json.dump(
    {
        "echo": args,
        "uid_gid": [os.getuid(), os.getgid()],
        "cwd": os.getcwd(),
        "env": {
            key: os.environ[key]
            for key in sorted(os.environ)
            if key.startswith(("TRELLIS_", "PROBE_"))
        },
    },
    sys.stdout,
)
sys.stdout.write("\n")
