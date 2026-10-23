"""Sleep for a caller-chosen time (holds a container slot during another call)."""

import json
import sys
import time

try:
    args = json.load(sys.stdin)
except ValueError:
    args = {}

seconds = max(0.0, min(30.0, float(args.get("seconds", 1))))
time.sleep(seconds)
json.dump({"slept": seconds}, sys.stdout)
sys.stdout.write("\n")
