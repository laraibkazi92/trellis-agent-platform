"""Live probe tool: what is visible from inside a v0.6 tool container.

Reads one JSON object from stdin (``targets``: name -> ``ip:port`` to try), writes
a JSON report to stdout. Deliberately does not raise: a probe that crashes tells
us less than one that records the failure.
"""

import json
import os
import socket
import sys


def can_connect(spec: str, timeout: float = 2.0) -> str:
    host, _, port = spec.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout):
            return "connected"
    except Exception as exc:  # noqa: BLE001 - the point is to report it
        return f"{type(exc).__name__}: {exc}"


def read_file(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return f"read {len(handle.read())} bytes"
    except OSError as exc:
        return f"{type(exc).__name__}: {exc.strerror}"


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(2000)
    except OSError as exc:
        return f"{type(exc).__name__}: {exc.strerror}"


def write_file(path: str) -> str:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("escaped\n")
        return "wrote"
    except OSError as exc:
        return f"{type(exc).__name__}: {exc.strerror}"


def listing(path: str):
    try:
        return sorted(os.listdir(path))
    except OSError as exc:
        return f"{type(exc).__name__}: {exc.strerror}"


def main() -> None:
    try:
        args = json.load(sys.stdin)
    except ValueError:
        args = {}
    targets = args.get("targets") or {}

    workspace = "/app/workspace"
    suite_dir = os.path.dirname(os.path.abspath(__file__))
    output_root = os.path.join(workspace, "output")
    output_agents = []
    try:
        output_agents = sorted(os.listdir(output_root))
    except OSError:
        pass

    report = {
        "suite_dir": suite_dir,
        "uid_gid": [os.getuid(), os.getgid()],
        "cwd": os.getcwd(),
        "hostname": socket.gethostname(),
        "workspace_listing": listing(workspace),
        "tools_listing": listing(os.path.join(workspace, "tools")),
        "agents_listing": listing(os.path.join(workspace, "agents")),
        "suite_listing": listing(suite_dir),
        "output_agents": output_agents,
        "reads": {
            path: read_file(path)
            for path in (
                "/app/workspace/agents/demo-assistant/config.yaml",
                "/app/workspace/agents/demo-assistant/skills.md",
                "/app/workspace/tools/demo/tool.yaml",
                "/app/workspace/tools/demo/text_stats.py",
                "/app/workspace/shared",
                "/app/workspace/.env",
                "/app/.env",
            )
        },
        "writes": {
            "workspace": write_file(os.path.join(workspace, "pwned")),
            "tools_parent": write_file(os.path.join(workspace, "tools", "pwned")),
            "own_suite": write_file(os.path.join(suite_dir, "pwned")),
            "parent_of_suite": write_file(os.path.join(suite_dir, "..", "pwned")),
            "output": (
                write_file(os.path.join(output_root, output_agents[0], "pwned"))
                if output_agents
                else "no output mount"
            ),
            "tmp": write_file("/tmp/pwned"),
        },
        "resolv_conf": read_text("/etc/resolv.conf"),
        "env_keys": sorted(os.environ),
        "leaked_env": sorted(
            key
            for key in os.environ
            if any(
                marker in key.upper()
                for marker in ("TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL")
            )
        ),
        "network": {name: can_connect(value) for name, value in targets.items()},
        "dns": {},
    }
    for name in ("example.com", "etcd", "redis"):
        try:
            report["dns"][name] = socket.gethostbyname(name)
        except Exception as exc:  # noqa: BLE001
            report["dns"][name] = f"{type(exc).__name__}: {exc}"

    json.dump(report, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
