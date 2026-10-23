#!/usr/bin/env bash
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0
#
# Install the deny-by-default network profiles for v0.6 tool containers.
#
# Two things are set up, and both are idempotent:
#   1. the pinned Docker bridge networks `trellis-tools-internal` (172.31.241.0/24)
#      and `trellis-tools-internet` (172.31.240.0/24), created with ICC disabled;
#   2. the `DOCKER-USER` rules that block cloud metadata, the engine's own subnets
#      and, for `internet`, every private range -- matched on those networks' CIDRs,
#      so they also cover gVisor (runsc) netstack traffic.
#
# The rules live in `core/execution/netprofiles.py`, which the runner also calls at
# startup. This script is only a thin root wrapper: it cannot drift from what the
# runner verifies.
#
# Run it as root on EVERY host that runs a runner (central and edge):
#   sudo scripts/setup-network-profiles.sh              # networks + rules
#   sudo scripts/setup-network-profiles.sh --all        # same as above (explicit)
#   sudo scripts/setup-network-profiles.sh --verify     # exit 1 if anything is missing
#   sudo scripts/setup-network-profiles.sh --teardown   # remove the rules (tests)
#   scripts/setup-network-profiles.sh --networks        # docker networks only (no root)
#
# `--verify` is the startup gate: run it after every host reboot / firewall reload,
# and from your provisioning tooling before `docker compose up -d`.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3 || command -v python || true)"
fi
if [[ -z "$PYTHON_BIN" ]]; then
  echo "error: no python3 on PATH and no .venv/bin/python in $REPO_ROOT" >&2
  exit 1
fi

usage() {
  cat <<'EOF'
Install the deny-by-default network profiles for v0.6 tool containers.

Usage: scripts/setup-network-profiles.sh [ACTION]

Actions:
  --install    (default) ensure the Docker networks, then install DOCKER-USER rules
  --all        same as --install (explicit form)
  --verify     exit non-zero when any rule is missing (startup gate)
  --teardown   remove the DOCKER-USER rules (Docker networks are left in place)
  --networks   create/verify the Docker networks only (no root needed)
  -h, --help   show this help

Rules and network definitions live in core/execution/netprofiles.py, which the
runner calls at startup, so this wrapper cannot drift from what it verifies.
EOF
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: $1 needs root (iptables DOCKER-USER chain); re-run with sudo." >&2
    exit 1
  fi
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not on PATH; the profile networks are created with it." >&2
    exit 1
  fi
}

ACTION="${1:---install}"
case "$ACTION" in
  -h|--help)
    usage
    exit 0
    ;;
  --install|--all)
    require_root "$ACTION"
    require_docker
    "$PYTHON_BIN" -m core.execution.netprofiles --networks
    "$PYTHON_BIN" -m core.execution.netprofiles --install
    echo "network profiles: networks ensured + DOCKER-USER rules installed (internal 172.31.241.0/24, internet 172.31.240.0/24)"
    ;;
  --verify)
    require_root "--verify"
    "$PYTHON_BIN" -m core.execution.netprofiles --verify
    echo "network profiles: all DOCKER-USER rules present"
    ;;
  --teardown)
    require_root "--teardown"
    "$PYTHON_BIN" -m core.execution.netprofiles --teardown
    echo "network profiles: DOCKER-USER rules removed (Docker networks left in place)"
    ;;
  --networks)
    require_docker
    "$PYTHON_BIN" -m core.execution.netprofiles --networks
    echo "network profiles: docker networks ensured"
    ;;
  *)
    echo "error: unknown action '$ACTION'" >&2
    usage >&2
    exit 2
    ;;
esac
