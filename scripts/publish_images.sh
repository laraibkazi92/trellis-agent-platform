#!/usr/bin/env bash
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0
#
# Manually build and push the Trellis container images (publishing is manual
# by decision — there is no CI pipeline for this repo).
#
# Usage:
#   REGISTRY=ghcr.io/your-org [TAG=sha] [PLATFORMS=linux/amd64] ./scripts/publish_images.sh
#
# Environment variables:
#   REGISTRY   (required) target registry/namespace, e.g. ghcr.io/your-org
#   TAG        (optional) image tag; defaults to `git rev-parse --short HEAD`,
#              or "dev" when run outside a git repository
#   PLATFORMS  (optional) comma-separated docker buildx platforms
#              (default: linux/amd64)
#
# Images (names mirror docker-compose.yml):
#   trellis-agent-platform  root Dockerfile (host, hub, ui, mcp gateway,
#                           db-sync, taskiq services all share it)
#   trellis-gateway         nginx edge proxy built from gateway/ (compose
#                           builds it from ./gateway without an explicit
#                           repository name; this script pins one)

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: REGISTRY=<registry> [TAG=<tag>] [PLATFORMS=<platforms>] ./scripts/publish_images.sh

  REGISTRY   Required. Target registry/namespace, e.g. ghcr.io/your-org
  TAG        Optional. Image tag (default: short git SHA, or "dev" outside a repo)
  PLATFORMS  Optional. docker buildx platforms, comma-separated (default: linux/amd64)

Examples:
  REGISTRY=ghcr.io/your-org ./scripts/publish_images.sh
  REGISTRY=ghcr.io/your-org TAG=v2 PLATFORMS=linux/amd64,linux/arm64 ./scripts/publish_images.sh
EOF
}

REGISTRY="${REGISTRY:-}"
TAG="${TAG:-}"
PLATFORMS="${PLATFORMS:-linux/amd64}"

APP_IMAGE="trellis-agent-platform"
GATEWAY_IMAGE="trellis-gateway"

if [[ -z "$REGISTRY" ]]; then
    usage
    echo "error: REGISTRY is required" >&2
    exit 1
fi

if [[ -z "$TAG" ]]; then
    TAG="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Publishing Trellis images:"
echo "  registry:  ${REGISTRY}"
echo "  tag:       ${TAG}"
echo "  platforms: ${PLATFORMS}"
echo

echo "==> Building and pushing ${REGISTRY}/${APP_IMAGE}:${TAG} (root Dockerfile)"
docker buildx build \
    --platform "${PLATFORMS}" \
    --push \
    -f "${REPO_ROOT}/Dockerfile" \
    -t "${REGISTRY}/${APP_IMAGE}:${TAG}" \
    "${REPO_ROOT}"

echo "==> Building and pushing ${REGISTRY}/${GATEWAY_IMAGE}:${TAG} (gateway/)"
docker buildx build \
    --platform "${PLATFORMS}" \
    --push \
    -t "${REGISTRY}/${GATEWAY_IMAGE}:${TAG}" \
    "${REPO_ROOT}/gateway"

echo
echo "Done. Pushed:"
echo "  ${REGISTRY}/${APP_IMAGE}:${TAG}"
echo "  ${REGISTRY}/${GATEWAY_IMAGE}:${TAG}"
