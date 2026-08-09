#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/deploy/bin"
mkdir -p "$OUT_DIR"

cd "$ROOT/third_party/fscan"

echo "==> building darwin/arm64"
go build -trimpath -ldflags="-s -w" -o "$OUT_DIR/aion-fscan-darwin-arm64" ./cmd/aion-bridge

echo "==> building linux/amd64"
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o "$OUT_DIR/aion-fscan-linux-amd64" ./cmd/aion-bridge

echo "==> done"
ls -lh "$OUT_DIR"/aion-fscan-*
