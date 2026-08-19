#!/bin/sh
# Cross-compiles the real bas-agent binary for Windows and Linux from a
# single Go source tree -- unlike a PyInstaller-based agent, this genuinely
# produces both native binaries from one host (no Wine/CI required).
set -e
cd "$(dirname "$0")"
mkdir -p dist

echo "Building Linux (amd64) binary..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/bas-agent-linux .

echo "Building Windows (amd64) binary..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/bas-agent-windows.exe .

echo "Building macOS (arm64) binary (dev/smoke-test use, not an official download target)..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o dist/bas-agent-darwin-arm64 .

echo "Done:"
ls -la dist/
