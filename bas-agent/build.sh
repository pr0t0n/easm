#!/bin/sh
# Cross-compiles the real bas-agent binary for Windows and Linux (amd64 +
# arm64) from a single Go source tree -- unlike a PyInstaller-based agent,
# this genuinely produces native binaries from one host (no Wine/CI
# required).
#
# Both Linux architectures are official download targets: an amd64-only
# binary silently segfaults deep in the Go runtime (epoll syscall handling)
# when run under binfmt/QEMU x86 emulation on an arm64 host -- e.g. any Kali
# VM under VirtualBox on Apple Silicon, which can only run arm64 guests.
set -e
cd "$(dirname "$0")"
mkdir -p dist

echo "Building Linux (amd64) binary..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/bas-agent-linux-amd64 .

echo "Building Linux (arm64) binary..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/bas-agent-linux-arm64 .

echo "Building Windows (amd64) binary..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/bas-agent-windows.exe .

echo "Building macOS (arm64) binary (dev/smoke-test use, not an official download target)..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o dist/bas-agent-darwin-arm64 .

echo "Done:"
ls -la dist/
