#!/usr/bin/env bash
# Build and run the Ghost gateway (default :8090, simulator ON).
set -e
cd "$(dirname "$0")/.."
go build -o ghost.exe .
exec ./ghost.exe "$@"
