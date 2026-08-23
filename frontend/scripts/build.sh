#!/usr/bin/env bash
# Type-check and production-build the HUD (tsc + vite invoked directly).
set -e
cd "$(dirname "$0")/.."
node node_modules/typescript/bin/tsc -b
exec node node_modules/vite/bin/vite.js build
