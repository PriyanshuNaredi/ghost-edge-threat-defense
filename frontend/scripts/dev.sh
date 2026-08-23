#!/usr/bin/env bash
# Start the HUD dev server. Calls vite directly: the '&' in the parent folder
# name breaks `npm run` under cmd.exe on Windows.
set -e
cd "$(dirname "$0")/.."
exec node node_modules/vite/bin/vite.js "$@"
