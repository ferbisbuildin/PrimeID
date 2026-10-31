#!/usr/bin/env bash
# Build PrimeID and launch it in the KeyOS simulator (run inside WSL).
# WSLg's Wayland surface crashes the sim's display server, so force X11.
set -euo pipefail
pkill -f "lib/keyos/simulator" 2>/dev/null || true; pkill -f foundation-simulator 2>/dev/null || true; sleep 1
unset WAYLAND_DISPLAY
cd ~/.foundation/sdk/current
exec nix develop . -c bash -c "unset WAYLAND_DISPLAY; export FOUNDATION_SDK_ROOT=$PWD PATH=$PWD/bin:\$PATH CARGO_BUILD_JOBS=3; cd /mnt/c/Users/varda/documents/foundation/primeid && foundation sim"
