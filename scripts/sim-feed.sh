#!/usr/bin/env bash
# Test driver (run inside WSL): from PrimeID's home screen, feed one payload file through
# "Enter payload" exactly as a user would, then screenshot the result.
#   sim-feed.sh <payload.json> <out.png>
set -euo pipefail
file=$1 shot=$2
cd ~/.foundation/sdk/current
nix develop . -c bash -c '
  pd() { bin/foundation-passport-drive --sim "$@" >/dev/null; }
  pd tap 345 750; sleep 0.6          # Home -> Enter payload
  pd tap 240 300; sleep 0.4          # focus the text box
  # The sim debug channel stalls on long strings, so type in small chunks.
  data=$(cat "$0")
  for ((i=0; i<${#data}; i+=32)); do pd input-text "${data:i:32}"; sleep 0.15; done
  sleep 0.4
  pd tap 240 420; sleep 1.2          # Verify payload (sits above the keyboard)
  bin/foundation-passport-drive --sim screenshot -o "$1" >/dev/null
' "$file" "$shot" 2>&1 | grep -v "shell ready\|foundation doctor" || true
