#!/usr/bin/env bash
# Simulator stand-in for the camera: types the Windows clipboard (a payload copied from the
# issuer/verifier page) into the focused PrimeID field via the SDK's official sim driver.
# Run inside WSL while `foundation sim` is running and the "Enter payload" field is focused.
set -euo pipefail
payload=$(powershell.exe -NoProfile -Command Get-Clipboard | tr -d '\r')
[ -n "$payload" ] || { echo "Clipboard is empty: click Copy on the web page first." >&2; exit 1; }
cd ~/.foundation/sdk/current
# The sim debug channel stalls on long strings, so type in small chunks.
nix develop . -c bash -c 'for ((i=0; i<${#0}; i+=32)); do bin/foundation-passport-drive --sim input-text "${0:i:32}" >/dev/null; sleep 0.15; done' "$payload" 2>/dev/null
echo "Typed ${#payload} bytes into the simulator."
