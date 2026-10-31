#!/usr/bin/env bash
# Simulator stand-in for the camera: types a payload into the focused PrimeID "Enter payload"
# field via the SDK's official sim driver. Usage (inside WSL, field focused):
#   bash scripts/sim-send.sh .primeid-demo/credential.json     # or no argument = Windows clipboard
set -euo pipefail
if [ $# -ge 1 ]; then payload=$(tr -d '\r\n' < "$1"); else payload=$(powershell.exe -NoProfile -Command Get-Clipboard | tr -d '\r'); fi
[ -n "$payload" ] || { echo "Nothing to send." >&2; exit 1; }
# One driver process for the whole payload (each process takes a hosted-kernel slot), typed in
# small paced chunks because the sim GUI queue overflows on fast long input.
python3 -c '
import json, sys
d = sys.argv[1]
steps = []
for i in range(0, len(d), 32):
    steps += [{"input_text": d[i:i+32]}, {"wait": 350}]
json.dump(steps, open("/tmp/sim-send.json", "w"))' "$payload"
cd ~/.foundation/sdk/current
nix develop . -c bin/foundation-passport-drive --sim run /tmp/sim-send.json >/dev/null 2>&1
echo "Typed ${#payload} bytes into the simulator. Now tap Verify."
