#!/usr/bin/env bash
# End-to-end test of PrimeID in the running KeyOS simulator (run inside WSL, app on its home screen).
# Drives the real app through the honest flow, the four attacks and revocation, using the demo CLI
# as issuer/verifier. Screenshots land in .primeid-demo/e2e/.
set -euo pipefail
ROOT=/mnt/c/Users/varda/documents/foundation
OUT=$ROOT/.primeid-demo/e2e
mkdir -p "$OUT"
cd "$ROOT"
cli() { node.exe scripts/primeid.mjs "$@"; }
J=.primeid-demo
run() { # one passport-drive process per call: the hosted kernel has few process slots
  python3 scripts/sim-script.py /tmp/e2e.json "$@" >/dev/null
  (cd ~/.foundation/sdk/current && nix develop . -c bin/foundation-passport-drive --sim run /tmp/e2e.json >/dev/null 2>&1)
}
pass=0; fail=0

echo "== 0. start clean: erase PrimeID data on the device"
run tap:120,530 tap:240,750 shot:$OUT/00-wipe.png tap:355,750 tap:240,750

echo "== 1. Prime's key QR -> issuer"
run tap:240,380 shot:$OUT/01-key.png tap:435,80
cli key "$(wslpath -w $OUT/01-key.png)" >/dev/null && echo "PASS  key read from Prime's on-screen QR" && pass=$((pass+1))

echo "== 2. trust issuer + verifier, import credential"
cli trust issuer >/dev/null; cli trust verifier >/dev/null; cli issue >/dev/null
run feed:$J/trust-issuer.json tap:355,750 tap:240,750 \
    feed:$J/trust-verifier.json tap:355,750 tap:240,750 \
    feed:$J/credential.json shot:$OUT/02-credential.png tap:240,750

echo "== 3. request -> approve -> answer QR -> verify"
cli request >/dev/null
run feed:$J/request.json shot:$OUT/03-review.png tap:345,750 wait:800 shot:$OUT/04-answer.png tap:435,80
if cli verify "$(wslpath -w $OUT/04-answer.png)"; then pass=$((pass+1)); else fail=$((fail+1)); fi

echo "== 4. attack: replayed answer (new request, old answer)"
cli request >/dev/null
if cli verify "$(wslpath -w $OUT/04-answer.png)" >/dev/null; then echo "FAIL  replay accepted"; fail=$((fail+1)); else echo "PASS  replay rejected (nonce)"; pass=$((pass+1)); fi

echo "== 5. attacks on Prime: forged, copied, fake bank (denied)"
cli attack forged >/dev/null; cli attack copied >/dev/null; cli attack fakebank >/dev/null
run feed:$J/attack-forged.json shot:$OUT/05-forged.png tap:240,750 \
    feed:$J/attack-copied.json shot:$OUT/06-copied.png tap:240,750 \
    feed:$J/attack-fakebank.json shot:$OUT/07-fakebank.png tap:120,750 wait:600 tap:240,750

echo "== 6. revocation"
cli revoke >/dev/null; cli request >/dev/null
run feed:$J/revocation.json shot:$OUT/08-revoked.png tap:240,750 \
    feed:$J/request.json shot:$OUT/09-after-revoke.png tap:240,750 \
    tap:360,530 shot:$OUT/10-receipts.png tap:435,80 tap:120,530 shot:$OUT/11-credentials.png tap:435,80

echo "== screens: $OUT  (inspect 02,03,05-09 for the expected messages)"
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
