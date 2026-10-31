# PrimeID demo runbook

PrimeID runs as a real KeyOS app (`primeid/`) in the Passport Prime simulator. The laptop plays the
**demo issuer** and **verifier** with `scripts/primeid.mjs` (the mock parties from `docs/idea.md`).
Every payload the CLI makes is real secp256k1-signed data, written as a QR image (`.png`) and as text (`.json`).

## Before the demo (once)

```bash
# WSL / Ubuntu: build and launch the app in the simulator (first build ~5 min)
bash /mnt/c/Users/varda/documents/foundation/scripts/sim.sh
```

On first launch KeyOS asks PrimeID's permission to use the secure-element app seed: approve it.
To start from an empty vault: Home → **Credentials** → **Erase all PrimeID data** → **Erase**.

Optional full rehearsal (drives the app itself and checks every outcome, ~3 min):
```bash
bash /mnt/c/Users/varda/documents/foundation/scripts/sim-e2e.sh
```

## Getting a QR into Prime

- **Camera (real QR):** needs the webcam passed into WSL (see "Webcam" below). On Prime tap **Scan QR**,
  then hold the `.png` (opened on your phone) up to the laptop camera.
- **Simulator without a camera:** on Prime tap **Enter payload**, tap the field, then in WSL run
  `bash scripts/sim-send.sh` after copying the `.json` text (`Get-Content .primeid-demo\credential.json | Set-Clipboard`).
  It runs exactly the same checks as a scan.

## The flow (Windows terminal in `C:\Users\varda\documents\foundation`)

| # | Laptop | Prime |
|---|--------|-------|
| 1 | `node scripts/primeid.mjs trust issuer` and `... trust verifier` | Load each trust card → **Trust** |
| 2 | Screenshot Prime's **My key QR** screen, then `node scripts/primeid.mjs key <screenshot.png>` | shows its holder key QR |
| 3 | `node scripts/primeid.mjs issue` | Load `credential` → "Credential stored · issuer signature valid · bound to this Prime" |
| 4 | `node scripts/primeid.mjs request` | Load `request` → green **Verified requester**, *shared: over_18 = true*, *stays: country, name* → **Approve** |
| 5 | Screenshot the answer QR, then `node scripts/primeid.mjs verify <screenshot.png>` | shows the signed answer QR |
| 6 | prints **VERIFIED: over_18 = true** with each check | Home → **Receipts** shows the entry |

## The four attacks

| Attack | Laptop | Result |
|--------|--------|--------|
| Forged "AI fake ID" | `attack forged`, load on Prime | Prime: *Issuer key is not in your trusted issuers* |
| Copied credential | `attack copied`, load on Prime | Prime: *Credential is bound to a different device key* |
| Replayed answer | `request` (new nonce), then `verify` the **old** answer screenshot | Verifier: nonce check FAILS |
| Fake bank | `attack fakebank`, load on Prime | Prime: red **Unknown requester · HDFC Bank** → Deny |

Bonus, revocation: `node scripts/primeid.mjs revoke`, load on Prime → *1 credential revoked*; a new `request` then gets *Cannot answer*.

## Webcam (real QR scanning in the simulator)

Admin PowerShell: `winget install --id dorssel.usbipd-win -e`, then `usbipd list`, `usbipd bind --busid <id>`,
`usbipd attach --wsl --busid <id>` for "Integrated Camera". In WSL: `sudo modprobe uvcvideo && sudo chmod 666 /dev/video0`.
Restart the simulator afterwards. `usbipd detach --busid <id>` gives the camera back to Windows.

## Honest limits to say out loud

- The issuer is a mock (`scripts/primeid.mjs`); every signature, hash and check is real.
- Simulator camera = the laptop webcam via WSL; without it, payloads go in through **Enter payload**.
- The holder key comes from KeyOS's per-app seed (`Security::app_seed`); in the simulator the security
  server is hosted, on hardware it is the secure element and needs the device unlocked.
- Issuer signature + bound key repeat across verifiers (linkable) until batch/BBS+ credentials (roadmap).
- Not built: e-passport NFC, x401 requests, zkSync anchoring, unlinkable batch credentials.
