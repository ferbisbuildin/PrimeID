# PrimeID: prove the fact, keep the document

PrimeID turns Foundation's **Passport Prime** into a personal credential vault. An issuer signs your
credential once. It lives encrypted on your Prime. When a venue asks "is this person over 18?", Prime
shows you who is asking and what will be shared. You approve on the device, and only that one fact
leaves it, signed by your Prime and good for that one request.

```
Issuer (web)            Passport Prime (KeyOS app)            Verifier (web)
  scan holder key  <---  Show my holder key (QR)
  sign offer (QR)  --->  verify, trust issuer, store (AES-GCM vault)
                                                     <---   signed request (QR), fresh nonce
                         review requester + claim, Approve
                         signed answer (QR)          --->   7 checks, nonce burned
                                                            revocation read from ZKsync
```

## What is in this repo

| Path | What it is |
| --- | --- |
| `crates/primeid-core` | Rust protocol core used on the device: canonical JSON, secp256k1 signatures, salted claim hashes, holder and vault keys from the KeyOS app seed, AES-256-GCM vault. |
| `keyos-app` | The KeyOS app (Rust + Slint ui2) built with the Foundation SDK. |
| `packages/core-crypto` | TypeScript issuer and verifier halves of the same protocol, plus the ZKsync registry client. |
| `packages/web-suite` | Issuer, Verifier and Attack Lab web app (Vite + React). |
| `contracts` | `PrimeIdRevocationRegistry.sol` for ZKsync. See [contracts/README.md](contracts/README.md). |

## Security model

- **Holder key.** Derived on Prime from `GetAppSeed`, a per-app seed from the secure element:
  HMAC-SHA256(seed, `primeid/holder-key/v1` || counter). Only the public key ever leaves the device.
- **Credential.** Each claim is hashed as sha256(salt:key:value) with its own random salt. The issuer
  signs the sorted hash list together with the holder key, so the credential only works for that Prime.
- **Vault.** On Prime, credentials, trusted issuers and receipts are sealed with AES-256-GCM under a
  key derived from the same seed. A fresh nonce is used on every write. The vault lives in the app's
  encrypted AppData. A vault that fails to decrypt is refused and never overwritten.
- **Issuer trust.** The first time Prime sees an issuer, it shows the issuer's key fingerprint and asks
  you to confirm it. It warns if a different key uses a name you already trust.
- **Requester identity.** A request shows a green "Verified requester" badge only if it carries a
  certificate from an issuer this Prime trusts, and that certificate matches the request's key and name.
  Otherwise the badge is red and the name is marked unconfirmed.
- **Answer.** It reveals one claim and its salt, is bound to the request digest, the verifier key and
  the nonce, and is signed by the holder key. Prime will not sign the same nonce twice.
- **Verifier checks.** Format, issuer signature and trust, expiry, revocation (when configured; fails
  closed if the registry cannot be reached), holder binding, the disclosed claim hash, and replay/relay.
- **Web keys.** Issuer and verifier signing keys are stored only as PBKDF2 (600k) + AES-GCM ciphertext
  in localStorage. They are decrypted into memory per tab and are never sent anywhere. localStorage
  holds nothing else secret: public keys, the verifier certificate, used nonces, and credential ids
  without values.

## Run it

### Tests (host)

```bash
npm install
npm test                                  # TS protocol + attacks + registry (writes Rust test vectors)
cd crates/primeid-core && cargo test      # Rust protocol, attacks, vault, cross-language vectors
```

### Web suite

```bash
cp .env.example .env.local                # optional: set VITE_PRIMEID_REGISTRY to enable revocation
npm run dev                               # http://localhost:3000
npm run build                             # tsc + production bundle in dist/
```

Camera and screen capture need a secure context, which `localhost` counts as.
To use a phone or another machine, serve over HTTPS.

### KeyOS app (Foundation SDK)

Needs the Foundation SDK (`foundation doctor` should pass). On Windows the SDK runs in WSL2.

```bash
cd keyos-app
foundation preview     # UI check; generates .foundation-sdk/current
foundation sim         # hosted KeyOS runtime
foundation build       # signed artifacts for a real Passport Prime
```

`app-id` in `keyos-app/app-config.toml` is the domain separation input for `GetAppSeed`.
Never change it: a new id means a new holder key, and every stored credential stops working.

## Demo script (about 4 minutes)

1. **Issuer tab.** Create the issuer key ("Demo ID Authority"). Click "Trust in this browser's verifier".
2. **Prime.** Open PrimeID and allow the app-seed prompt on first use. Tap **Show my holder key**.
3. **Issuer.** Click "Scan with camera" (or "Scan a window" for the simulator). Check that the
   fingerprint matches the Prime screen. Fill in the claims and click **Sign credential**.
4. **Prime.** Tap **Scan QR** and point it at the offer. Prime shows "New issuer" and the issuer
   fingerprint. Tap **Trust issuer and save**.
5. **Verifier tab.** Create the verifier key ("Club Entry") and copy its public key. In the Issuer tab,
   use **Certify a verifier**, then **Install in this browser's verifier**.
   Back in Verifier, create a request for `over_18`.
6. **Prime.** Scan the request. It shows a green *Verified requester*, *Will share: over_18 = true*, and
   the other claims under *Stays on Prime*. Tap **Approve and sign**.
7. **Verifier.** Scan the answer QR. It shows ACCEPTED with all checks passed.
8. **Attack Lab.** Run the attacks on that real answer: replay, re-signed answer, edited value and forged
   issuer signature are each stopped, and the panel shows which check stopped each one.
9. *(If the registry is deployed)* In the Issuer tab, **Revoke** the credential (your wallet pays gas).
   A new request and answer now fail at the *Revocation* step.

## Environment variables

All public (`VITE_*` values are bundled into the page). See `.env.example`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `VITE_PRIMEID_REGISTRY` | empty | Deployed registry address. When empty, revocation is off and shown as SKIP. |
| `VITE_ZKSYNC_RPC_URL` | `https://sepolia.era.zksync.dev` | RPC endpoint used for `eth_call` and receipts. |
| `VITE_ZKSYNC_CHAIN_ID` | `300` | ZKsync Sepolia. |
| `VITE_ZKSYNC_EXPLORER` | `https://sepolia.explorer.zksync.io` | Used for transaction links. |

## Status and limitations

| Item | Status |
| --- | --- |
| Rust protocol core (`cargo test`, 8 tests) | implemented + tested |
| TS protocol, attacks, registry client (`npm test`, 12 tests) | implemented + tested |
| Rust/TS byte compatibility (shared vectors) | implemented + tested |
| Web suite type-check and production build | implemented + tested (build only; UI not exercised end to end) |
| KeyOS app | implemented, **not built**: it has not been compiled with the Foundation SDK or run on the simulator or a device |
| Registry contract | implemented; compiles with solc 0.8.24; **not deployed, not tested on chain** |
| Revocation from the web UI | implemented, not tested (needs a deployed registry and a funded wallet) |

Known limits:

- The KeyOS app uses only APIs found in the KeyOS source (`GetAppSeed`, `FileBacked`, the system QR
  scanner, the file picker, `qrcode::render`). Its first SDK build may still need small fixes.
- One QR per payload. Large credentials (many long claims) can exceed what one QR holds. Prime refuses
  rather than truncating, and the web side offers `.json` files for USB import.
- Issuer trust is trust-on-first-use, confirmed by fingerprint. There is no issuer directory.
- Revocation is permanent and checked by the verifier, not by Prime (Prime is offline by design).
- A verifier's outstanding requests live in tab memory, so reloading the page invalidates them.
- This is not a zero-knowledge proof system. Privacy comes from selective disclosure of salted hashes.
  ZKsync is used for a public revocation registry, not for proofs.
