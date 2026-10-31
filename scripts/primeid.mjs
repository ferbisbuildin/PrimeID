#!/usr/bin/env node
// PrimeID demo issuer + verifier (the laptop side of the 3-party flow in docs/idea.md).
// Same wire format as the device: secp256k1 compact sig over SHA-256(RFC 8785 canonical JSON).
// Every payload is written as .json (simulator paste) and .png (a real QR for the camera).
//
//   node scripts/primeid.mjs trust issuer|verifier     trust card for Prime
//   node scripts/primeid.mjs key <prime-key.png|hex>   read Prime's holder key QR (step 1)
//   node scripts/primeid.mjs issue [k=v ...]           credential bound to that key (step 2)
//   node scripts/primeid.mjs request [claim]           signed, nonce-bound request (step 4)
//   node scripts/primeid.mjs verify <answer.png|json>  check Prime's answer against the open request (step 7)
//   node scripts/primeid.mjs revoke <credential_id>    issuer-signed revocation list
//   node scripts/primeid.mjs attack forged|copied|fakebank
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from "@noble/hashes/utils";
import QRCode from "qrcode";
import jsQR from "jsqr";
import { PNG } from "pngjs";
import fs from "node:fs";
import path from "node:path";

const DIR = path.resolve(".primeid-demo");
const STATE = path.join(DIR, "state.json");
fs.mkdirSync(DIR, { recursive: true });

const canon = (o) =>
  Array.isArray(o) ? `[${o.map(canon).join(",")}]`
  : o && typeof o === "object" ? `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(",")}}`
  : JSON.stringify(o);
const digest = (o) => sha256(utf8ToBytes(canon(o)));
const sign = (o, priv) => secp256k1.sign(digest(o), hexToBytes(priv)).toCompactHex();
const verifySig = (o, sig, pub) => { try { return secp256k1.verify(hexToBytes(sig), digest(o), hexToBytes(pub)); } catch { return false; } };
const pubOf = (priv) => bytesToHex(secp256k1.getPublicKey(hexToBytes(priv), true));
const newKey = () => bytesToHex(secp256k1.utils.randomPrivateKey());
const claimHash = (d) => bytesToHex(sha256(utf8ToBytes(`${d.salt}:${d.key}:${d.value}`)));
const now = () => Math.floor(Date.now() / 1000);

// shortcut: demo issuer/verifier private keys live in a git-ignored local file; a real issuer uses an HSM.
const st = fs.existsSync(STATE) ? JSON.parse(fs.readFileSync(STATE, "utf8")) : {};
st.issuer ??= newKey();
st.verifier ??= newKey();
const save = () => fs.writeFileSync(STATE, JSON.stringify(st, null, 1), { mode: 0o600 });
save();

async function emit(name, payload) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload);
  fs.writeFileSync(path.join(DIR, `${name}.json`), text);
  await QRCode.toFile(path.join(DIR, `${name}.png`), text, { errorCorrectionLevel: "L", margin: 4, width: 900 });
  console.log(`  -> .primeid-demo/${name}.png  (QR, ${text.length} bytes)   .primeid-demo/${name}.json`);
}

function readQr(file) {
  if (!file.endsWith(".png")) return fs.readFileSync(file, "utf8").trim();
  const png = PNG.sync.read(fs.readFileSync(file));
  const code = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  if (!code) throw new Error(`no QR code found in ${file}`);
  return code.data.trim();
}

function credential(holder, claims, priv = st.issuer, name = "Demo Issuer (mock)") {
  const disclosures = Object.entries(claims).map(([key, value]) => ({ key, value: String(value), salt: bytesToHex(randomBytes(32)) }));
  const t = now();
  const body = { credential_id: "cred-" + bytesToHex(randomBytes(6)), issuer_name: name, issuer: pubOf(priv), holder, issued_at: t, expires: t + 30 * 86400, claims: disclosures.map(claimHash) };
  return { credential: { ...body, signature: sign(body, priv) }, disclosures };
}

function request(claim, priv = st.verifier, name = "Demo Verifier") {
  const t = now();
  const body = { request_id: "req-" + bytesToHex(randomBytes(4)), verifier_name: name, verifier_pubKey: pubOf(priv), requested_claim: claim, nonce: "0x" + bytesToHex(randomBytes(16)), expires: t + 600 };
  return { ...body, signature: sign(body, priv) };
}

const DEFAULT_CLAIMS = { over_18: "true", country: "IN", name: "Asha Rao" };
const [cmd, ...args] = process.argv.slice(2);
const needHolder = () => st.holder ?? (console.error("Run `key` first: Prime's holder key is unknown."), process.exit(1));

switch (cmd) {
  case "trust": {
    const role = args[0];
    if (role !== "issuer" && role !== "verifier") { console.error("trust issuer|verifier"); process.exit(1); }
    const name = role === "issuer" ? "Demo Issuer (mock)" : "Demo Verifier";
    console.log(`${role} trust card: ${name}, key ${pubOf(st[role])}`);
    await emit(`trust-${role}`, { primeid_trust: { name, pubkey: pubOf(st[role]), role } });
    break;
  }
  case "key": {
    const k = args[0].endsWith(".png") ? readQr(args[0]) : args[0];
    if (!/^0[23][0-9a-f]{64}$/i.test(k)) { console.error("not a compressed secp256k1 public key:", k); process.exit(1); }
    st.holder = k.toLowerCase();
    save();
    console.log("Prime holder key:", st.holder);
    break;
  }
  case "issue": {
    const claims = args.length ? Object.fromEntries(args.map((a) => a.split("="))) : DEFAULT_CLAIMS;
    const pkg = credential(needHolder(), claims);
    st.lastCredential = pkg.credential.credential_id;
    save();
    console.log(`credential ${pkg.credential.credential_id} bound to ${st.holder.slice(0, 12)}…, claims: ${Object.keys(claims).join(", ")}`);
    await emit("credential", pkg);
    break;
  }
  case "request": {
    const req = request(args[0] ?? "over_18");
    st.openRequest = req;
    save();
    console.log(`request ${req.request_id}: prove ${req.requested_claim}, nonce ${req.nonce}, expires in 600s`);
    await emit("request", req);
    break;
  }
  case "verify": {
    const a = JSON.parse(readQr(args[0]));
    const req = st.openRequest;
    if (!req) { console.error("No open request: run `request` first."); process.exit(1); }
    const { signature, ...credBody } = a.credential;
    const t = now();
    const checks = [
      ["1. Issuer signature", verifySig(credBody, signature, a.credential.issuer)],
      ["   Issuer is the one we trust", a.credential.issuer === pubOf(st.issuer)],
      ["2. Disclosed claim matches signed hash", a.credential.claims.includes(claimHash(a.disclosed_claim))],
      ["3. Holder binding (answer signed by bound key)", verifySig({ credential: a.credential, disclosed_claim: a.disclosed_claim, request_context: a.request_context }, a.holder_signature, a.credential.holder)],
      ["4. Nonce is this request's", a.request_context.nonce === req.nonce && a.request_context.verifier_pubKey === req.verifier_pubKey],
      ["   Not expired", t <= a.request_context.expires && t <= a.credential.expires],
      ["   Answers the claim we asked", a.disclosed_claim.key === req.requested_claim],
    ];
    for (const [n, ok] of checks) console.log(`${ok ? "PASS" : "FAIL"}  ${n}`);
    const ok = checks.every((c) => c[1]);
    // A valid proof of "over_18 = false" proves the person is NOT over 18: yes/no claims must be "true".
    const yesNo = ["true", "false"].includes(a.disclosed_claim.value);
    const accepted = ok && (!yesNo || a.disclosed_claim.value === "true");
    if (!ok) console.log("\nREJECTED: proof invalid");
    else if (!accepted) console.log(`\nPROOF VALID, BUT NOT ACCEPTED: ${a.disclosed_claim.key} = ${a.disclosed_claim.value}`);
    else console.log(`\nVERIFIED: ${a.disclosed_claim.key} = ${a.disclosed_claim.value}`);
    if (!accepted) process.exit(1);
    if (ok) { delete st.openRequest; save(); } // one-time nonce: a second presentation is a replay
    process.exit(ok ? 0 : 1);
  }
  case "revoke": {
    const id = args[0] ?? st.lastCredential;
    const body = { issuer: pubOf(st.issuer), revoked: [id], published_at: now() };
    console.log("revocation list revoking", id);
    await emit("revocation", { primeid_revocation: body, signature: sign(body, st.issuer) });
    break;
  }
  case "attack": {
    const kind = args[0];
    if (kind === "forged") {
      // "AI fake ID": looks like a credential, but signed by a key Prime never trusted.
      await emit("attack-forged", credential(needHolder(), DEFAULT_CLAIMS, newKey(), "Demo Issuer (mock)"));
    } else if (kind === "copied") {
      // A real credential, but bound to someone else's device key.
      await emit("attack-copied", credential(pubOf(newKey()), DEFAULT_CLAIMS));
    } else if (kind === "fakebank") {
      // Phisher signs with its own key and claims a bank's name.
      await emit("attack-fakebank", request("over_18", newKey(), "HDFC Bank"));
    } else {
      console.error("attack forged|copied|fakebank");
      process.exit(1);
    }
    break;
  }
  default:
    console.log(fs.readFileSync(new URL(import.meta.url), "utf8").split("\n").slice(1, 13).join("\n"));
}
