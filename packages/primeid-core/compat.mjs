// Cross-checks primeid-core (Rust) against the noble-based wire format used by the web suite.
//   node packages/primeid-core/compat.mjs gen            -> writes tests/fixtures.json
//   node packages/primeid-core/compat.mjs verify <file>  -> runs the verifier's 4 checks on a Rust answer
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from "@noble/hashes/utils";
import fs from "node:fs";
import path from "node:path";

const dir = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1"));
const canon = (o) =>
  Array.isArray(o) ? `[${o.map(canon).join(",")}]`
  : o && typeof o === "object" ? `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(",")}}`
  : JSON.stringify(o);
const sign = (o, priv) => secp256k1.sign(sha256(utf8ToBytes(canon(o))), priv).toCompactHex();
const verify = (o, sig, pub) => { try { return secp256k1.verify(hexToBytes(sig), sha256(utf8ToBytes(canon(o))), hexToBytes(pub)); } catch { return false; } };
const pubOf = (priv) => bytesToHex(secp256k1.getPublicKey(priv, true));
const claimHash = (d) => bytesToHex(sha256(utf8ToBytes(`${d.salt}:${d.key}:${d.value}`)));

// Holder key for test seed [7u8; 32], same derivation as primeid_core::holder_key.
const holderPriv = sha256(concatBytes(utf8ToBytes("primeid/holder/v1"), new Uint8Array(32).fill(7)));
const holderPub = pubOf(holderPriv);
const issuerPriv = sha256(utf8ToBytes("demo issuer"));
const verifierPriv = sha256(utf8ToBytes("demo verifier"));
const FAR = 4102444800; // 2100-01-01

function issue(holder, priv = issuerPriv) {
  const disclosures = [["over_18", "true"], ["country", "IN"], ["name", "Asha Rao"]].map(([key, value], i) => ({ key, value, salt: bytesToHex(sha256(utf8ToBytes("salt" + i))) }));
  const body = { credential_id: "cred-1", issuer_name: "Demo Issuer", issuer: pubOf(issuerPriv), holder, issued_at: 1700000000, expires: FAR, claims: disclosures.map(claimHash) };
  return { credential: { ...body, signature: sign(body, priv) }, disclosures };
}
const reqBody = { request_id: "req-1", verifier_name: "Demo Verifier", verifier_pubKey: pubOf(verifierPriv), requested_claim: "over_18", nonce: "0xabcdef0123456789", expires: FAR };

if (process.argv[2] === "gen") {
  const out = {
    holder_pub: holderPub,
    valid: issue(holderPub),
    forged: issue(holderPub, sha256(utf8ToBytes("attacker"))),
    other_holder: issue(pubOf(sha256(utf8ToBytes("someone else")))),
    request: { ...reqBody, signature: sign(reqBody, verifierPriv) },
    tampered_request: { ...reqBody, requested_claim: "name", signature: sign(reqBody, verifierPriv) },
    revocation: (() => { const b = { issuer: pubOf(issuerPriv), revoked: ["cred-1"], published_at: 1700000100 }; return { primeid_revocation: b, signature: sign(b, issuerPriv) }; })(),
    revocation_forged: (() => { const b = { issuer: pubOf(issuerPriv), revoked: ["cred-1"], published_at: 1700000100 }; return { primeid_revocation: b, signature: sign(b, sha256(utf8ToBytes("attacker"))) }; })(),
  };
  fs.writeFileSync(path.join(dir, "tests", "fixtures.json"), JSON.stringify(out, null, 1));
  console.log("fixtures written, holder", holderPub);
} else if (process.argv[2] === "demo") {
  // Real payloads for driving the simulator: node compat.mjs demo <prime-holder-pubkey> <outdir>
  const [holder, out] = process.argv.slice(3);
  const now = Math.floor(Date.now() / 1000);
  const mk = (h, priv = issuerPriv) => {
    const p = issue(h, priv);
    const body = { ...p.credential, issued_at: now, expires: now + 30 * 86400, credential_id: "cred-" + now };
    delete body.signature;
    p.credential = { ...body, signature: sign(body, priv) };
    return p;
  };
  const req = (name, priv) => {
    const b = { request_id: "req-" + now, verifier_name: name, verifier_pubKey: pubOf(priv), requested_claim: "over_18", nonce: "0x" + bytesToHex(secp256k1.utils.randomPrivateKey()).slice(0, 32), expires: now + 600 };
    return { ...b, signature: sign(b, priv) };
  };
  const files = {
    "1-trust-issuer": { primeid_trust: { name: "Demo Issuer", pubkey: pubOf(issuerPriv), role: "issuer" } },
    "2-trust-verifier": { primeid_trust: { name: "Demo Verifier", pubkey: pubOf(verifierPriv), role: "verifier" } },
    "3-credential": mk(holder),
    "4-request": req("Demo Verifier", verifierPriv),
    "a1-untrusted-issuer": (() => { const p = issue(holder, sha256(utf8ToBytes("rogue"))); p.credential.issuer = pubOf(sha256(utf8ToBytes("rogue"))); const { signature, ...b } = p.credential; p.credential.signature = sign(b, sha256(utf8ToBytes("rogue"))); return p; })(),
    "a1-tampered-claim": (() => { const p = mk(holder); p.disclosures[0].value = "false"; return p; })(),
    "a2-other-holder": mk(pubOf(sha256(utf8ToBytes("someone else")))),
    "a4-fake-bank": req("HDFC Bank", sha256(utf8ToBytes("phisher"))),
  };
  fs.mkdirSync(out, { recursive: true });
  for (const [n, v] of Object.entries(files)) fs.writeFileSync(path.join(out, n + ".json"), JSON.stringify(v));
  console.log("wrote", Object.keys(files).join(" "));
} else if (process.argv[2] === "verify") {
  // verify <answer.json|answer-screenshot.png> [request.json]
  let raw = fs.readFileSync(process.argv[3]);
  if (process.argv[3].endsWith(".png")) {
    const { PNG } = await import("pngjs");
    const jsQR = (await import("jsqr")).default;
    const png = PNG.sync.read(raw);
    const code = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
    if (!code) { console.log("no QR found"); process.exit(1); }
    raw = code.data;
    console.log("decoded QR:", raw.length, "bytes");
  }
  const a = JSON.parse(raw.toString());
  const expected = process.argv[4] ? JSON.parse(fs.readFileSync(process.argv[4], "utf8")) : reqBody;
  const { signature, ...credBody } = a.credential;
  const checks = {
    issuer: verify(credBody, signature, a.credential.issuer),
    disclosure: a.credential.claims.includes(claimHash(a.disclosed_claim)),
    holder: verify({ credential: a.credential, disclosed_claim: a.disclosed_claim, request_context: a.request_context }, a.holder_signature, a.credential.holder),
    nonce: a.request_context.nonce === expected.nonce && a.request_context.verifier_pubKey === expected.verifier_pubKey,
    unexpired: Math.floor(Date.now() / 1000) <= a.request_context.expires && Math.floor(Date.now() / 1000) <= a.credential.expires,
    only_one_claim: Object.keys(a.disclosed_claim).sort().join() === "key,salt,value" && a.disclosed_claim.key === "over_18",
  };
  console.log(checks);
  process.exit(Object.values(checks).every(Boolean) ? 0 : 1);
}
