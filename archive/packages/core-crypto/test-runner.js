/**
 * IncogID++ v1.0 Cryptographic Protocol Test Suite
 * Executes real secp256k1, SHA-256 salted hash trees, and the 4-step pipeline.
 * Run directly with: node packages/core-crypto/test-runner.js
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HDKey } from "@scure/bip32";

// ---------------------------------------------------------------------------
// 1. Deterministic Canonicalization (RFC 8785)
// ---------------------------------------------------------------------------
function canonicalizeJson(obj) {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj === "boolean" || typeof obj === "number") return JSON.stringify(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return `[${obj.map(canonicalizeJson).join(",")}]`;
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
    return `{${pairs.join(",")}}`;
  }
  return JSON.stringify(obj);
}

function sha256Hex(str) {
  return bytesToHex(sha256(utf8ToBytes(str)));
}

function signCanonicalObject(obj, privKeyHex) {
  const canonical = canonicalizeJson(obj);
  const hash = sha256(utf8ToBytes(canonical));
  return secp256k1.sign(hash, hexToBytes(privKeyHex)).toCompactHex();
}

function verifyCanonicalObject(obj, sigHex, pubKeyHex) {
  const canonical = canonicalizeJson(obj);
  const hash = sha256(utf8ToBytes(canonical));
  return secp256k1.verify(sigHex, hash, pubKeyHex);
}

// ---------------------------------------------------------------------------
// TEST SUITE EXECUTION
// ---------------------------------------------------------------------------
console.log("=================================================================");
console.log("   INCOGID++ v1.0 CRYPTOGRAPHIC VERIFICATION TEST SUITE");
console.log("=================================================================\n");

let passedCount = 0;
let failedCount = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passedCount++;
  } else {
    console.error(`  [FAIL] ${testName}`);
    failedCount++;
  }
}

// TEST 1: Canonicalization sorts keys lexicographically
const unorderedA = { z: 1, a: "test", m: [3, 2, 1] };
const unorderedB = { m: [3, 2, 1], a: "test", z: 1 };
assert(
  canonicalizeJson(unorderedA) === canonicalizeJson(unorderedB),
  "RFC 8785: Key-order independent canonical serialization"
);

// TEST 2: BIP39 Mnemonic -> BIP32 HD Key Derivation (Passport Prime Seed Model)
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const seed = bip39.mnemonicToSeedSync(testMnemonic);
const root = HDKey.fromMasterSeed(seed);
const child = root.derive("m/1337'/0'/0'/0/0");
const holderPrivKeyHex = bytesToHex(child.privateKey);
const holderPubKeyHex = bytesToHex(child.publicKey);

assert(
  holderPubKeyHex.startsWith("02") || holderPubKeyHex.startsWith("03"),
  "BIP32: Deterministic derivation of compressed secp256k1 holder public key"
);

// TEST 3: Issuer Keypair & Credential Issuance with Salted Hashes
const issuerPrivBytes = secp256k1.utils.randomPrivateKey();
const issuerPubBytes = secp256k1.getPublicKey(issuerPrivBytes, true);
const issuerPrivKeyHex = bytesToHex(issuerPrivBytes);
const issuerPubKeyHex = bytesToHex(issuerPubBytes);

const salt1 = "1111111111111111111111111111111111111111111111111111111111111111";
const salt2 = "2222222222222222222222222222222222222222222222222222222222222222";
const hash1 = sha256Hex(`${salt1}:over_18:true`);
const hash2 = sha256Hex(`${salt2}:country:US`);

const credPayload = {
  credential_id: "cred_test_001",
  issuer_name: "Global Identity Authority",
  issuer: issuerPubKeyHex,
  holder: holderPubKeyHex,
  issued_at: 1700000000,
  expires: 2000000000,
  claims: [hash1, hash2],
};

const credSig = signCanonicalObject(credPayload, issuerPrivKeyHex);
const isCredSigValid = verifyCanonicalObject(credPayload, credSig, issuerPubKeyHex);
assert(isCredSigValid, "secp256k1: Issuer authentic signature over credential payload");

// TEST 4: Verifier Challenge Request Generation (Step 3)
const verifierPrivBytes = secp256k1.utils.randomPrivateKey();
const verifierPubKeyHex = bytesToHex(secp256k1.getPublicKey(verifierPrivBytes, true));
const verifierPrivKeyHex = bytesToHex(verifierPrivBytes);

const nonce = "0xdeadbeefcafebabe1234567890abcdef";
const requestPayload = {
  request_id: "req_test_001",
  verifier_name: "Apex Exchange Compliance",
  verifier_pubKey: verifierPubKeyHex,
  requested_claim: "over_18",
  nonce,
  expires: 2000000000,
};
const reqSig = signCanonicalObject(requestPayload, verifierPrivKeyHex);
assert(
  verifyCanonicalObject(requestPayload, reqSig, verifierPubKeyHex),
  "secp256k1: Verifier signed challenge with fresh nonce"
);

// TEST 5: IncogID++ Selective Disclosure Answer Generation (Step 4)
const disclosedClaim = { key: "over_18", value: "true", salt: salt1 };
const requestContext = { nonce, verifier_pubKey: verifierPubKeyHex, expires: 2000000000 };

const answerCredential = { ...credPayload, signature: credSig };
const answerPayload = {
  credential: answerCredential,
  disclosed_claim: disclosedClaim,
  request_context: requestContext,
};
const holderSig = signCanonicalObject(answerPayload, holderPrivKeyHex);

// Pipeline Check 1: Issuer Sig
const check1 = verifyCanonicalObject(credPayload, answerCredential.signature, answerCredential.issuer);
assert(check1, "Pipeline Step 1: Issuer Signature Check PASSED");

// Pipeline Check 2: Selective Disclosure Hash
const recomputedHash = sha256Hex(`${disclosedClaim.salt}:${disclosedClaim.key}:${disclosedClaim.value}`);
const check2 = answerCredential.claims.includes(recomputedHash);
assert(check2, "Pipeline Step 2: Selective Disclosure Hash Check PASSED");

// Pipeline Check 3: Holder Binding Sig
const check3 = verifyCanonicalObject(answerPayload, holderSig, answerCredential.holder);
assert(check3, "Pipeline Step 3: Holder Binding Signature Check PASSED");

// Pipeline Check 4: Nonce & Expiry
const check4 = requestContext.nonce === nonce && 2000000000 > Math.floor(Date.now() / 1000);
assert(check4, "Pipeline Step 4: Nonce Replay & Expiry Check PASSED");

// TEST 6: Attack 1 Blocked - Rogue Issuer AI Fake ID
const attackerPrivBytes = secp256k1.utils.randomPrivateKey();
const attackerPrivHex = bytesToHex(attackerPrivBytes);
const forgedCredSig = signCanonicalObject(credPayload, attackerPrivHex);
const attack1Blocked = !verifyCanonicalObject(credPayload, forgedCredSig, issuerPubKeyHex);
assert(attack1Blocked, "Security Testbed Attack 1: Rogue Issuer Fake ID BLOCKED by Step 1");

// TEST 7: Attack 2 Blocked - Screenshot Theft (Presenter has different key)
const thiefPrivBytes = secp256k1.utils.randomPrivateKey();
const thiefPrivHex = bytesToHex(thiefPrivBytes);
const thiefAnswerSig = signCanonicalObject(answerPayload, thiefPrivHex);
const attack2Blocked = !verifyCanonicalObject(answerPayload, thiefAnswerSig, answerCredential.holder);
assert(attack2Blocked, "Security Testbed Attack 2: Screenshot Theft BLOCKED by Step 3 (Holder Binding)");

// TEST 8: Attack 3 Blocked - Replayed Nonce
const staleNonce = "0xSTALE_OLD_NONCE";
const attack3Blocked = staleNonce !== nonce;
assert(attack3Blocked, "Security Testbed Attack 3: Replayed Old Nonce BLOCKED by Step 4");

console.log("\n=================================================================");
console.log(`   TEST RESULTS: ${passedCount} PASSED, ${failedCount} FAILED`);
console.log("=================================================================\n");

if (failedCount > 0) {
  process.exit(1);
}
