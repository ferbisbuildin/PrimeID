/**
 * secp256k1 ECDSA over SHA-256 of canonical JSON (audited @noble libraries).
 * Byte-compatible with crates/primeid-core/src/crypto.rs: compact r||s hex, low-S, RFC 6979.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { canonicalizeJson } from "./canonical";

export { bytesToHex, hexToBytes };

export function sha256Hex(input: string | Uint8Array): string {
  return bytesToHex(sha256(typeof input === "string" ? utf8ToBytes(input) : input));
}

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

const HEX = /^[0-9a-f]*$/;

export function isHex(s: unknown, bytes: number): s is string {
  return typeof s === "string" && s.length === bytes * 2 && HEX.test(s);
}

/** Validates a 33-byte compressed public key and returns it unchanged. Throws otherwise. */
export function parsePublicKey(pubHex: unknown): string {
  if (!isHex(pubHex, 33) || !(pubHex.startsWith("02") || pubHex.startsWith("03"))) {
    throw new Error("Public key must be 33-byte compressed lowercase hex");
  }
  secp256k1.ProjectivePoint.fromHex(pubHex).assertValidity();
  return pubHex;
}

export function newPrivateKey(): string {
  return bytesToHex(secp256k1.utils.randomPrivateKey());
}

export function publicKeyOf(privHex: string): string {
  return bytesToHex(secp256k1.getPublicKey(hexToBytes(privHex), true));
}

/** First 8 bytes of SHA-256 of the compressed key, grouped like the Prime screen shows it. */
export function fingerprint(pubHex: string): string {
  const h = sha256Hex(hexToBytes(pubHex)).slice(0, 16).toUpperCase();
  return `${h.slice(0, 4)} ${h.slice(4, 8)} ${h.slice(8, 12)} ${h.slice(12, 16)}`;
}

function digest(payload: unknown): Uint8Array {
  return sha256(utf8ToBytes(canonicalizeJson(payload)));
}

export function signPayload(payload: unknown, privHex: string): string {
  return secp256k1.sign(digest(payload), hexToBytes(privHex)).toCompactHex();
}

export function verifyPayload(payload: unknown, sigHex: unknown, pubHex: string): boolean {
  if (!isHex(sigHex, 64)) return false;
  try {
    return secp256k1.verify(hexToBytes(sigHex), digest(payload), hexToBytes(parsePublicKey(pubHex)), { lowS: true, format: "compact" });
  } catch {
    return false;
  }
}

/** Mirrors HolderKey::from_app_seed in Rust. Used only to generate cross-language test vectors. */
export function holderPrivateKeyFromAppSeed(appSeedHex: string): string {
  for (let counter = 0; ; counter++) {
    const msg = new Uint8Array([...utf8ToBytes("primeid/holder-key/v1"), 0, 0, 0, 0]);
    new DataView(msg.buffer).setUint32(msg.length - 4, counter);
    const candidate = hmac(sha256, hexToBytes(appSeedHex), msg);
    if (secp256k1.utils.isValidPrivateKey(candidate)) return bytesToHex(candidate);
  }
}
