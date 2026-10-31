/**
 * secp256k1 Cryptographic Engine
 * Uses @noble/curves/secp256k1 and @noble/hashes for real, audited ECDSA operations.
 * Implements deterministic canonical JSON signing and verification.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { canonicalizeJson } from "./canonical";

export interface KeyPair {
  privateKeyHex: string;
  publicKeyHex: string; // 33-byte compressed hex (66 chars)
}

/**
 * Computes SHA-256 hash of a string or byte array and returns a hex string.
 */
export function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
  const hash = sha256(bytes);
  return bytesToHex(hash);
}

/**
 * Computes SHA-256 hash and returns raw Uint8Array.
 */
export function sha256Bytes(input: string | Uint8Array): Uint8Array {
  const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
  return sha256(bytes);
}

/**
 * Generates a fresh random secp256k1 keypair.
 */
export function generateRandomKeyPair(): KeyPair {
  const privKey = secp256k1.utils.randomPrivateKey();
  const pubKey = secp256k1.getPublicKey(privKey, true); // compressed 33 bytes
  return {
    privateKeyHex: bytesToHex(privKey),
    publicKeyHex: bytesToHex(pubKey),
  };
}

/**
 * Derives public key (compressed 33-byte hex) from a private key hex.
 */
export function getPublicKeyFromPrivate(privateKeyHex: string): string {
  const privBytes = hexToBytes(privateKeyHex);
  const pubBytes = secp256k1.getPublicKey(privBytes, true);
  return bytesToHex(pubBytes);
}

/**
 * Signs an arbitrary object deterministically using RFC 8785 canonicalization.
 */
export function signCanonicalObject(obj: unknown, privateKeyHex: string): string {
  const canonicalString = canonicalizeJson(obj);
  const hash = sha256(utf8ToBytes(canonicalString));
  const privBytes = hexToBytes(privateKeyHex);
  const sig = secp256k1.sign(hash, privBytes);
  return sig.toCompactHex();
}

/**
 * Verifies a signature against an arbitrary object using RFC 8785 canonicalization.
 */
export function verifyCanonicalObjectSignature(
  obj: unknown,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    const canonicalString = canonicalizeJson(obj);
    const hash = sha256(utf8ToBytes(canonicalString));
    return secp256k1.verify(hexToBytes(signatureHex), hash, hexToBytes(publicKeyHex));
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

/**
 * Signs raw text with secp256k1.
 */
export function signText(text: string, privateKeyHex: string): string {
  const hash = sha256(utf8ToBytes(text));
  const privBytes = hexToBytes(privateKeyHex);
  const sig = secp256k1.sign(hash, privBytes);
  return sig.toCompactHex();
}

/**
 * Verifies a signature over raw text.
 */
export function verifyTextSignature(
  text: string,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    const hash = sha256(utf8ToBytes(text));
    return secp256k1.verify(hexToBytes(signatureHex), hash, hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}

export { bytesToHex, hexToBytes, utf8ToBytes };
