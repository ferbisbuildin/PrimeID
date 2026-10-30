/**
 * Passphrase-encrypted keystore for the issuer and verifier signing keys.
 *
 * Only ciphertext is persisted (PBKDF2-SHA256 600k -> AES-256-GCM, via WebCrypto). The private key
 * is decrypted into memory for the tab's lifetime and never sent anywhere. Name and public key are
 * public and stored in the clear so other panels can show them while the key is locked.
 */

import { bytesToHex, hexToBytes, newPrivateKey, publicKeyOf } from "@core-crypto";

export type Role = "issuer" | "verifier";

export interface KeystoreRecord {
  v: 1;
  role: Role;
  name: string;
  pub: string;
  salt: string;
  iv: string;
  ct: string;
}

export interface UnlockedKey {
  role: Role;
  name: string;
  pub: string;
  priv: string;
}

const ITERATIONS = 600_000;
const storageKey = (role: Role) => `primeid.keystore.${role}`;
const enc = new TextEncoder();
/** Copies into a plain ArrayBuffer-backed view, as WebCrypto typings require. */
const buf = (u: Uint8Array) => new Uint8Array(u);

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: buf(salt), iterations: ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function readKeystore(role: Role): KeystoreRecord | null {
  try {
    const raw = localStorage.getItem(storageKey(role));
    if (!raw) return null;
    const rec = JSON.parse(raw) as KeystoreRecord;
    return rec.v === 1 && rec.role === role ? rec : null;
  } catch {
    return null;
  }
}

export async function createKeystore(role: Role, name: string, passphrase: string): Promise<UnlockedKey> {
  if (passphrase.length < 10) throw new Error("Use a passphrase of at least 10 characters");
  const priv = newPrivateKey();
  const pub = publicKeyOf(priv);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`primeid/${role}`) }, key, buf(hexToBytes(priv)));
  const rec: KeystoreRecord = { v: 1, role, name, pub, salt: bytesToHex(salt), iv: bytesToHex(iv), ct: bytesToHex(new Uint8Array(ct)) };
  localStorage.setItem(storageKey(role), JSON.stringify(rec));
  return { role, name, pub, priv };
}

export async function unlockKeystore(role: Role, passphrase: string): Promise<UnlockedKey> {
  const rec = readKeystore(role);
  if (!rec) throw new Error("No key stored for this role");
  const key = await deriveKey(passphrase, buf(hexToBytes(rec.salt)));
  let plain: ArrayBuffer;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf(hexToBytes(rec.iv)), additionalData: enc.encode(`primeid/${role}`) }, key, buf(hexToBytes(rec.ct)));
  } catch {
    throw new Error("Wrong passphrase");
  }
  const priv = bytesToHex(new Uint8Array(plain));
  if (publicKeyOf(priv) !== rec.pub) throw new Error("Keystore is corrupted");
  return { role, name: rec.name, pub: rec.pub, priv };
}

export function deleteKeystore(role: Role): void {
  localStorage.removeItem(storageKey(role));
}
