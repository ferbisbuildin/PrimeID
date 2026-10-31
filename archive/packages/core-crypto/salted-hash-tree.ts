/**
 * SD-JWT Style Salted Hash Claim Tree
 * Generates cryptographic salts, salted claim hashes, and verifies selective disclosures.
 */

import { ClaimEntry, DisclosedClaim } from "./schemas";
import { sha256Hex } from "./secp256k1";

/**
 * Generate a cryptographically secure 32-byte (64 hex characters) salt
 */
export function generateSalt(): string {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Fallback for Node environments without global crypto
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require("crypto");
    const nodeBytes = nodeCrypto.randomBytes(32);
    return Buffer.from(nodeBytes).toString("hex");
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Computes the canonical salted hash for a specific claim:
 * SHA-256(salt + ":" + key + ":" + value)
 */
export function computeClaimHash(salt: string, key: string, value: string): string {
  const preimage = `${salt}:${key}:${value}`;
  return sha256Hex(preimage);
}

/**
 * Creates salted claim entries for a dictionary of claims.
 * Returns the private claim entries (stored in IncogID++ vault)
 * and the public hashed array to be included in the signed credential.
 */
export function createSaltedClaims(claimsObj: Record<string, string>): {
  disclosures: ClaimEntry[];
  claimHashes: string[];
} {
  const disclosures: ClaimEntry[] = [];
  const claimHashes: string[] = [];

  for (const [key, value] of Object.entries(claimsObj)) {
    const salt = generateSalt();
    const hash = computeClaimHash(salt, key, String(value));
    disclosures.push({
      key,
      value: String(value),
      salt,
    });
    claimHashes.push(hash);
  }

  return { disclosures, claimHashes };
}

/**
 * Extracts a specific claim and its salt to produce a Selective Disclosure payload.
 */
export function createDisclosedClaim(
  disclosures: ClaimEntry[],
  requestedKey: string
): DisclosedClaim | null {
  const entry = disclosures.find((d) => d.key === requestedKey);
  if (!entry) {
    return null;
  }
  return {
    key: entry.key,
    value: entry.value,
    salt: entry.salt,
  };
}

/**
 * Verifies that a disclosed claim (salt + key + value) hashes to one of the
 * hashes committed to in the credential's claim tree.
 */
export function verifyDisclosedClaimHash(
  disclosed: DisclosedClaim,
  credentialClaims: string[]
): { isValid: boolean; computedHash: string } {
  const computedHash = computeClaimHash(disclosed.salt, disclosed.key, disclosed.value);
  const isValid = credentialClaims.includes(computedHash);
  return { isValid, computedHash };
}
