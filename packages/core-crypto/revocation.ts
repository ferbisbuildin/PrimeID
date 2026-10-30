/**
 * Revocation Engine
 * Supports issuer-signed Revocation Lists (CRLs).
 * Allows IncogID++ and Verifiers to verify whether a credential ID has been revoked by its issuer.
 */

import { RevocationList } from "./schemas";
import { signCanonicalObject, verifyCanonicalObjectSignature } from "./secp256k1";

/**
 * Creates a cryptographically signed Revocation List for an issuer.
 */
export function createRevocationList(
  issuerName: string,
  issuerPubKey: string,
  issuerPrivKey: string,
  revokedCredentialIds: string[]
): RevocationList {
  const publishedAt = Math.floor(Date.now() / 1000);
  const payloadToSign = {
    issuer_name: issuerName,
    issuer_pubKey: issuerPubKey,
    revoked_credential_ids: [...revokedCredentialIds].sort(),
    published_at: publishedAt,
  };

  const signature = signCanonicalObject(payloadToSign, issuerPrivKey);

  return {
    issuer_name: issuerName,
    issuer_pubKey: issuerPubKey,
    revoked_credential_ids: payloadToSign.revoked_credential_ids,
    published_at: publishedAt,
    signature,
  };
}

/**
 * Verifies that a Revocation List was authentically signed by the issuer.
 */
export function verifyRevocationListSignature(crl: RevocationList): boolean {
  const payloadToVerify = {
    issuer_name: crl.issuer_name,
    issuer_pubKey: crl.issuer_pubKey,
    revoked_credential_ids: [...crl.revoked_credential_ids].sort(),
    published_at: crl.published_at,
  };

  return verifyCanonicalObjectSignature(payloadToVerify, crl.signature, crl.issuer_pubKey);
}

/**
 * Checks if a specific credential_id is revoked according to a verified CRL.
 */
export function isCredentialRevoked(credentialId: string, crl: RevocationList): boolean {
  if (!verifyRevocationListSignature(crl)) {
    throw new Error("Invalid revocation list signature - CRL cannot be trusted");
  }
  return crl.revoked_credential_ids.includes(credentialId);
}
