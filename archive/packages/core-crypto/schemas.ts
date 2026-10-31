/**
 * IncogID++ v1.0 Cryptographic Data Schemas
 * Standardized across KeyOS, Issuer Studio, and Verifier Terminal
 */

export interface ClaimEntry {
  key: string;
  value: string;
  salt: string; // Cryptographically secure random 32-byte hex salt
}

export interface CredentialPayload {
  credential_id: string;
  issuer_name: string;
  issuer: string; // issuer secp256k1 public key hex (compressed, 33 bytes -> 66 hex chars)
  holder: string; // Prime IncogID secp256k1 public key hex
  issued_at: number; // Unix timestamp in seconds
  expires: number; // Unix timestamp in seconds
  claims: string[]; // SHA-256 salted hashes: sha256(salt + ":" + key + ":" + value)
  signature: string; // issuer secp256k1 signature hex over canonical JSON of above fields
}

/**
 * Full issuance bundle transferred to IncogID++'s secure sandboxed storage.
 * The QR code contains the credential + the private claim entries (with salts)
 * so that the air-gapped device can store and reconstruct individual selective disclosures.
 */
export interface CredentialIssuancePackage {
  credential: CredentialPayload;
  disclosures: ClaimEntry[]; // Private claim values and salts for device storage only
}

export interface VerifierRequest {
  request_id: string;
  verifier_name: string;
  verifier_pubKey: string; // verifier secp256k1 public key hex
  requested_claim: string; // e.g., "over_18"
  nonce: string; // 128-bit cryptographically secure random hex
  expires: number; // Unix timestamp in seconds
  signature: string; // verifier secp256k1 signature over canonical request fields
}

export interface DisclosedClaim {
  key: string;
  value: string;
  salt: string;
}

export interface RequestContext {
  nonce: string;
  verifier_pubKey: string;
  expires: number;
}

export interface SignedAnswer {
  credential: CredentialPayload;
  disclosed_claim: DisclosedClaim;
  request_context: RequestContext;
  holder_signature: string; // secp256k1 signature by holder private key over canonical payload
}

export interface PrivacyReceipt {
  id: string;
  timestamp: number;
  verifier_name: string;
  verifier_pubKey: string;
  is_verified_requester: boolean;
  requested_claim: string;
  decision: "APPROVED" | "DENIED";
  revealed_data: {
    key: string;
    value: string;
  } | null;
  concealed_claims: string[]; // Keys of claims that remained protected on device
  credential_id: string;
  nonce: string;
}

export interface RevocationList {
  issuer_name: string;
  issuer_pubKey: string;
  revoked_credential_ids: string[];
  published_at: number;
  signature: string;
}

export interface PipelineStepResult {
  step: number;
  name: string;
  status: "PASSED" | "FAILED" | "PENDING";
  description: string;
  technical_details: string;
  computed_hash?: string;
  expected_hash?: string;
  verified_key?: string;
}

export interface VerificationPipelineResult {
  isValid: boolean;
  reason?: string;
  steps: PipelineStepResult[];
  disclosedClaim?: {
    key: string;
    value: string;
  };
  holderPubKey?: string;
  issuerPubKey?: string;
  timestamp: number;
}
