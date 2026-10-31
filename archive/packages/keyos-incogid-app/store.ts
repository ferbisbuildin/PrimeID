/**
 * Passport Prime KeyOS Application Sandboxed Store
 * Encapsulates device identity keys, sandboxed credential vault with salts,
 * local settings, and privacy receipts log.
 */

import {
  CredentialPayload,
  ClaimEntry,
  VerifierRequest,
  SignedAnswer,
  PrivacyReceipt,
  CredentialIssuancePackage,
} from "../core-crypto/schemas";
import {
  deriveKeyPairFromMnemonic,
  generateMnemonic,
  deriveUnlinkableChildKey,
  INCOGID_BASE_DERIVATION_PATH,
} from "../core-crypto/bip39-bip32";
import { KeyPair, signCanonicalObject } from "../core-crypto/secp256k1";
import { createDisclosedClaim } from "../core-crypto/salted-hash-tree";
import { lookupVerifier } from "./registry";
import { PrivacyReceiptManager } from "./receipts";

export interface StoredCredentialRecord {
  credential: CredentialPayload;
  disclosures: ClaimEntry[];
  addedAt: number;
  label?: string;
  isIcaoPassport?: boolean;
}

export interface KeyOsDeviceSettings {
  deviceName: string;
  pinProtected: boolean;
  hapticFeedback: boolean;
  audibleChirp: boolean;
  requirePhysicalConfirmation: boolean;
  showTechnicalHashes: boolean;
  activeDerivationPath: string;
  useUnlinkableKeys: boolean;
  unlinkableChildIndex: number;
}

const DEFAULT_SETTINGS: KeyOsDeviceSettings = {
  deviceName: "Passport Prime #0482",
  pinProtected: true,
  hapticFeedback: true,
  audibleChirp: true,
  requirePhysicalConfirmation: true,
  showTechnicalHashes: true,
  activeDerivationPath: INCOGID_BASE_DERIVATION_PATH,
  useUnlinkableKeys: false,
  unlinkableChildIndex: 0,
};

// Default seed phrase for immediate testing out of the box (standard BIP39)
export const DEFAULT_DEMO_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

export class KeyOsStore {
  private mnemonic: string;
  private holderKey: KeyPair;
  private credentials: StoredCredentialRecord[] = [];
  public receipts: PrivacyReceiptManager;
  public settings: KeyOsDeviceSettings;

  constructor(initialMnemonic?: string) {
    this.mnemonic = initialMnemonic || DEFAULT_DEMO_MNEMONIC;
    this.holderKey = deriveKeyPairFromMnemonic(this.mnemonic, INCOGID_BASE_DERIVATION_PATH);
    this.receipts = new PrivacyReceiptManager();
    this.settings = { ...DEFAULT_SETTINGS };
  }

  public getMnemonic(): string {
    return this.mnemonic;
  }

  public getHolderKey(): KeyPair {
    if (this.settings.useUnlinkableKeys) {
      return deriveUnlinkableChildKey(this.mnemonic, this.settings.unlinkableChildIndex);
    }
    return this.holderKey;
  }

  public restoreFromMnemonic(newMnemonic: string): void {
    const derived = deriveKeyPairFromMnemonic(newMnemonic, this.settings.activeDerivationPath);
    this.mnemonic = newMnemonic;
    this.holderKey = derived;
  }

  public generateNewSeed(wordCount: 12 | 24 = 12): string {
    const mnemonic = generateMnemonic(wordCount);
    this.restoreFromMnemonic(mnemonic);
    return mnemonic;
  }

  public incrementUnlinkableIndex(): number {
    this.settings.unlinkableChildIndex++;
    return this.settings.unlinkableChildIndex;
  }

  /**
   * Ingest a newly scanned issuance package from an issuer into sandboxed vault.
   */
  public importCredentialPackage(pkg: CredentialIssuancePackage, label?: string): {
    success: boolean;
    error?: string;
  } {
    // 1. Check if bound to this device
    const currentHolder = this.getHolderKey().publicKeyHex.toLowerCase();
    const pkgHolder = pkg.credential.holder.toLowerCase();

    if (currentHolder !== pkgHolder) {
      return {
        success: false,
        error: `Credential is bound to public key ${pkgHolder.slice(0, 16)}..., but this device key is ${currentHolder.slice(0, 16)}...`,
      };
    }

    // 2. Check if already in vault
    const existingIndex = this.credentials.findIndex(
      (c) => c.credential.credential_id === pkg.credential.credential_id
    );

    const record: StoredCredentialRecord = {
      credential: pkg.credential,
      disclosures: pkg.disclosures,
      addedAt: Date.now(),
      label: label || pkg.credential.issuer_name,
      isIcaoPassport: pkg.disclosures.some((d) => d.key === "icao_verified"),
    };

    if (existingIndex >= 0) {
      this.credentials[existingIndex] = record;
    } else {
      this.credentials.push(record);
    }

    return { success: true };
  }

  public getCredentials(): StoredCredentialRecord[] {
    return [...this.credentials];
  }

  public getCredentialById(id: string): StoredCredentialRecord | undefined {
    return this.credentials.find((c) => c.credential.credential_id === id);
  }

  public deleteCredential(id: string): void {
    this.credentials = this.credentials.filter((c) => c.credential.credential_id !== id);
  }

  /**
   * Evaluates a verifier's incoming request against vault credentials.
   * Returns matching credentials that contain the requested claim.
   */
  public findMatchingCredentials(requestedClaimKey: string): StoredCredentialRecord[] {
    return this.credentials.filter((cred) =>
      cred.disclosures.some((d) => d.key === requestedClaimKey)
    );
  }

  /**
   * User approves the request on hardware: reveals ONLY the requested claim,
   * signs the payload with holder private key, and writes a Privacy Receipt.
   */
  public generateApprovedAnswer(
    request: VerifierRequest,
    targetCredentialRecord: StoredCredentialRecord
  ): SignedAnswer {
    const { requested_claim, nonce, verifier_pubKey, expires } = request;

    // 1. Extract only the single requested claim + salt
    const disclosedClaim = createDisclosedClaim(
      targetCredentialRecord.disclosures,
      requested_claim
    );

    if (!disclosedClaim) {
      throw new Error(`Claim "${requested_claim}" not found in selected credential.`);
    }

    const requestContext = {
      nonce,
      verifier_pubKey,
      expires,
    };

    // 2. Construct canonical payload to sign
    const answerPayload = {
      credential: targetCredentialRecord.credential,
      disclosed_claim: disclosedClaim,
      request_context: requestContext,
    };

    // 3. Sign with device's holder private key
    const activeKeyPair = this.getHolderKey();
    const holderSignature = signCanonicalObject(answerPayload, activeKeyPair.privateKeyHex);

    const answer: SignedAnswer = {
      credential: targetCredentialRecord.credential,
      disclosed_claim: disclosedClaim,
      request_context: requestContext,
      holder_signature: holderSignature,
    };

    // 4. Record local privacy receipt
    const concealedClaimKeys = targetCredentialRecord.disclosures
      .filter((d) => d.key !== requested_claim)
      .map((d) => d.key);

    const isVerified = lookupVerifier(request.verifier_pubKey).isVerified;

    this.receipts.recordReceipt({
      id: "rec_" + Math.random().toString(36).slice(2, 10),
      timestamp: Math.floor(Date.now() / 1000),
      verifier_name: request.verifier_name,
      verifier_pubKey: request.verifier_pubKey,
      is_verified_requester: isVerified,
      requested_claim: request.requested_claim,
      decision: "APPROVED",
      revealed_data: {
        key: disclosedClaim.key,
        value: disclosedClaim.value,
      },
      concealed_claims: concealedClaimKeys,
      credential_id: targetCredentialRecord.credential.credential_id,
      nonce: request.nonce,
    });

    if (this.settings.useUnlinkableKeys) {
      this.incrementUnlinkableIndex();
    }

    return answer;
  }

  /**
   * User rejects the request on hardware: records a DENIED Privacy Receipt.
   */
  public recordDeniedRequest(request: VerifierRequest): void {
    const isVerified = lookupVerifier(request.verifier_pubKey).isVerified;
    this.receipts.recordReceipt({
      id: "rec_denied_" + Math.random().toString(36).slice(2, 10),
      timestamp: Math.floor(Date.now() / 1000),
      verifier_name: request.verifier_name,
      verifier_pubKey: request.verifier_pubKey,
      is_verified_requester: isVerified,
      requested_claim: request.requested_claim,
      decision: "DENIED",
      revealed_data: null,
      concealed_claims: ["ALL_DATA_PROTECTED"],
      credential_id: "NONE",
      nonce: request.nonce,
    });
  }
}
