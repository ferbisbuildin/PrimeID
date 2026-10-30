/**
 * KeyOS Application State Machine & Hardware Engine
 * Drives the state transitions, physical button handling,
 * trusted display logic, and QR workflows on Passport Prime.
 */

import { KeyOsStore, StoredCredentialRecord } from "./store";
import {
  CredentialIssuancePackage,
  VerifierRequest,
  SignedAnswer,
  PrivacyReceipt,
} from "../core-crypto/schemas";
import { lookupVerifier } from "./registry";

export type KeyOsScreen =
  | "VAULT_HOME"
  | "DEVICE_KEY_QR"
  | "SCAN_ISSUANCE"
  | "CONFIRM_IMPORT"
  | "SCAN_REQUEST"
  | "REVIEW_DISCLOSURE"
  | "SHOW_ANSWER_QR"
  | "RECEIPTS_LOG"
  | "SEED_SETTINGS"
  | "ICAO_NFC_READER";

export interface PendingImportState {
  pkg: CredentialIssuancePackage;
  rawJson: string;
  isBoundToDevice: boolean;
  issuerSignatureValid: boolean;
  label: string;
}

export interface PendingRequestState {
  request: VerifierRequest;
  rawJson: string;
  isVerifiedRequester: boolean;
  matchingCredential?: StoredCredentialRecord;
  revealedClaimKey: string;
  revealedClaimValue?: string;
  concealedClaimKeys: string[];
}

export class HardwareEngine {
  public store: KeyOsStore;
  public currentScreen: KeyOsScreen = "VAULT_HOME";
  public pendingImport: PendingImportState | null = null;
  public pendingRequest: PendingRequestState | null = null;
  public activeAnswer: SignedAnswer | null = null;
  public selectedIndex = 0;
  public audioAlertTriggered: "APPROVE" | "DENY" | "SCAN" | null = null;

  constructor(store: KeyOsStore) {
    this.store = store;
  }

  public navigate(screen: KeyOsScreen): void {
    this.currentScreen = screen;
    this.selectedIndex = 0;
    this.audioAlertTriggered = null;
  }

  /**
   * Process a scanned QR code payload from an issuer (Step 2)
   */
  public handleScannedIssuancePayload(rawJson: string): { success: boolean; error?: string } {
    try {
      const parsed = JSON.parse(rawJson);
      // Determine if format is { credential, disclosures }
      if (!parsed.credential || !parsed.disclosures) {
        return { success: false, error: "Invalid credential QR format (missing credential or disclosures)." };
      }

      const pkg = parsed as CredentialIssuancePackage;
      const devicePubKey = this.store.getHolderKey().publicKeyHex.toLowerCase();
      const isBound = pkg.credential.holder.toLowerCase() === devicePubKey;

      this.pendingImport = {
        pkg,
        rawJson,
        isBoundToDevice: isBound,
        issuerSignatureValid: true, // will be verified by pipeline
        label: pkg.credential.issuer_name || "New Credential",
      };

      this.navigate("CONFIRM_IMPORT");
      this.triggerHaptic("SCAN");
      return { success: true };
    } catch (err: unknown) {
      return { success: false, error: err instanceof Error ? err.message : "JSON parse failed" };
    }
  }

  /**
   * Process a scanned QR code payload from a verifier (Step 3)
   */
  public handleScannedRequestPayload(rawJson: string): { success: boolean; error?: string } {
    try {
      const parsed = JSON.parse(rawJson);
      if (!parsed.requested_claim || !parsed.nonce || !parsed.verifier_pubKey) {
        return { success: false, error: "Invalid Verifier Request QR format." };
      }

      const request = parsed as VerifierRequest;
      const verifierLookup = lookupVerifier(request.verifier_pubKey);
      const matchingCreds = this.store.findMatchingCredentials(request.requested_claim);

      if (matchingCreds.length === 0) {
        return {
          success: false,
          error: `No credential in your vault contains the requested claim "${request.requested_claim}".`,
        };
      }

      const primaryCred = matchingCreds[0];
      const matchingDisclosure = primaryCred.disclosures.find(
        (d) => d.key === request.requested_claim
      );
      const concealedKeys = primaryCred.disclosures
        .filter((d) => d.key !== request.requested_claim)
        .map((d) => d.key);

      this.pendingRequest = {
        request,
        rawJson,
        isVerifiedRequester: verifierLookup.isVerified,
        matchingCredential: primaryCred,
        revealedClaimKey: request.requested_claim,
        revealedClaimValue: matchingDisclosure?.value,
        concealedClaimKeys: concealedKeys,
      };

      this.navigate("REVIEW_DISCLOSURE");
      this.triggerHaptic("SCAN");
      return { success: true };
    } catch (err: unknown) {
      return { success: false, error: err instanceof Error ? err.message : "JSON parse failed" };
    }
  }

  /**
   * Hardware Physical Center Button: OK / APPROVE
   */
  public pressHardwareOk(): void {
    if (this.currentScreen === "CONFIRM_IMPORT" && this.pendingImport) {
      const res = this.store.importCredentialPackage(this.pendingImport.pkg, this.pendingImport.label);
      if (res.success) {
        this.triggerHaptic("APPROVE");
        this.pendingImport = null;
        this.navigate("VAULT_HOME");
      }
    } else if (this.currentScreen === "REVIEW_DISCLOSURE" && this.pendingRequest) {
      if (this.pendingRequest.matchingCredential) {
        const answer = this.store.generateApprovedAnswer(
          this.pendingRequest.request,
          this.pendingRequest.matchingCredential
        );
        this.activeAnswer = answer;
        this.pendingRequest = null;
        this.triggerHaptic("APPROVE");
        this.navigate("SHOW_ANSWER_QR");
      }
    } else if (this.currentScreen === "VAULT_HOME") {
      this.navigate("DEVICE_KEY_QR");
    }
  }

  /**
   * Hardware Physical Back Button: DENY / CANCEL
   */
  public pressHardwareBack(): void {
    if (this.currentScreen === "REVIEW_DISCLOSURE" && this.pendingRequest) {
      this.store.recordDeniedRequest(this.pendingRequest.request);
      this.pendingRequest = null;
      this.triggerHaptic("DENY");
      this.navigate("VAULT_HOME");
    } else if (this.currentScreen === "CONFIRM_IMPORT") {
      this.pendingImport = null;
      this.navigate("VAULT_HOME");
    } else if (this.currentScreen !== "VAULT_HOME") {
      this.navigate("VAULT_HOME");
    }
  }

  public pressDpadUp(): void {
    if (this.selectedIndex > 0) {
      this.selectedIndex--;
    }
  }

  public pressDpadDown(maxItems = 5): void {
    if (this.selectedIndex < maxItems - 1) {
      this.selectedIndex++;
    }
  }

  private triggerHaptic(type: "APPROVE" | "DENY" | "SCAN"): void {
    this.audioAlertTriggered = type;
  }
}
