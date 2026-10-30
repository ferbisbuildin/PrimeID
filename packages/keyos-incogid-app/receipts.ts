/**
 * Local Privacy Receipts Audit Log
 * Immutable local record on Passport Prime of every identity presentation.
 * Privacy principle: Only the user can view this log on their physical hardware.
 */

import { PrivacyReceipt } from "../core-crypto/schemas";

export interface ReceiptStats {
  totalRequests: number;
  approvedCount: number;
  deniedCount: number;
  totalClaimsConcealed: number;
  totalClaimsRevealed: number;
  privacyShieldRatio: number; // percentage of claims kept safe on device
  verifiedRequestersCount: number;
  unknownRequestersCount: number;
}

export class PrivacyReceiptManager {
  private receipts: PrivacyReceipt[] = [];

  constructor(initialReceipts: PrivacyReceipt[] = []) {
    this.receipts = [...initialReceipts];
  }

  public recordReceipt(receipt: PrivacyReceipt): void {
    // Append at the beginning (newest first)
    this.receipts.unshift(receipt);
  }

  public getAll(): PrivacyReceipt[] {
    return [...this.receipts];
  }

  public getById(id: string): PrivacyReceipt | undefined {
    return this.receipts.find((r) => r.id === id);
  }

  public clear(): void {
    this.receipts = [];
  }

  public getStats(): ReceiptStats {
    const totalRequests = this.receipts.length;
    let approvedCount = 0;
    let deniedCount = 0;
    let totalClaimsConcealed = 0;
    let totalClaimsRevealed = 0;
    let verifiedRequestersCount = 0;
    let unknownRequestersCount = 0;

    for (const r of this.receipts) {
      if (r.decision === "APPROVED") {
        approvedCount++;
        if (r.revealed_data) {
          totalClaimsRevealed++;
        }
      } else {
        deniedCount++;
      }
      totalClaimsConcealed += r.concealed_claims.length;
      if (r.is_verified_requester) {
        verifiedRequestersCount++;
      } else {
        unknownRequestersCount++;
      }
    }

    const totalClaimsHandled = totalClaimsConcealed + totalClaimsRevealed;
    const privacyShieldRatio =
      totalClaimsHandled > 0 ? (totalClaimsConcealed / totalClaimsHandled) * 100 : 100;

    return {
      totalRequests,
      approvedCount,
      deniedCount,
      totalClaimsConcealed,
      totalClaimsRevealed,
      privacyShieldRatio: Math.round(privacyShieldRatio),
      verifiedRequestersCount,
      unknownRequestersCount,
    };
  }
}
