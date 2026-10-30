/** Verifier state shared by the Verifier panel and the Attack Lab. */

import { checkRevoked, type Answer, type AnswerVerdict, type PrimeRequest, type VerifyContext, verifyAnswer } from "@core-crypto";
import { KEYS, TrustedIssuer, load, registryConfig, registryEnabled, save } from "./store";

/** Requests shown and not yet answered, by nonce. In memory only: a reload invalidates them. */
export const outstanding = new Map<string, PrimeRequest>();

export function verifierContext(): VerifyContext {
  return {
    outstanding,
    usedNonces: new Set(load<string[]>(KEYS.nonces, [])),
    trustedIssuers: new Set(load<TrustedIssuer[]>(KEYS.trusted, []).map((t) => t.pub)),
    isRevoked: registryEnabled
      ? (issuerPub: string, credId: string) => checkRevoked(registryConfig.rpcUrl, registryConfig.address, issuerPub, credId)
      : undefined,
  };
}

/** Verifies an answer; on success burns its nonce so it can never be accepted again. */
export async function verifyAndRecord(raw: unknown): Promise<AnswerVerdict> {
  const verdict = await verifyAnswer(raw, verifierContext());
  if (verdict.ok) {
    const nonce = (raw as Answer).nonce;
    outstanding.delete(nonce);
    save(KEYS.nonces, [nonce, ...load<string[]>(KEYS.nonces, [])].slice(0, 1000));
  }
  return verdict;
}

export interface VerifiedExchange { answer: Answer; request: PrimeRequest }
