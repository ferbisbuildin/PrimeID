/**
 * Red-Team Attack Suite & Cryptographic Adversary Generators
 * Tests and proves protocol security guarantees against real attack vectors:
 * 1. Forged Credential ("The AI Fake ID") -> Tampered issuer signature / rogue issuer
 * 2. Copied Credential in Another App -> Screenshot replay signed by different holder key
 * 3. Replayed Old Answer -> Expired or duplicate nonce reuse
 * 4. Fake Requester Posing as a Bank -> Unregistered / untrusted verifier public key
 */

import { CredentialPayload, SignedAnswer, VerifierRequest, ClaimEntry } from "./schemas";
import { generateRandomKeyPair, signCanonicalObject } from "./secp256k1";
import { executeVerificationPipeline } from "./pipeline";
import { VerificationPipelineResult } from "./schemas";

export interface AttackScenarioResult {
  attackId: string;
  name: string;
  targetCheck: string;
  expectedOutcome: "BLOCKED" | "WARNING";
  description?: string;
  threatModel: string;
  pipelineResult: VerificationPipelineResult;
  isDefenseSuccessful: boolean;
  securityVerdict: string;
}

/**
 * ATTACK 1: The AI Fake ID (Forged Credential)
 * An adversary generates plausible claims and signs them with a rogue private key,
 * pretending to be the official "Global Identity Authority".
 */
export function simulateAiFakeIdAttack(
  legitimateIssuerPubKey: string,
  holderPubKey: string,
  claims: string[],
  disclosedClaim: { key: string; value: string; salt: string },
  activeChallengeNonce: string,
  verifierPubKey: string
): AttackScenarioResult {
  // Attacker generates their own rogue keypair
  const attackerKeys = generateRandomKeyPair();

  const forgedCredentialPayload = {
    credential_id: "forged_cred_ai_fake_01",
    issuer_name: "Global Identity Authority [FORGED BY AI]",
    issuer: legitimateIssuerPubKey, // Pretends to be legitimate issuer
    holder: holderPubKey,
    issued_at: Math.floor(Date.now() / 1000) - 100,
    expires: Math.floor(Date.now() / 1000) + 86400,
    claims,
  };

  // Attacker cannot forge legitimateIssuer's private key signature, so signs with rogue key
  const forgedSignature = signCanonicalObject(forgedCredentialPayload, attackerKeys.privateKeyHex);

  const forgedCredential: CredentialPayload = {
    ...forgedCredentialPayload,
    signature: forgedSignature,
  };

  // Holder signs answer
  const answerContext = {
    nonce: activeChallengeNonce,
    verifier_pubKey: verifierPubKey,
    expires: Math.floor(Date.now() / 1000) + 300,
  };

  // Even if a valid holder key signs the answer, the issuer signature inside the credential will fail
  const dummyHolder = generateRandomKeyPair();
  const answerPayload = {
    credential: forgedCredential,
    disclosed_claim: disclosedClaim,
    request_context: answerContext,
  };
  const holderSig = signCanonicalObject(answerPayload, dummyHolder.privateKeyHex);

  const answer: SignedAnswer = {
    credential: forgedCredential,
    disclosed_claim: disclosedClaim,
    request_context: answerContext,
    holder_signature: holderSig,
  };

  const pipelineResult = executeVerificationPipeline(answer, {
    expectedNonce: activeChallengeNonce,
    expectedVerifierPubKey: verifierPubKey,
  });

  const step1Failed = pipelineResult.steps[0].status === "FAILED";
  const isDefenseSuccessful = !pipelineResult.isValid && step1Failed;

  return {
    attackId: "ai_fake_id",
    name: "Forged Credential ('The AI Fake ID')",
    targetCheck: "Step 1: Issuer Signature Check",
    expectedOutcome: "BLOCKED",
    threatModel:
      "Adversary uses generative AI to generate a synthetic ID image/data payload and attempts to present it as a legitimate government/bank credential.",
    pipelineResult,
    isDefenseSuccessful,
    securityVerdict: isDefenseSuccessful
      ? "DEFENSE CONFIRMED: Cryptographic ECDSA check on secp256k1 proved the issuer signature does not resolve to the genuine authority. Attack blocked at Step 1."
      : "SECURITY COMPROMISED: Forged credential bypassed Step 1 check!",
  };
}

/**
 * ATTACK 2: Copied Credential in Another App (Credential Theft)
 * An adversary takes a screenshot or intercepts someone else's credential QR
 * and tries to present it using their own wallet app / private key.
 */
export function simulateCopiedCredentialAttack(
  validCredential: CredentialPayload,
  disclosedClaim: { key: string; value: string; salt: string },
  activeChallengeNonce: string,
  verifierPubKey: string
): AttackScenarioResult {
  // Thief has their own device/wallet with a different keypair
  const thiefKeys = generateRandomKeyPair();

  const answerContext = {
    nonce: activeChallengeNonce,
    verifier_pubKey: verifierPubKey,
    expires: Math.floor(Date.now() / 1000) + 300,
  };

  // The thief signs the answer with the thief's private key
  const answerPayload = {
    credential: validCredential, // Legitimate credential bound to Victim's holder key
    disclosed_claim: disclosedClaim,
    request_context: answerContext,
  };

  // Thief signs with thief's key, NOT victim's key
  const thiefHolderSig = signCanonicalObject(answerPayload, thiefKeys.privateKeyHex);

  const answer: SignedAnswer = {
    credential: validCredential,
    disclosed_claim: disclosedClaim,
    request_context: answerContext,
    holder_signature: thiefHolderSig,
  };

  const pipelineResult = executeVerificationPipeline(answer, {
    expectedNonce: activeChallengeNonce,
    expectedVerifierPubKey: verifierPubKey,
  });

  const step3Failed = pipelineResult.steps[2].status === "FAILED";
  const isDefenseSuccessful = !pipelineResult.isValid && step3Failed;

  return {
    attackId: "copied_credential",
    name: "Copied Credential ('The Screenshot Thief')",
    targetCheck: "Step 3: Holder Binding Signature Check",
    expectedOutcome: "BLOCKED",
    threatModel:
      "Adversary photographs or copies a user's credential QR code and loads it onto another device to impersonate them.",
    pipelineResult,
    isDefenseSuccessful,
    securityVerdict: isDefenseSuccessful
      ? "DEFENSE CONFIRMED: Hardware key binding stopped the theft! The thief's signature was checked against credential.holder and failed. Attack blocked at Step 3."
      : "SECURITY COMPROMISED: Stolen credential was accepted by verifier!",
  };
}

/**
 * ATTACK 3: Replayed Old Answer (Replay Attack)
 * An adversary captures an old, previously valid Answer QR (from CCTV or intercepted traffic)
 * and resubmits it to a new verification session.
 */
export function simulateReplayedAnswerAttack(
  previouslyValidAnswer: SignedAnswer,
  newChallengeNonce: string,
  verifierPubKey: string
): AttackScenarioResult {
  // The answer contains the OLD nonce from the previous session, not the fresh newChallengeNonce
  const pipelineResult = executeVerificationPipeline(previouslyValidAnswer, {
    expectedNonce: newChallengeNonce,
    expectedVerifierPubKey: verifierPubKey,
  });

  const step4Failed = pipelineResult.steps[3].status === "FAILED";
  const isDefenseSuccessful = !pipelineResult.isValid && step4Failed;

  return {
    attackId: "replayed_answer",
    name: "Replayed Old Answer ('The Replay Attack')",
    targetCheck: "Step 4: Nonce & Expiry Check",
    expectedOutcome: "BLOCKED",
    threatModel:
      "Adversary intercepts or records a user's valid Answer QR at an airport or venue and attempts to replay it later at another terminal.",
    pipelineResult,
    isDefenseSuccessful,
    securityVerdict: isDefenseSuccessful
      ? `DEFENSE CONFIRMED: One-time cryptographic challenge nonce mismatch detected (Expected: ${newChallengeNonce.slice(0, 8)}... Received: ${previouslyValidAnswer.request_context.nonce.slice(0, 8)}...). Attack blocked at Step 4.`
      : "SECURITY COMPROMISED: Replayed answer was accepted!",
  };
}

/**
 * ATTACK 4: Fake Requester Posing as a Bank (Phishing Attack)
 * A rogue website or malicious actor crafts a signed request pretending to be "First National Bank",
 * but signs with an unknown/untrusted public key.
 */
export function simulatePhishingRequesterAttack(
  registeredVerifierPubKeys: string[],
  requestedClaim = "over_18"
): {
  request: VerifierRequest;
  isRegistered: boolean;
  uiBadge: "VERIFIED" | "UNKNOWN_THREAT";
  warningText: string;
} {
  const rogueKeys = generateRandomKeyPair();
  const nonce = "phish_" + Math.random().toString(16).slice(2);
  const expires = Math.floor(Date.now() / 1000) + 300;

  const requestPayload = {
    request_id: "req_phish_" + Math.random().toString(36).slice(2, 8),
    verifier_name: "First National Bank Security (Phishing Imposter)",
    verifier_pubKey: rogueKeys.publicKeyHex,
    requested_claim: requestedClaim,
    nonce,
    expires,
  };

  const signature = signCanonicalObject(requestPayload, rogueKeys.privateKeyHex);

  const request: VerifierRequest = {
    ...requestPayload,
    signature,
  };

  const isRegistered = registeredVerifierPubKeys.includes(request.verifier_pubKey);

  return {
    request,
    isRegistered,
    uiBadge: isRegistered ? "VERIFIED" : "UNKNOWN_THREAT",
    warningText:
      "CRITICAL SECURITY ALERT: Requester key is NOT in your Passport Prime on-device registry! This requester is UNKNOWN and may be an attacker attempting to phish your identity.",
  };
}
