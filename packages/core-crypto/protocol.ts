/**
 * PrimeID protocol v1: the issuer and verifier halves.
 * The Passport Prime half lives in crates/primeid-core (Rust) and must stay byte-compatible.
 * tests/vectors.test.ts and crates/primeid-core/tests/vectors.rs pin that compatibility.
 */

import { canonicalizeJson } from "./canonical";
import { isHex, parsePublicKey, publicKeyOf, randomHex, sha256Hex, signPayload, verifyPayload } from "./crypto";

export const TYP = {
  holder: "primeid/holder/v1",
  offer: "primeid/offer/v1",
  credential: "primeid/credential/v1",
  verifierCert: "primeid/verifier-cert/v1",
  request: "primeid/request/v1",
  answer: "primeid/answer/v1",
} as const;

export const CLOCK_SKEW_SECS = 300;
export const MAX_REQUEST_LIFETIME_SECS = 15 * 60;

export interface HolderKeyQr { typ: typeof TYP.holder; pub: string }

export interface Credential {
  typ: typeof TYP.credential;
  id: string;
  iss: string;
  iss_name: string;
  sub: string;
  iat: number;
  exp: number;
  claims: string[];
  sig: string;
}

export interface Disclosure { k: string; v: string; s: string }

export interface CredentialOffer { typ: typeof TYP.offer; cred: Credential; disc: Disclosure[] }

export interface VerifierCert {
  typ: typeof TYP.verifierCert;
  name: string;
  pub: string;
  iss: string;
  iss_name: string;
  exp: number;
  sig: string;
}

export interface PrimeRequest {
  typ: typeof TYP.request;
  id: string;
  aud: string;
  aud_name: string;
  claim: string;
  nonce: string;
  iat: number;
  exp: number;
  cert?: VerifierCert;
  sig: string;
}

export interface Answer {
  typ: typeof TYP.answer;
  cred: Credential;
  disc: Disclosure;
  req: string;
  nonce: string;
  aud: string;
  sig: string;
}

export const nowSecs = () => Math.floor(Date.now() / 1000);

const CLAIM_KEY = /^[a-z][a-z0-9_]{0,31}$/;

export function checkClaimKey(k: string): void {
  if (!CLAIM_KEY.test(k)) throw new Error(`Claim key "${k}" must match ^[a-z][a-z0-9_]{0,31}$`);
}

export function checkName(s: string, what: string): void {
  if (!s.trim() || [...s].length > 64 || /[\u0000-\u001f\u007f-\u009f]/.test(s)) {
    throw new Error(`${what} must be 1-64 printable characters`);
  }
}

export function claimHash(salt: string, key: string, value: string): string {
  return sha256Hex(`${salt}:${key}:${value}`);
}

function unsigned<T extends { sig: string }>(item: T): Omit<T, "sig"> {
  const { sig: _sig, ...rest } = item;
  return rest;
}

export const toCanonicalJson = (item: unknown) => canonicalizeJson(item);

export function requestDigest(req: PrimeRequest): string {
  return sha256Hex(canonicalizeJson(req));
}

// ----------------------------------------------------------------------------- issuer

export interface IssueInput {
  issuerPriv: string;
  issuerName: string;
  holderPub: string;
  claims: Record<string, string>;
  lifetimeSecs: number;
  now?: number;
  /** Fixed salts/id for reproducible test vectors only. */
  fixed?: { id: string; salts: string[] };
}

export function issueCredential(input: IssueInput): CredentialOffer {
  const now = input.now ?? nowSecs();
  checkName(input.issuerName, "Issuer name");
  parsePublicKey(input.holderPub);
  const entries = Object.entries(input.claims);
  if (entries.length === 0 || entries.length > 32) throw new Error("A credential needs 1-32 claims");
  const disc: Disclosure[] = entries.map(([k, v], i) => {
    checkClaimKey(k);
    if ([...v].length > 128) throw new Error(`Value for ${k} is longer than 128 characters`);
    return { k, v, s: input.fixed?.salts[i] ?? randomHex(16) };
  });
  const claims = disc.map((d) => claimHash(d.s, d.k, d.v)).sort();
  const body: Omit<Credential, "sig"> = {
    typ: TYP.credential,
    id: input.fixed?.id ?? randomHex(16),
    iss: publicKeyOf(input.issuerPriv),
    iss_name: input.issuerName,
    sub: input.holderPub,
    iat: now,
    exp: now + input.lifetimeSecs,
    claims,
  };
  return { typ: TYP.offer, cred: { ...body, sig: signPayload(body, input.issuerPriv) }, disc };
}

export function certifyVerifier(issuerPriv: string, issuerName: string, verifierName: string, verifierPub: string, lifetimeSecs: number, now = nowSecs()): VerifierCert {
  checkName(verifierName, "Verifier name");
  parsePublicKey(verifierPub);
  const body: Omit<VerifierCert, "sig"> = {
    typ: TYP.verifierCert,
    name: verifierName,
    pub: verifierPub,
    iss: publicKeyOf(issuerPriv),
    iss_name: issuerName,
    exp: now + lifetimeSecs,
  };
  return { ...body, sig: signPayload(body, issuerPriv) };
}

/** Accepts the holder key QR Prime shows (JSON) or a bare compressed key. */
export function parseHolderKey(text: string): string {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) {
    const qr = JSON.parse(trimmed) as HolderKeyQr;
    if (qr.typ !== TYP.holder) throw new Error("This QR is not a PrimeID holder key");
    return parsePublicKey(qr.pub);
  }
  return parsePublicKey(trimmed);
}

// ----------------------------------------------------------------------------- verifier

export function createRequest(verifierPriv: string, verifierName: string, claim: string, cert: VerifierCert | undefined, lifetimeSecs = 300, now = nowSecs(), fixed?: { id: string; nonce: string }): PrimeRequest {
  checkClaimKey(claim);
  checkName(verifierName, "Verifier name");
  if (lifetimeSecs > MAX_REQUEST_LIFETIME_SECS) throw new Error("Request lifetime too long");
  const body: Omit<PrimeRequest, "sig"> = {
    typ: TYP.request,
    id: fixed?.id ?? randomHex(16),
    aud: publicKeyOf(verifierPriv),
    aud_name: verifierName,
    claim,
    nonce: fixed?.nonce ?? randomHex(16),
    iat: now,
    exp: now + lifetimeSecs,
    ...(cert ? { cert } : {}),
  };
  return { ...body, sig: signPayload(body, verifierPriv) };
}

export interface CheckStep { name: string; ok: boolean; detail: string }

export interface AnswerVerdict {
  ok: boolean;
  steps: CheckStep[];
  claim?: { key: string; value: string };
  issuerName?: string;
  holderPub?: string;
}

export interface VerifyContext {
  /** Requests this verifier issued and has not yet seen answered, by nonce. */
  outstanding: Map<string, PrimeRequest>;
  /** Nonces already answered: a second answer to the same nonce is a replay. */
  usedNonces: Set<string>;
  /** Issuer public keys this verifier accepts. */
  trustedIssuers: Set<string>;
  /** Credential ids the issuer has revoked (from the on-chain registry when configured). */
  isRevoked?: (issuerPub: string, credentialId: string) => Promise<boolean | null>;
  now?: number;
}

/**
 * Every check a verifier runs on an answer. Each step is reported separately so the screen can
 * show which protection stopped an attack. `ok` is true only if every step passed.
 */
export async function verifyAnswer(raw: unknown, ctx: VerifyContext): Promise<AnswerVerdict> {
  const steps: CheckStep[] = [];
  const now = ctx.now ?? nowSecs();
  const fail = (name: string, detail: string): AnswerVerdict => {
    steps.push({ name, ok: false, detail });
    return { ok: false, steps };
  };
  const pass = (name: string, detail: string) => steps.push({ name, ok: true, detail });

  const a = raw as Answer;
  if (!a || a.typ !== TYP.answer || !a.cred || !a.disc || typeof a.sig !== "string") {
    return fail("Format", "Not a PrimeID answer");
  }
  const c = a.cred;
  if (c.typ !== TYP.credential || !isHex(c.id, 16) || !Array.isArray(c.claims) || !c.claims.every((h) => isHex(h, 32))) {
    return fail("Format", "Credential fields are malformed");
  }
  pass("Format", "PrimeID answer v1");

  if (!verifyPayload(unsigned(c), c.sig, c.iss)) {
    return fail("Issuer signature", "Credential was not signed by the key it names. Forged or altered.");
  }
  if (!ctx.trustedIssuers.has(c.iss)) {
    return fail("Issuer signature", `Signature is valid, but issuer "${c.iss_name}" is not on this verifier's trusted list`);
  }
  pass("Issuer signature", `Signed by trusted issuer ${c.iss_name}`);

  if (now >= c.exp) return fail("Expiry", "Credential has expired");
  if (c.iat > now + CLOCK_SKEW_SECS) return fail("Expiry", "Credential issued in the future");
  pass("Expiry", `Valid until ${new Date(c.exp * 1000).toISOString()}`);

  if (ctx.isRevoked) {
    const revoked = await ctx.isRevoked(c.iss, c.id);
    if (revoked === null) return fail("Revocation", "Revocation registry unreachable. Refusing to accept without a revocation check.");
    if (revoked) return fail("Revocation", "Issuer has revoked this credential");
    pass("Revocation", "Not revoked (checked on ZKsync registry)");
  }

  if (!verifyPayload(unsigned(a), a.sig, c.sub)) {
    return fail("Holder binding", "Answer was not signed by the key this credential is bound to. Copied credential.");
  }
  pass("Holder binding", "Signed by the Passport the credential was issued to");

  if (!c.claims.includes(claimHash(a.disc.s, a.disc.k, a.disc.v))) {
    return fail("Selective disclosure", "Disclosed value does not match any signed claim hash");
  }
  pass("Selective disclosure", `Only "${a.disc.k}" revealed; ${c.claims.length - 1} other claim(s) stayed on the device`);

  if (ctx.usedNonces.has(a.nonce)) return fail("Replay protection", "This nonce was already answered. Replayed answer.");
  const req = ctx.outstanding.get(a.nonce);
  if (!req) return fail("Replay protection", "No outstanding request has this nonce. Old or relayed answer.");
  if (a.req !== requestDigest(req) || a.aud !== req.aud) {
    return fail("Replay protection", "Answer is bound to a different request or verifier");
  }
  if (a.disc.k !== req.claim) return fail("Replay protection", "Answer discloses a different claim than requested");
  if (now >= req.exp) return fail("Replay protection", "Request expired before the answer arrived");
  pass("Replay protection", "Fresh nonce, bound to this verifier's request");

  return {
    ok: true,
    steps,
    claim: { key: a.disc.k, value: a.disc.v },
    issuerName: c.iss_name,
    holderPub: c.sub,
  };
}
