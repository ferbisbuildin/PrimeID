/**
 * Cross-language test vectors and the four-attack suite for the verifier.
 * Run: npm test   (writes crates/primeid-core/tests/vectors.json, which the Rust tests read back)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { canonicalizeJson } from "./canonical";
import { holderPrivateKeyFromAppSeed, publicKeyOf, signPayload } from "./crypto";
import {
  Answer, CredentialOffer, PrimeRequest, TYP, certifyVerifier, createRequest, issueCredential, requestDigest, verifyAnswer,
} from "./protocol";

const NOW = 1_793_000_000;
const ISSUER = "11".repeat(32);
const VERIFIER = "22".repeat(32);
const APP_SEED = "07".repeat(32);

/** The device-side answer builder, reimplemented here only to produce the expected vector. */
function buildAnswer(holderPriv: string, offer: CredentialOffer, req: PrimeRequest): Answer {
  const disc = offer.disc.find((d) => d.k === req.claim)!;
  const body = { typ: TYP.answer, cred: offer.cred, disc, req: requestDigest(req), nonce: req.nonce, aud: req.aud };
  return { ...body, sig: signPayload(body, holderPriv) };
}

const holderPriv = holderPrivateKeyFromAppSeed(APP_SEED);
const holderPub = publicKeyOf(holderPriv);
const offer = issueCredential({
  issuerPriv: ISSUER,
  issuerName: "Demo Issuer",
  holderPub,
  claims: { over_18: "true", country: "IN", name: "Asha \"A\" Rao\n" },
  lifetimeSecs: 86_400,
  now: NOW - 60,
  fixed: { id: "00112233445566778899aabbccddeeff", salts: ["0a".repeat(16), "0b".repeat(16), "0c".repeat(16)] },
});
const cert = certifyVerifier(ISSUER, "Demo Issuer", "Club Entry", publicKeyOf(VERIFIER), 86_400, NOW);
const req = createRequest(VERIFIER, "Club Entry", "over_18", cert, 300, NOW - 5, {
  id: "ffeeddccbbaa99887766554433221100",
  nonce: "0123456789abcdef0123456789abcdef",
});
const answer = buildAnswer(holderPriv, offer, req);

const ctx = () => ({
  outstanding: new Map([[req.nonce, req]]),
  usedNonces: new Set<string>(),
  trustedIssuers: new Set([publicKeyOf(ISSUER)]),
  now: NOW,
});

test("writes vectors for the Rust device code", () => {
  const out = fileURLToPath(new URL("../../crates/primeid-core/tests/vectors.json", import.meta.url));
  writeFileSync(out, JSON.stringify({ now: NOW, app_seed: APP_SEED, holder_pub: holderPub, offer, request: req, answer_canonical: canonicalizeJson(answer) }, null, 2) + "\n");
});

test("honest answer verifies", async () => {
  const v = await verifyAnswer(answer, ctx());
  assert.equal(v.ok, true, JSON.stringify(v.steps));
  assert.deepEqual(v.claim, { key: "over_18", value: "true" });
});

test("attack 1: forged credential (AI fake ID) fails the issuer check", async () => {
  const forger = "33".repeat(32);
  const fake = issueCredential({ issuerPriv: forger, issuerName: "Demo Issuer", holderPub, claims: { over_18: "true" }, lifetimeSecs: 86_400, now: NOW - 60 });
  const selfSigned = await verifyAnswer(buildAnswer(holderPriv, fake, req), ctx());
  assert.equal(selfSigned.ok, false);
  assert.equal(selfSigned.steps.at(-1)!.name, "Issuer signature");
  const renamed = { ...answer, cred: { ...answer.cred, iss: publicKeyOf(ISSUER), sig: fake.cred.sig } };
  assert.equal((await verifyAnswer(renamed, ctx())).steps.at(-1)!.name, "Issuer signature");
});

test("attack 2: copied credential fails holder binding", async () => {
  const thief = "44".repeat(32);
  const { sig: _s, ...body } = answer;
  const v = await verifyAnswer({ ...body, sig: signPayload(body, thief) }, ctx());
  assert.equal(v.ok, false);
  assert.equal(v.steps.at(-1)!.name, "Holder binding");
});

test("attack 3: replayed answer fails the nonce check", async () => {
  const c = ctx();
  assert.equal((await verifyAnswer(answer, c)).ok, true);
  c.usedNonces.add(answer.nonce);
  c.outstanding.delete(answer.nonce);
  const v = await verifyAnswer(answer, c);
  assert.equal(v.ok, false);
  assert.equal(v.steps.at(-1)!.name, "Replay protection");
});

test("tampered disclosure fails", async () => {
  const v = await verifyAnswer({ ...answer, disc: { ...answer.disc, v: "false" } }, ctx());
  assert.equal(v.ok, false);
});

test("revocation is enforced when a registry is configured", async () => {
  const revoked = await verifyAnswer(answer, { ...ctx(), isRevoked: async () => true });
  assert.equal(revoked.steps.at(-1)!.name, "Revocation");
  const unreachable = await verifyAnswer(answer, { ...ctx(), isRevoked: async () => null });
  assert.equal(unreachable.ok, false);
});
