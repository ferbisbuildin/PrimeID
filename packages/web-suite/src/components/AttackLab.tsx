import React, { useState } from "react";
import {
  type Answer, type AnswerVerdict, type VerifyContext, buildAnswerSoftware, createRequest, issueCredential, newPrivateKey, publicKeyOf, signPayload, verifyAnswer,
} from "@core-crypto";
import { VerifiedExchange, verifierContext } from "../lib/verifierSession";
import { VerdictView } from "./VerdictView";
import { Btn, Note, Section } from "./ui";

interface Result { title: string; expect: "accept" | "reject"; story: string; verdict: AnswerVerdict }

const resign = (a: Answer, priv: string): Answer => {
  const { sig: _s, ...body } = a;
  return { ...body, sig: signPayload(body, priv) };
};

/** Every attack runs through the same verifyAnswer the Verifier tab uses. */
async function labRun(): Promise<Result[]> {
  // Lab keys are generated fresh in this tab. The "holder" here is software, not a Passport.
  const issuer = newPrivateKey();
  const holder = newPrivateKey();
  const verifier = newPrivateKey();
  const offer = issueCredential({
    issuerPriv: issuer, issuerName: "Lab ID Authority", holderPub: publicKeyOf(holder),
    claims: { over_18: "true", full_name: "Asha Rao", date_of_birth: "1999-04-12" }, lifetimeSecs: 86_400,
  });
  const req = createRequest(verifier, "Lab Club", "over_18", undefined, 300);
  const disc = offer.disc.find((d) => d.k === "over_18")!;
  const honest = buildAnswerSoftware(holder, offer.cred, disc, req);
  const ctx = (): VerifyContext => ({ outstanding: new Map([[req.nonce, req]]), usedNonces: new Set(), trustedIssuers: new Set([publicKeyOf(issuer)]) });

  const forger = newPrivateKey();
  const fake = issueCredential({ issuerPriv: forger, issuerName: "Lab ID Authority", holderPub: publicKeyOf(holder), claims: { over_18: "true" }, lifetimeSecs: 86_400 });
  const replayCtx = ctx();
  replayCtx.usedNonces.add(req.nonce);
  replayCtx.outstanding.clear();
  const otherReq = createRequest(newPrivateKey(), "Other Venue", "over_18", undefined, 300);

  return [
    { title: "Honest answer", expect: "accept", story: "The holder approves on the device. Only over_18 is revealed.", verdict: await verifyAnswer(honest, ctx()) },
    {
      title: "Forged ID (AI-generated)", expect: "reject",
      story: "An attacker mints a perfect-looking credential with the same issuer name but their own key.",
      verdict: await verifyAnswer(buildAnswerSoftware(holder, fake.cred, fake.disc[0], req), ctx()),
    },
    { title: "Stolen credential", expect: "reject", story: "A thief copies the credential and signs the answer with their own key.", verdict: await verifyAnswer(resign(honest, newPrivateKey()), ctx()) },
    { title: "Edited value", expect: "reject", story: 'Someone changes the revealed value in transit ("true" to "false").', verdict: await verifyAnswer({ ...honest, disc: { ...honest.disc, v: "false" } }, ctx()) },
    { title: "Replay", expect: "reject", story: "Yesterday's accepted answer is shown again.", verdict: await verifyAnswer(honest, replayCtx) },
    {
      title: "Relay to another verifier", expect: "reject",
      story: "A rogue venue forwards an answer it received to a different verifier.",
      verdict: await verifyAnswer(honest, { ...ctx(), outstanding: new Map([[otherReq.nonce, otherReq]]) }),
    },
  ];
}

async function liveRun(x: VerifiedExchange): Promise<Result[]> {
  const ctx = verifierContext();
  const { sig: _s, ...credBody } = x.answer.cred;
  const forgedCred = { ...x.answer.cred, sig: signPayload(credBody, newPrivateKey()) };
  return [
    { title: "Replay the real answer", expect: "reject", story: "The answer Prime just produced, submitted a second time.", verdict: await verifyAnswer(x.answer, ctx) },
    { title: "Thief re-signs it", expect: "reject", story: "Same credential, answer signed by a key that is not this Prime's.", verdict: await verifyAnswer(resign(x.answer, newPrivateKey()), ctx) },
    { title: "Edit the revealed value", expect: "reject", story: "Flip the disclosed value.", verdict: await verifyAnswer({ ...x.answer, disc: { ...x.answer.disc, v: x.answer.disc.v + "x" } }, ctx) },
    { title: "Re-sign the credential", expect: "reject", story: "Swap the issuer signature for one from a forger's key.", verdict: await verifyAnswer({ ...x.answer, cred: forgedCred }, ctx) },
  ];
}

const ResultCard: React.FC<{ r: Result }> = ({ r }) => {
  const correct = (r.expect === "accept") === r.verdict.ok;
  return (
    <div className="border border-foundation-border rounded-xl p-4 space-y-2 bg-[#0D1016]">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-semibold text-slate-100">{r.title}</h3>
        <span className={`ml-auto text-[11px] font-mono ${correct ? "text-emerald-400" : "text-rose-400"}`}>
          {correct ? (r.verdict.ok ? "accepted, as expected" : "blocked, as expected") : "UNEXPECTED"}
        </span>
      </div>
      <p className="text-xs text-slate-400">{r.story}</p>
      <VerdictView verdict={r.verdict} />
    </div>
  );
};

export const AttackLab: React.FC<{ lastReal: VerifiedExchange | null }> = ({ lastReal }) => {
  const [lab, setLab] = useState<Result[] | null>(null);
  const [live, setLive] = useState<Result[] | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<Result[]>, set: (r: Result[]) => void) => {
    setBusy(true);
    try {
      set(await fn());
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <Section title="Attacks on your last real Prime answer">
        {lastReal ? (
          <>
            <p className="text-xs text-slate-400">
              Uses the answer the Verifier tab accepted from Passport Prime ({lastReal.answer.disc.k}), against the same verifier state.
            </p>
            <Btn disabled={busy} onClick={() => run(() => liveRun(lastReal), setLive)}>Run attacks on it</Btn>
            {live && <div className="grid gap-3 lg:grid-cols-2">{live.map((r) => <ResultCard key={r.title} r={r} />)}</div>}
          </>
        ) : (
          <Note>Verify one real answer from Prime in the Verifier tab first. Then each attack here starts from that real answer.</Note>
        )}
      </Section>

      <Section title="Self-contained lab">
        <Note tone="warn">
          This lab generates throwaway issuer, verifier and holder keys in this tab. Its holder is software, not a Passport, so the lab
          runs without a device. Only the attacks above use a real Prime answer.
        </Note>
        <Btn disabled={busy} onClick={() => run(labRun, setLab)}>Run all six</Btn>
        {lab && <div className="grid gap-3 lg:grid-cols-2">{lab.map((r) => <ResultCard key={r.title} r={r} />)}</div>}
      </Section>
    </div>
  );
};
