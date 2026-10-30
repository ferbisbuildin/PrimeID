import React, { useEffect, useState } from "react";
import { type Answer, type AnswerVerdict, type PrimeRequest, type VerifierCert, createRequest, fingerprint, nowSecs, parsePublicKey, toCanonicalJson, verifyPayload } from "@core-crypto";
import type { UnlockedKey } from "../lib/keystore";
import { KEYS, TrustedIssuer, registryConfig, registryEnabled, usePersistent } from "../lib/store";
import { VerifiedExchange, outstanding, verifyAndRecord } from "../lib/verifierSession";
import { KeyUnlock } from "./KeyUnlock";
import { QrCodeDisplay } from "./QrCodeDisplay";
import { QrScanner } from "./QrScanner";
import { VerdictView } from "./VerdictView";
import { Btn, Field, Mono, Note, Section, errorText } from "./ui";

interface Props {
  verifier: UnlockedKey | null;
  setVerifier: (k: UnlockedKey | null) => void;
  onVerified: (x: VerifiedExchange) => void;
}

export const VerifierPanel: React.FC<Props> = ({ verifier, setVerifier, onVerified }) => {
  if (!verifier) return <KeyUnlock role="verifier" defaultName="Club Entry" onUnlock={setVerifier} />;
  return <UnlockedVerifier verifier={verifier} lock={() => setVerifier(null)} onVerified={onVerified} />;
};

/** Why a stored certificate cannot be attached, or "" if it is good for this verifier. */
function certProblem(cert: VerifierCert | null, verifier: UnlockedKey, trusted: TrustedIssuer[]): string {
  if (!cert) return "No certificate installed: Prime will show this verifier as unverified.";
  const { sig, ...body } = cert;
  if (!verifyPayload(body, sig, cert.iss)) return "Certificate signature is invalid.";
  if (cert.pub !== verifier.pub) return "Certificate is for a different verifier key.";
  if (cert.exp <= nowSecs()) return "Certificate has expired.";
  if (!trusted.some((t) => t.pub === cert.iss)) return `Certificate is signed by "${cert.iss_name}", which this verifier does not trust.`;
  return "";
}

const UnlockedVerifier: React.FC<{ verifier: UnlockedKey; lock: () => void; onVerified: Props["onVerified"] }> = ({ verifier, lock, onVerified }) => {
  const [trusted, setTrusted] = usePersistent<TrustedIssuer[]>(KEYS.trusted, []);
  const [cert, setCert] = usePersistent<VerifierCert | null>(KEYS.cert, null);
  const [claim, setClaim] = useState("over_18");
  const [lifetime, setLifetime] = useState(300);
  const [request, setRequest] = useState<PrimeRequest | null>(null);
  const [requestError, setRequestError] = useState("");
  const [verdict, setVerdict] = useState<AnswerVerdict | null>(null);
  const [now, setNow] = useState(nowSecs());

  useEffect(() => {
    const t = setInterval(() => setNow(nowSecs()), 1000);
    return () => clearInterval(t);
  }, []);

  const problem = certProblem(cert, verifier, trusted);

  const newRequest = () => {
    setRequestError("");
    setVerdict(null);
    try {
      // With a certificate, the request carries the certified name so Prime can match them.
      const name = problem ? verifier.name : cert!.name;
      const req = createRequest(verifier.priv, name, claim.trim(), problem ? undefined : cert!, lifetime);
      outstanding.set(req.nonce, req);
      setRequest(req);
    } catch (e) {
      setRequestError(errorText(e));
    }
  };

  const onAnswer = async (text: string) => {
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      setVerdict({ ok: false, steps: [{ name: "Format", ok: false, detail: "Scanned code is not JSON" }] });
      return;
    }
    const answered = outstanding.get((raw as Answer)?.nonce);
    const v = await verifyAndRecord(raw);
    setVerdict(v);
    if (v.ok && answered) onVerified({ answer: raw as Answer, request: answered });
  };

  const remaining = request ? request.exp - now : 0;

  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Section title="Verifier key">
        <p className="text-sm text-slate-200">{verifier.name}</p>
        <p className="text-xs text-slate-400">
          Fingerprint <Mono>{fingerprint(verifier.pub)}</Mono>
        </p>
        <p className="text-[11px] text-slate-500 break-all font-mono">{verifier.pub}</p>
        <div className="flex gap-2">
          <Btn variant="secondary" onClick={() => navigator.clipboard.writeText(verifier.pub)}>Copy public key</Btn>
          <Btn variant="secondary" onClick={lock}>Lock</Btn>
        </div>
        {problem ? <Note tone="warn">{problem}</Note> : <Note tone="ok">Certified as "{cert!.name}" by {cert!.iss_name} until {new Date(cert!.exp * 1000).toISOString().slice(0, 10)}.</Note>}
        <CertInstall onInstall={setCert} />
      </Section>

      <TrustList trusted={trusted} setTrusted={setTrusted} />

      <Section title="Proof request" step="1">
        <div className="grid grid-cols-2 gap-2">
          <Field label="Claim to prove" value={claim} onChange={(e) => setClaim(e.target.value)} />
          <label className="block">
            <span className="block text-xs text-slate-400 mb-1">Expires after</span>
            <select value={lifetime} onChange={(e) => setLifetime(Number(e.target.value))} className="w-full bg-[#07090C] border border-foundation-border rounded-lg px-3 py-2 text-sm">
              <option value={120}>2 minutes</option>
              <option value={300}>5 minutes</option>
              <option value={600}>10 minutes</option>
            </select>
          </label>
        </div>
        <Btn onClick={newRequest}>Create signed request</Btn>
        {requestError && <Note tone="bad">{requestError}</Note>}
        {request && (
          <>
            <QrCodeDisplay text={toCanonicalJson(request)} caption="On Prime: Scan QR, review the requester, Approve." downloadName="primeid-request.json" />
            <p className={`text-xs text-center ${remaining > 0 ? "text-slate-400" : "text-rose-400"}`}>
              {remaining > 0 ? `Expires in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}` : "Expired: create a new request"}
            </p>
          </>
        )}
      </Section>

      <Section title="Answer from Prime" step="2">
        <p className="text-xs text-slate-500">
          {registryEnabled ? `Revocation checked live on ZKsync (${registryConfig.address.slice(0, 10)}...).` : "Revocation not configured; that step is skipped and shown as SKIP."}
        </p>
        <QrScanner hint="the signed answer QR on Passport Prime" onResult={onAnswer} />
        {verdict && <VerdictView verdict={verdict} />}
      </Section>
    </div>
  );
};

const CertInstall: React.FC<{ onInstall: (c: VerifierCert) => void }> = ({ onInstall }) => {
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  return (
    <details className="text-xs text-slate-400">
      <summary className="cursor-pointer">Install a certificate from an issuer</summary>
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3} className="mt-2 w-full bg-[#07090C] border border-foundation-border rounded-lg p-2 font-mono text-[11px] text-slate-200" />
      <Btn
        variant="secondary"
        className="mt-2"
        onClick={() => {
          try {
            const c = JSON.parse(text) as VerifierCert;
            if (c.typ !== "primeid/verifier-cert/v1") throw new Error("Not a PrimeID verifier certificate");
            onInstall(c);
            setText("");
            setError("");
          } catch (e) {
            setError(errorText(e));
          }
        }}
      >
        Install
      </Btn>
      {error && <Note tone="bad">{error}</Note>}
    </details>
  );
};

const TrustList: React.FC<{ trusted: TrustedIssuer[]; setTrusted: (f: (p: TrustedIssuer[]) => TrustedIssuer[]) => void }> = ({ trusted, setTrusted }) => {
  const [pub, setPub] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const add = () => {
    try {
      const key = parsePublicKey(pub.trim().toLowerCase());
      setTrusted((p) => (p.some((t) => t.pub === key) ? p : [...p, { pub: key, name: name.trim() || "Issuer" }]));
      setPub("");
      setName("");
      setError("");
    } catch (e) {
      setError(errorText(e));
    }
  };
  return (
    <Section title="Trusted issuers">
      <p className="text-xs text-slate-400">Answers are accepted only for credentials signed by these keys.</p>
      {trusted.length === 0 && <Note tone="warn">No trusted issuers yet. Every answer will be rejected.</Note>}
      {trusted.map((t) => (
        <div key={t.pub} className="flex items-center gap-3 text-xs">
          <span className="text-slate-200">{t.name}</span>
          <Mono>{fingerprint(t.pub)}</Mono>
          <Btn variant="secondary" className="ml-auto" onClick={() => setTrusted((p) => p.filter((x) => x.pub !== t.pub))}>Remove</Btn>
        </div>
      ))}
      <div className="grid grid-cols-[1fr_2fr_auto] gap-2 items-end">
        <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <Field label="Issuer public key (hex)" value={pub} onChange={(e) => setPub(e.target.value)} />
        <Btn variant="secondary" disabled={!pub.trim()} onClick={add}>Add</Btn>
      </div>
      {error && <Note tone="bad">{error}</Note>}
    </Section>
  );
};
