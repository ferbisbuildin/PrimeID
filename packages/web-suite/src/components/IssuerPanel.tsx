import React, { useState } from "react";
import { certifyVerifier, ethAddressOf, fingerprint, issueCredential, parseHolderKey, toCanonicalJson } from "@core-crypto";
import type { UnlockedKey } from "../lib/keystore";
import { readKeystore } from "../lib/keystore";
import { IssuedRecord, KEYS, TrustedIssuer, registryConfig, registryEnabled, save, usePersistent } from "../lib/store";
import { relayRevocation, walletAvailable } from "../lib/wallet";
import { KeyUnlock } from "./KeyUnlock";
import { QrCodeDisplay } from "./QrCodeDisplay";
import { QrScanner } from "./QrScanner";
import { Btn, Field, Mono, Note, Section, errorText } from "./ui";

const DEFAULT_CLAIMS: [string, string][] = [
  ["over_18", "true"],
  ["country", "IN"],
  ["full_name", ""],
  ["date_of_birth", ""],
];

export const IssuerPanel: React.FC<{ issuer: UnlockedKey | null; setIssuer: (k: UnlockedKey | null) => void }> = ({ issuer, setIssuer }) => {
  if (!issuer) return <KeyUnlock role="issuer" defaultName="Demo ID Authority" onUnlock={setIssuer} />;
  return <UnlockedIssuer issuer={issuer} lock={() => setIssuer(null)} />;
};

const UnlockedIssuer: React.FC<{ issuer: UnlockedKey; lock: () => void }> = ({ issuer, lock }) => {
  const [holderPub, setHolderPub] = useState("");
  const [holderError, setHolderError] = useState("");
  const [claims, setClaims] = useState<[string, string][]>(DEFAULT_CLAIMS);
  const [days, setDays] = useState(365);
  const [offer, setOffer] = useState("");
  const [issueError, setIssueError] = useState("");
  const [issued, setIssued] = usePersistent<IssuedRecord[]>(KEYS.issued, []);
  const [trusted, setTrusted] = usePersistent<TrustedIssuer[]>(KEYS.trusted, []);

  const trustedHere = trusted.some((t) => t.pub === issuer.pub);

  const scanHolder = (text: string) => {
    setHolderError("");
    setOffer("");
    try {
      setHolderPub(parseHolderKey(text));
    } catch (e) {
      setHolderError(errorText(e));
    }
  };

  const issue = () => {
    setIssueError("");
    try {
      const filled = Object.fromEntries(claims.filter(([k, v]) => k.trim() && v.trim()).map(([k, v]) => [k.trim(), v.trim()]));
      const o = issueCredential({ issuerPriv: issuer.priv, issuerName: issuer.name, holderPub, claims: filled, lifetimeSecs: days * 86_400 });
      setOffer(toCanonicalJson(o));
      // Only the id, holder key and claim names are kept; values exist only on the holder's Prime.
      setIssued((prev) => [{ id: o.cred.id, issuer: issuer.pub, holderPub, claimKeys: Object.keys(filled), iat: o.cred.iat, exp: o.cred.exp }, ...prev].slice(0, 200));
    } catch (e) {
      setIssueError(errorText(e));
    }
  };

  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Section title="Issuer key">
        <p className="text-sm text-slate-200">{issuer.name}</p>
        <p className="text-xs text-slate-400">
          Fingerprint <Mono>{fingerprint(issuer.pub)}</Mono>
        </p>
        <p className="text-xs text-slate-400">Prime shows this fingerprint the first time it sees a credential from you. Read it out to the holder.</p>
        {registryEnabled && (
          <p className="text-xs text-slate-500">
            Registry identity <Mono>{ethAddressOf(issuer.pub)}</Mono>
          </p>
        )}
        <div className="flex gap-2 flex-wrap">
          <Btn variant="secondary" disabled={trustedHere} onClick={() => setTrusted((p) => [...p, { pub: issuer.pub, name: issuer.name }])}>
            {trustedHere ? "Trusted by this browser's verifier" : "Trust in this browser's verifier"}
          </Btn>
          <Btn variant="secondary" onClick={lock}>Lock</Btn>
        </div>
      </Section>

      <Section title="Holder key" step="1">
        {holderPub ? (
          <>
            <Note tone="ok">
              Holder key <Mono>{fingerprint(holderPub)}</Mono>. Check it matches the fingerprint on the Prime screen.
            </Note>
            <Btn variant="secondary" onClick={() => { setHolderPub(""); setOffer(""); }}>Scan a different holder</Btn>
          </>
        ) : (
          <QrScanner hint={'the "Show my holder key" QR on Passport Prime'} onResult={scanHolder} />
        )}
        {holderError && <Note tone="bad">{holderError}</Note>}
      </Section>

      <Section title="Claims" step="2">
        <p className="text-xs text-slate-400">Each claim is salted and hashed separately, so the holder can later prove one without revealing the rest. Empty rows are skipped.</p>
        {claims.map(([k, v], i) => (
          <div key={i} className="grid grid-cols-[1fr_1.4fr_auto] gap-2 items-end">
            <Field label="Claim" value={k} onChange={(e) => setClaims(claims.map((c, j) => (j === i ? [e.target.value, c[1]] : c)))} />
            <Field label="Value" value={v} onChange={(e) => setClaims(claims.map((c, j) => (j === i ? [c[0], e.target.value] : c)))} />
            <Btn variant="secondary" onClick={() => setClaims(claims.filter((_, j) => j !== i))} aria-label="Remove claim">x</Btn>
          </div>
        ))}
        <div className="flex gap-2 items-end">
          <Btn variant="secondary" onClick={() => setClaims([...claims, ["", ""]])}>Add claim</Btn>
          <Field label="Valid for (days)" type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Math.max(1, Number(e.target.value) || 1))} />
        </div>
        <Btn disabled={!holderPub} onClick={issue}>Sign credential</Btn>
        {!holderPub && <p className="text-xs text-slate-500">Scan the holder key first: the credential is bound to that Prime.</p>}
        {issueError && <Note tone="bad">{issueError}</Note>}
      </Section>

      <Section title="Credential offer" step="3">
        {offer ? (
          <QrCodeDisplay text={offer} caption='On Prime: Scan QR, check the issuer fingerprint, then "Trust issuer and save".' downloadName="primeid-offer.json" />
        ) : (
          <p className="text-xs text-slate-500">The signed offer appears here.</p>
        )}
      </Section>

      <CertifyVerifier issuer={issuer} />
      <IssuedList issuer={issuer} issued={issued} setIssued={setIssued} />
    </div>
  );
};

const CertifyVerifier: React.FC<{ issuer: UnlockedKey }> = ({ issuer }) => {
  const local = readKeystore("verifier");
  const [name, setName] = useState(local?.name ?? "");
  const [pub, setPub] = useState(local?.pub ?? "");
  const [cert, setCert] = useState("");
  const [error, setError] = useState("");
  const [installed, setInstalled] = useState(false);

  const sign = () => {
    setError("");
    setInstalled(false);
    try {
      setCert(toCanonicalJson(certifyVerifier(issuer.priv, issuer.name, name.trim(), pub.trim().toLowerCase(), 30 * 86_400)));
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <Section title="Certify a verifier">
      <p className="text-xs text-slate-400">
        Prime shows a green "Verified requester" badge only for requests from a verifier certified by an issuer it trusts. Valid 30 days.
      </p>
      <Field label="Verifier name (must match the verifier's name)" value={name} onChange={(e) => setName(e.target.value)} />
      <Field label="Verifier public key (hex)" value={pub} onChange={(e) => setPub(e.target.value)} />
      <Btn disabled={!name.trim() || !pub.trim()} onClick={sign}>Sign certificate</Btn>
      {error && <Note tone="bad">{error}</Note>}
      {cert && (
        <>
          <textarea readOnly value={cert} rows={4} className="w-full bg-[#07090C] border border-foundation-border rounded-lg p-2 font-mono text-[11px] text-slate-300" />
          <div className="flex gap-2">
            <Btn variant="secondary" onClick={() => navigator.clipboard.writeText(cert)}>Copy</Btn>
            {local && local.pub === JSON.parse(cert).pub && (
              <Btn variant="secondary" onClick={() => { save(KEYS.cert, JSON.parse(cert)); setInstalled(true); }}>
                {installed ? "Installed" : "Install in this browser's verifier"}
              </Btn>
            )}
          </div>
        </>
      )}
    </Section>
  );
};

const IssuedList: React.FC<{ issuer: UnlockedKey; issued: IssuedRecord[]; setIssued: (f: (p: IssuedRecord[]) => IssuedRecord[]) => void }> = ({ issuer, issued, setIssued }) => {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const update = (id: string, patch: Partial<IssuedRecord>) => setIssued((p) => p.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  const revoke = async (id: string) => {
    setError("");
    setBusy(id);
    try {
      const ok = await relayRevocation(issuer.priv, id, (hash) => update(id, { revokeTx: hash }));
      if (!ok) throw new Error("Transaction reverted; the credential is NOT revoked");
      update(id, { revoked: true });
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy("");
    }
  };

  const mine = issued.filter((r) => r.issuer === issuer.pub);
  return (
    <Section title="Issued credentials" className="lg:col-span-2">
      {!registryEnabled && (
        <Note tone="warn">Revocation is off: set VITE_PRIMEID_REGISTRY to a deployed PrimeIdRevocationRegistry address (see contracts/README.md).</Note>
      )}
      {registryEnabled && !walletAvailable() && <Note tone="warn">Revoking needs a browser wallet on ZKsync Sepolia to pay gas.</Note>}
      {mine.length === 0 && <p className="text-xs text-slate-500">Nothing issued from this browser yet.</p>}
      <div className="divide-y divide-foundation-border">
        {mine.map((r) => (
          <div key={r.id} className="py-2 flex flex-wrap items-center gap-3 text-xs">
            <span className="font-mono text-slate-300">{r.id.slice(0, 12)}...</span>
            <span className="text-slate-400">holder {fingerprint(r.holderPub)}</span>
            <span className="text-slate-400">{r.claimKeys.join(", ")}</span>
            <span className="text-slate-500">until {new Date(r.exp * 1000).toISOString().slice(0, 10)}</span>
            {r.revokeTx && (
              <a className="text-cyan-400 underline" href={`${registryConfig.explorer}/tx/${r.revokeTx}`} target="_blank" rel="noreferrer">
                tx
              </a>
            )}
            <span className="ml-auto">
              {r.revoked ? (
                <span className="text-rose-400 font-semibold">Revoked on chain</span>
              ) : (
                <Btn variant="danger" disabled={!registryEnabled || !walletAvailable() || !!busy} onClick={() => revoke(r.id)}>
                  {busy === r.id ? "Waiting for ZKsync..." : "Revoke"}
                </Btn>
              )}
            </span>
          </div>
        ))}
      </div>
      {error && <Note tone="bad">{error}</Note>}
    </Section>
  );
};
