import React, { useState } from "react";
import { clsx } from "clsx";
import type { UnlockedKey } from "./lib/keystore";
import type { VerifiedExchange } from "./lib/verifierSession";
import { registryConfig, registryEnabled } from "./lib/store";
import { IssuerPanel } from "./components/IssuerPanel";
import { VerifierPanel } from "./components/VerifierPanel";
import { AttackLab } from "./components/AttackLab";

type Tab = "issuer" | "verifier" | "lab" | "how";

const TABS: { id: Tab; label: string }[] = [
  { id: "issuer", label: "Issuer" },
  { id: "verifier", label: "Verifier" },
  { id: "lab", label: "Attack Lab" },
  { id: "how", label: "How it works" },
];

export const App: React.FC = () => {
  const [tab, setTab] = useState<Tab>("issuer");
  // Decrypted keys live only in memory for this tab; reloading locks them again.
  const [issuer, setIssuer] = useState<UnlockedKey | null>(null);
  const [verifier, setVerifier] = useState<UnlockedKey | null>(null);
  const [lastReal, setLastReal] = useState<VerifiedExchange | null>(null);

  return (
    <div className="max-w-6xl mx-auto px-4 py-6 space-y-6">
      <header className="flex flex-wrap items-end gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foundation-gold">PrimeID</h1>
          <p className="text-sm text-slate-400">Prove the fact, keep the document. Credentials live on Passport Prime; only the approved fact leaves it.</p>
        </div>
        <span className="ml-auto text-[11px] font-mono text-slate-500">
          revocation: {registryEnabled ? `ZKsync chain ${registryConfig.chainId}` : "not configured"}
        </span>
      </header>

      <nav className="flex gap-1 border-b border-foundation-border">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={clsx(
              "px-4 py-2 text-sm font-semibold border-b-2 -mb-px",
              tab === t.id ? "border-foundation-gold text-foundation-gold" : "border-transparent text-slate-400 hover:text-slate-200",
            )}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "issuer" && <IssuerPanel issuer={issuer} setIssuer={setIssuer} />}
      {tab === "verifier" && <VerifierPanel verifier={verifier} setVerifier={setVerifier} onVerified={setLastReal} />}
      {tab === "lab" && <AttackLab lastReal={lastReal} />}
      {tab === "how" && <HowItWorks />}
    </div>
  );
};

const HowItWorks: React.FC = () => (
  <div className="grid gap-4 md:grid-cols-2 text-sm text-slate-300">
    {[
      ["1. Holder key", "Prime derives a holder key from its secure-element app seed (KeyOS GetAppSeed). The issuer scans only the public key."],
      ["2. Issue", "The issuer salts and hashes every claim separately, signs the list, and binds it to that holder key. Prime verifies the signature and asks the user to trust the issuer's fingerprint once."],
      ["3. Store", "Prime keeps the credential in an AES-256-GCM vault in its app data, keyed from the same app seed. It never leaves the device."],
      ["4. Request", "A verifier signs a request for one claim with a fresh nonce and a short expiry. Prime shows who is asking (green if an issuer it trusts certified them), what will be shared, and what stays on the device."],
      ["5. Answer", "On approval Prime signs an answer that reveals one claim and its salt, bound to that request and nonce. It refuses to sign the same nonce twice."],
      ["6. Verify", "The verifier checks issuer signature and trust, expiry, revocation on ZKsync if configured, holder binding, the claim hash, and replay. The Attack Lab shows each check stopping an attack."],
    ].map(([title, body]) => (
      <div key={title} className="bg-foundation-card border border-foundation-border rounded-2xl p-4">
        <h3 className="font-semibold text-foundation-gold mb-1">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed">{body}</p>
      </div>
    ))}
  </div>
);
