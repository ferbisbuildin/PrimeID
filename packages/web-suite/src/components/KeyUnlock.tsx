import React, { useState } from "react";
import { fingerprint } from "@core-crypto";
import { Role, UnlockedKey, createKeystore, deleteKeystore, readKeystore, unlockKeystore } from "../lib/keystore";
import { Btn, Field, Note, Section, errorText } from "./ui";

interface Props {
  role: Role;
  defaultName: string;
  onUnlock: (key: UnlockedKey) => void;
}

export const KeyUnlock: React.FC<Props> = ({ role, defaultName, onUnlock }) => {
  const [rec, setRec] = useState(() => readKeystore(role));
  const [name, setName] = useState(defaultName);
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const run = async (fn: () => Promise<UnlockedKey>) => {
    setBusy(true);
    setError("");
    try {
      const key = await fn();
      setPass("");
      setConfirm("");
      onUnlock(key);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const forget = () => {
    if (!window.confirm(`Delete the stored ${role} key? Anything it signed can no longer be extended, and Prime will see a new ${role} key.`)) return;
    deleteKeystore(role);
    setRec(null);
  };

  if (rec) {
    return (
      <Section title={`Unlock ${role} key`}>
        <p className="text-sm text-slate-300">
          {rec.name} <span className="text-slate-500 font-mono ml-2">{fingerprint(rec.pub)}</span>
        </p>
        <form onSubmit={(e) => { e.preventDefault(); run(() => unlockKeystore(role, pass)); }} className="space-y-3">
          <Field label="Passphrase" type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} />
          <div className="flex gap-2">
            <Btn type="submit" disabled={busy || !pass}>{busy ? "Decrypting..." : "Unlock"}</Btn>
            <Btn type="button" variant="secondary" onClick={forget}>Forget key</Btn>
          </div>
        </form>
        {error && <Note tone="bad">{error}</Note>}
      </Section>
    );
  }

  return (
    <Section title={`Create ${role} key`}>
      <Note>
        A new secp256k1 key is generated in this browser. Only an encrypted copy is saved (PBKDF2 + AES-GCM); the passphrase is
        never stored. Lose the passphrase and you lose the key.
      </Note>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (pass !== confirm) return setError("Passphrases do not match");
          run(() => createKeystore(role, name.trim(), pass));
        }}
        className="space-y-3"
      >
        <Field label={role === "issuer" ? "Issuer name (shown on Prime)" : "Verifier name (shown on Prime)"} value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
        <Field label="Passphrase (10+ characters)" type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />
        <Field label="Confirm passphrase" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        <Btn type="submit" disabled={busy || !name.trim() || !pass}>{busy ? "Creating..." : "Create key"}</Btn>
      </form>
      {error && <Note tone="bad">{error}</Note>}
    </Section>
  );
};
