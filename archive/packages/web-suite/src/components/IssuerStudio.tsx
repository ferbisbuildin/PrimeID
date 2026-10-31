import React, { useState } from "react";
import {
  Building2,
  Award,
  Coins,
  Plus,
  Trash2,
  Key,
  Radio,
  FileCheck2,
  AlertTriangle,
  Ban,
  Sparkles,
} from "lucide-react";
import {
  generateRandomKeyPair,
  KeyPair,
  signCanonicalObject,
} from "@core-crypto/secp256k1";
import { createSaltedClaims } from "@core-crypto/salted-hash-tree";
import {
  CredentialPayload,
  CredentialIssuancePackage,
  RevocationList,
} from "@core-crypto/schemas";
import { createRevocationList } from "@core-crypto/revocation";
import { QrCodeDisplay } from "./QrCodeDisplay";
import jsQR from "jsqr";
import { loadOrCreateKey, saveKey, trustCard } from "../demoKeys";

interface IssuerStudioProps {
  deviceHolderPubKey: string;
  onBeamCredentialToDevice?: (pkg: CredentialIssuancePackage) => void;
  onPublishRevocationList?: (crl: RevocationList) => void;
  compact?: boolean;
}

interface ClaimItem {
  id: string;
  key: string;
  value: string;
}

const PRESET_TEMPLATES = [
  {
    id: "gov_id",
    name: "Government National ID",
    icon: Building2,
    issuerName: "Global Identity Authority (G7 DPA Pilot)",
    claims: [
      { id: "1", key: "over_18", value: "true" },
      { id: "2", key: "country", value: "US" },
      { id: "3", key: "name", value: "Alice Vance" },
      { id: "4", key: "doc_number", value: "A9823104" },
      { id: "5", key: "dob", value: "1994-04-12" },
    ],
  },
  {
    id: "university",
    name: "Stanford Student ID",
    icon: Award,
    issuerName: "Stanford University Registrar",
    claims: [
      { id: "1", key: "enrolled_student", value: "true" },
      { id: "2", key: "university", value: "Stanford" },
      { id: "3", key: "degree", value: "B.S. CS" },
      { id: "4", key: "grad_year", value: "2027" },
      { id: "5", key: "student_id", value: "0892348" },
    ],
  },
  {
    id: "exchange_kyc",
    name: "Apex Exchange Compliance",
    icon: Coins,
    issuerName: "Apex Exchange Compliance Authority",
    claims: [
      { id: "1", key: "verified_adult", value: "true" },
      { id: "2", key: "restricted_region", value: "false" },
      { id: "3", key: "kyc_tier", value: "2" },
      { id: "4", key: "sanctions_clean", value: "true" },
    ],
  },
];

export const IssuerStudio: React.FC<IssuerStudioProps> = ({
  deviceHolderPubKey,
  onBeamCredentialToDevice,
  onPublishRevocationList,
  compact = false,
}) => {
  // Deterministic or generated issuer keypair
  const [issuerKeypair, setIssuerKeypair] = useState<KeyPair>(() => loadOrCreateKey("primeid.issuer"));
  const [issuerName, setIssuerName] = useState<string>("Global Identity Authority");
  const [holderPubKeyInput, setHolderPubKeyInput] = useState<string>(deviceHolderPubKey);
  const [claimsList, setClaimsList] = useState<ClaimItem[]>(PRESET_TEMPLATES[0].claims);
  const [expiryDays, setExpiryDays] = useState<number>(365);

  // Output issuance package
  const [issuedPackage, setIssuedPackage] = useState<CredentialIssuancePackage | null>(null);

  // Revocation list state
  const [revokedCredIds, setRevokedCredIds] = useState<string[]>([]);
  const [activeCrl, setActiveCrl] = useState<RevocationList | null>(null);

  // Sync with device key if device changes
  React.useEffect(() => {
    if (deviceHolderPubKey) {
      setHolderPubKeyInput(deviceHolderPubKey);
    }
  }, [deviceHolderPubKey]);

  const handleSelectTemplate = (templateId: string) => {
    const tpl = PRESET_TEMPLATES.find((t) => t.id === templateId);
    if (tpl) {
      setIssuerName(tpl.issuerName);
      setClaimsList(tpl.claims);
    }
  };

  const handleAddClaim = () => {
    setClaimsList((prev) => [
      ...prev,
      { id: Math.random().toString(), key: "custom_claim", value: "true" },
    ]);
  };

  const handleRemoveClaim = (id: string) => {
    setClaimsList((prev) => prev.filter((c) => c.id !== id));
  };

  const handleUpdateClaim = (id: string, key: string, value: string) => {
    setClaimsList((prev) => prev.map((c) => (c.id === id ? { ...c, key, value } : c)));
  };

  /**
   * ISSUE CREDENTIAL (Step 2)
   * Real secp256k1 + SHA-256 salted hash tree generation
   */
  const handleIssueCredential = () => {
    if (!holderPubKeyInput.trim()) {
      alert("Please provide the Passport Prime Holder Public Key.");
      return;
    }

    // 1. Build claims dictionary
    const claimsObj: Record<string, string> = {};
    for (const c of claimsList) {
      if (c.key.trim()) {
        claimsObj[c.key.trim()] = c.value.trim();
      }
    }

    // 2. Generate salts and SHA-256 salted hashes
    const { disclosures, claimHashes } = createSaltedClaims(claimsObj);

    const now = Math.floor(Date.now() / 1000);
    const expires = now + expiryDays * 86400;
    const credentialId = "cred_" + Math.random().toString(36).slice(2, 10);

    // 3. Construct canonical payload to sign
    const payloadToSign = {
      credential_id: credentialId,
      issuer_name: issuerName,
      issuer: issuerKeypair.publicKeyHex,
      holder: holderPubKeyInput.trim(),
      issued_at: now,
      expires,
      claims: claimHashes,
    };

    // 4. Sign with Issuer secp256k1 private key
    const signature = signCanonicalObject(payloadToSign, issuerKeypair.privateKeyHex);

    const credential: CredentialPayload = {
      ...payloadToSign,
      signature,
    };

    const issuancePackage: CredentialIssuancePackage = {
      credential,
      disclosures,
    };

    setIssuedPackage(issuancePackage);
  };

  /**
   * Revoke Credential & Publish Signed CRL
   */
  const handleRevokeCredential = (credId: string) => {
    const updatedRevoked = Array.from(new Set([...revokedCredIds, credId]));
    setRevokedCredIds(updatedRevoked);

    const crl = createRevocationList(
      issuerName,
      issuerKeypair.publicKeyHex,
      issuerKeypair.privateKeyHex,
      updatedRevoked
    );

    setActiveCrl(crl);
    if (onPublishRevocationList) {
      onPublishRevocationList(crl);
    }
  };

  return (
    <div
      className={
        compact
          ? "space-y-4 w-full"
          : "grid grid-cols-1 lg:grid-cols-12 gap-6 p-6 max-w-7xl mx-auto"
      }
    >
      {/* Left Column: Issuer Configuration & Claims Studio */}
      <div className={compact ? "space-y-4 w-full" : "lg:col-span-7 space-y-6"}>
        <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-4 sm:p-6 shadow-oled">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <div>
              <h2 className="text-sm sm:text-base font-bold text-slate-100 font-mono flex items-center gap-2">
                <Building2 className="w-4 h-4 sm:w-5 sm:h-5 text-amber-400" />
                <span>ISSUER STUDIO (STEP 2)</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Generate cryptographic credentials bound to Passport Prime holder key
              </p>
            </div>
            <button
              onClick={() => setIssuerKeypair(saveKey("primeid.issuer", generateRandomKeyPair()))}
              className="py-1 px-3 bg-[#181F2C] hover:bg-[#222B3D] text-xs font-mono text-slate-300 rounded-xl border border-[#2D374A] flex items-center gap-1.5"
            >
              <Key className="w-3.5 h-3.5 text-amber-400" />
              <span>Rotate Issuer Key</span>
            </button>
          </div>

          {/* Issuer Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                Issuer Authority Name
              </label>
              <input
                type="text"
                value={issuerName}
                onChange={(e) => setIssuerName(e.target.value)}
                className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-400"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                Validity (Days)
              </label>
              <input
                type="number"
                value={expiryDays}
                onChange={(e) => setExpiryDays(parseInt(e.target.value, 10) || 30)}
                className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-400"
              />
            </div>
          </div>

          {/* Target Holder Key Binding */}
          <div className="mb-5">
            <div className="flex justify-between items-center mb-1">
              <label className="text-[11px] font-mono text-slate-400 uppercase">
                Step 1 Scanned: Device Holder Key (Passport Prime)
              </label>
              {deviceHolderPubKey && (
                <button
                  onClick={() => setHolderPubKeyInput(deviceHolderPubKey)}
                  className="text-[10px] text-amber-400 hover:underline font-mono"
                >
                  Sync with Simulator Key
                </button>
              )}
            </div>
            <input
              type="text"
              value={holderPubKeyInput}
              onChange={(e) => setHolderPubKeyInput(e.target.value)}
              placeholder="02... or 03... (33-byte compressed secp256k1 public key)"
              className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-amber-300 font-semibold focus:outline-none focus:border-amber-400"
            />
            <label className="mt-2 inline-block py-1.5 px-3 bg-[#181F2C] hover:bg-[#222B3D] text-xs font-mono text-amber-300 rounded-xl border border-[#2D374A] cursor-pointer">
              Read Prime key QR from screenshot
              <input
                type="file"
                accept="image/*"
                className="hidden"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  e.target.value = "";
                  if (!file) return;
                  const bmp = await createImageBitmap(file);
                  const canvas = document.createElement("canvas");
                  canvas.width = bmp.width;
                  canvas.height = bmp.height;
                  const ctx = canvas.getContext("2d")!;
                  ctx.drawImage(bmp, 0, 0);
                  const img = ctx.getImageData(0, 0, bmp.width, bmp.height);
                  const code = jsQR(img.data, img.width, img.height);
                  if (!code) return alert("No QR code found in that image.");
                  if (!/^0[23][0-9a-f]{64}$/i.test(code.data.trim())) return alert("That QR is not a Prime holder key.");
                  setHolderPubKeyInput(code.data.trim());
                }}
              />
            </label>
            <p className="text-[10px] text-slate-500 mt-1 font-mono">
              Crucial: The issuer signs this key into the credential so screenshots cannot be used by
              anyone else.
            </p>
          </div>

          {/* Presets */}
          <div className="mb-5">
            <label className="block text-[11px] font-mono text-slate-400 uppercase mb-2">
              Preset Credential Templates
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              {PRESET_TEMPLATES.map((tpl) => (
                <button
                  key={tpl.id}
                  onClick={() => handleSelectTemplate(tpl.id)}
                  className="p-3 bg-[#0E121A] hover:bg-[#161D2A] border border-[#212838] hover:border-amber-500/50 rounded-xl text-left transition-all active:scale-98"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <tpl.icon className="w-4 h-4 text-amber-400" />
                    <span className="text-xs font-semibold text-slate-200">{tpl.name}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">
                    {tpl.claims.length} claims pre-configured
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Claims Studio */}
          <div className="mb-5">
            <div className="flex justify-between items-center mb-2">
              <label className="text-[11px] font-mono text-slate-400 uppercase">
                Enclosed Claims (Individual Salted Hashes)
              </label>
              <button
                onClick={handleAddClaim}
                className="py-1 px-2.5 bg-[#181F2C] hover:bg-[#222B3D] text-[10px] font-mono text-amber-300 rounded-lg flex items-center gap-1 border border-[#2D374A]"
              >
                <Plus className="w-3 h-3" /> Add Custom Claim
              </button>
            </div>

            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {claimsList.map((c) => (
                <div key={c.id} className="flex items-center gap-2">
                  <input
                    type="text"
                    value={c.key}
                    onChange={(e) => handleUpdateClaim(c.id, e.target.value, c.value)}
                    placeholder="claim_key (e.g. over_18)"
                    className="flex-1 py-1.5 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-slate-200"
                  />
                  <input
                    type="text"
                    value={c.value}
                    onChange={(e) => handleUpdateClaim(c.id, c.key, e.target.value)}
                    placeholder="claim_value (e.g. true)"
                    className="flex-1 py-1.5 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-emerald-400 font-semibold"
                  />
                  <button
                    onClick={() => handleRemoveClaim(c.id)}
                    className="p-2 hover:bg-rose-950/40 text-slate-500 hover:text-rose-400 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Issue Action Button */}
          <button
            onClick={handleIssueCredential}
            className="w-full py-3 bg-gradient-to-r from-amber-500 via-amber-400 to-amber-600 hover:brightness-110 text-slate-950 font-bold font-mono text-xs rounded-xl shadow-lg flex items-center justify-center gap-2 active:scale-98 transition-all"
          >
            <Sparkles className="w-4 h-4 text-slate-950" />
            GENERATE SALTED HASHES & SIGN CREDENTIAL (secp256k1)
          </button>
        </div>

        {/* Revocation List Manager */}
        <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-6 shadow-oled">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
              <Ban className="w-4 h-4 text-rose-400" />
              ISSUER REVOCATION LIST (CRL MANAGER)
            </h3>
            {activeCrl && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                {activeCrl.revoked_credential_ids.length} Revoked
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mb-3">
            Publish signed revocation updates. When a credential ID is revoked, the 4-step pipeline
            rejects presentations.
          </p>

          {issuedPackage && (
            <div className="flex items-center justify-between p-3 bg-[#080A0E] border border-[#232B3B] rounded-xl mb-3 text-xs font-mono">
              <div>
                <span className="text-slate-400">Current ID: </span>
                <span className="text-amber-300">{issuedPackage.credential.credential_id}</span>
              </div>
              <button
                onClick={() => handleRevokeCredential(issuedPackage.credential.credential_id)}
                className="py-1 px-3 bg-rose-900/60 hover:bg-rose-800 text-rose-200 border border-rose-700 rounded-lg text-xs"
              >
                Revoke This Credential
              </button>
            </div>
          )}

          {activeCrl && (
            <div className="p-3 bg-[#080A0E] border border-rose-900/40 rounded-xl text-[10px] font-mono text-slate-300 space-y-1">
              <div className="text-rose-400 font-semibold">Active Signed CRL Broadcast:</div>
              <div>Issuer: {activeCrl.issuer_name}</div>
              <div>Revoked IDs: {activeCrl.revoked_credential_ids.join(", ")}</div>
              <div className="text-slate-500 break-all">Sig: {activeCrl.signature.slice(0, 32)}...</div>
            </div>
          )}
        </div>
      </div>

      {/* Right Column: Credential Issuance Package QR & Cryptographic Inspector */}
      <div className={compact ? "space-y-4 w-full" : "lg:col-span-5 space-y-6"}>
        <QrCodeDisplay
          data={trustCard(issuerName, issuerKeypair.publicKeyHex, "issuer")}
          title="Step 0: Issuer Trust Card"
          subtitle="Scan once on Passport Prime and approve, so Prime accepts credentials signed by this key"
          size={200}
        />
        {issuedPackage ? (
          <div className="space-y-4">
            <QrCodeDisplay
              data={issuedPackage}
              title="Step 2: Credential Issuance QR"
              subtitle="Passport Prime scans this offline to store credentials and private salts"
              size={230}
              onBeam={
                onBeamCredentialToDevice
                  ? () => onBeamCredentialToDevice(issuedPackage)
                  : undefined
              }
              beamLabel="Beam to Passport Prime (Air-Gap Bridge)"
            />

            {/* Cryptographic Inspector */}
            <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-5 text-xs font-mono space-y-3">
              <div className="text-amber-400 font-bold uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <FileCheck2 className="w-4 h-4" /> Cryptographic Proof Anatomy
              </div>

              <div className="space-y-2 text-[11px]">
                <div>
                  <span className="text-slate-500">Credential ID:</span>
                  <div className="text-slate-200 font-semibold">
                    {issuedPackage.credential.credential_id}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500">Holder Public Key Bound:</span>
                  <div className="text-[#D4AF37] break-all">
                    {issuedPackage.credential.holder}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500">
                    Salted Hash Tree ({issuedPackage.credential.claims.length} leaves):
                  </span>
                  <div className="space-y-1 mt-1 max-h-24 overflow-y-auto">
                    {issuedPackage.credential.claims.map((hash: string, i: number) => (
                      <div key={i} className="text-[9px] text-slate-400 break-all bg-[#080A0E] p-1 rounded">
                        [{i}] {hash}
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500">Issuer secp256k1 Signature:</span>
                  <div className="text-emerald-400 text-[10px] break-all">
                    {issuedPackage.credential.signature}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="h-full min-h-[400px] flex flex-col items-center justify-center p-8 bg-[#0C0F15] border border-dashed border-[#212838] rounded-2xl text-center">
            <Building2 className="w-12 h-12 text-slate-600 mb-3" />
            <h3 className="text-sm font-semibold text-slate-300 font-mono">
              Ready to Issue Credential
            </h3>
            <p className="text-xs text-slate-500 mt-1 max-w-xs font-mono">
              Configure claims on the left and click "Generate Salted Hashes & Sign" to render the Step 2 QR code.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
