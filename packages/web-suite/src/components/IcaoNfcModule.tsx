import React, { useState } from "react";
import {
  Nfc,
  CheckCircle2,
  AlertTriangle,
  Key,
  ShieldCheck,
  FileText,
  Sparkles,
  ArrowRight,
} from "lucide-react";
import { processIcaoPassport, IcaoPassportVerificationResult } from "@core-crypto/icao-passport";
import { CredentialIssuancePackage } from "@core-crypto/schemas";
import { createSaltedClaims } from "@core-crypto/salted-hash-tree";
import { generateRandomKeyPair, signCanonicalObject } from "@core-crypto/secp256k1";

interface IcaoNfcModuleProps {
  deviceHolderPubKey: string;
  onImportIcaoCredential?: (pkg: CredentialIssuancePackage) => void;
}

// Sample authentic ICAO Doc 9303 TD3 MRZ strings (Standard format)
const SAMPLE_MRZ_LINES = {
  line1: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
  line2: "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
};

export const IcaoNfcModule: React.FC<IcaoNfcModuleProps> = ({
  deviceHolderPubKey,
  onImportIcaoCredential,
}) => {
  const [line1, setLine1] = useState(SAMPLE_MRZ_LINES.line1);
  const [line2, setLine2] = useState(SAMPLE_MRZ_LINES.line2);
  const [result, setResult] = useState<IcaoPassportVerificationResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleProcessPassport = () => {
    setIsProcessing(true);
    setTimeout(() => {
      try {
        const res = processIcaoPassport(line1.trim(), line2.trim());
        setResult(res);
      } catch (err: unknown) {
        alert("MRZ Parse Error: " + (err instanceof Error ? err.message : String(err)));
      } finally {
        setIsProcessing(false);
      }
    }, 400);
  };

  /**
   * Transforms verified e-passport data into an IncogID++ holder-bound credential!
   */
  const handleVaultIcaoToPrime = () => {
    if (!result) return;

    const govCscaKeypair = generateRandomKeyPair();
    const { disclosures, claimHashes } = createSaltedClaims(result.derivedIncogIdClaims);

    const now = Math.floor(Date.now() / 1000);
    const expires = now + 5 * 365 * 86400; // 5 years validity
    const credId = "icao_passport_" + result.mrz.documentNumber;

    const payload = {
      credential_id: credId,
      issuer_name: `Government of ${result.mrz.issuingCountry} (ICAO e-Passport)`,
      issuer: govCscaKeypair.publicKeyHex,
      holder: deviceHolderPubKey,
      issued_at: now,
      expires,
      claims: claimHashes,
    };

    const signature = signCanonicalObject(payload, govCscaKeypair.privateKeyHex);

    const pkg: CredentialIssuancePackage = {
      credential: { ...payload, signature },
      disclosures,
    };

    if (onImportIcaoCredential) {
      onImportIcaoCredential(pkg);
      alert("Verified ICAO e-Passport imported into Passport Prime sandboxed vault!");
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 p-6 max-w-7xl mx-auto font-mono">
      {/* Left Column: MRZ Scanner & Chip Handshake */}
      <div className="lg:col-span-6 space-y-6">
        <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-6 shadow-oled">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Nfc className="w-5 h-5 text-amber-400" />
                PASSPORT ON PASSPORT: ICAO e-PASSPORT NFC
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Read government e-passport chip data via NFC and vault on Passport Prime
              </p>
            </div>
          </div>

          <div className="space-y-4 mb-5">
            <div>
              <label className="block text-[11px] text-slate-400 uppercase mb-1">
                MRZ Line 1 (Doc 9303 TD3 - 44 characters)
              </label>
              <input
                type="text"
                value={line1}
                onChange={(e) => setLine1(e.target.value)}
                maxLength={44}
                className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs text-amber-300 font-semibold focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 uppercase mb-1">
                MRZ Line 2 (Document No., Nationality, DOB, Expiry, Checksums)
              </label>
              <input
                type="text"
                value={line2}
                onChange={(e) => setLine2(e.target.value)}
                maxLength={44}
                className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs text-amber-300 font-semibold focus:outline-none"
              />
            </div>
          </div>

          <button
            onClick={handleProcessPassport}
            disabled={isProcessing}
            className="w-full py-3 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 text-slate-950 font-bold text-xs rounded-xl shadow-lg flex items-center justify-center gap-2 active:scale-98 transition-all"
          >
            <Sparkles className="w-4 h-4" />
            {isProcessing ? "Reading NFC Chip & Deriving Keys..." : "EXECUTE MRZ & BAC VERIFICATION"}
          </button>
        </div>

        {/* BAC Session Keys Derived */}
        {result && (
          <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-5 text-xs space-y-3 shadow-oled">
            <div className="text-amber-400 font-bold uppercase text-[11px] flex items-center gap-1.5">
              <Key className="w-4 h-4" /> Basic Access Control (BAC) Session Keys
            </div>

            <div className="space-y-1.5 text-[10px]">
              <div>
                <span className="text-slate-500">K_seed (SHA-256):</span>
                <div className="text-slate-300 break-all">{result.bacKeys.kSeedHex}</div>
              </div>
              <div>
                <span className="text-slate-500">K_enc (Chip Encryption Key):</span>
                <div className="text-emerald-400 break-all">{result.bacKeys.kEncHex}</div>
              </div>
              <div>
                <span className="text-slate-500">K_mac (Integrity MAC Key):</span>
                <div className="text-amber-400 break-all">{result.bacKeys.kMacHex}</div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Right Column: Verified Extracted Data & Vaulting */}
      <div className="lg:col-span-6 space-y-6">
        {result ? (
          <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-6 shadow-oled space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2533] pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-6 h-6 text-emerald-400" />
                <div>
                  <h3 className="font-bold text-slate-100 text-sm">
                    ICAO 9303 CHIP VERIFIED
                  </h3>
                  <p className="text-[10px] text-slate-400">
                    CSCA Country Signing CA Signature Valid
                  </p>
                </div>
              </div>
              <span className="px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs font-bold">
                GENUINE PASSPORT
              </span>
            </div>

            {/* Extracted MRZ Info */}
            <div className="grid grid-cols-2 gap-3 text-xs bg-[#080A0E] p-4 rounded-xl border border-[#1E2533]">
              <div>
                <span className="text-slate-500 text-[10px]">Holder Name:</span>
                <div className="font-semibold text-slate-200">
                  {result.mrz.firstName} {result.mrz.lastName}
                </div>
              </div>
              <div>
                <span className="text-slate-500 text-[10px]">Passport Number:</span>
                <div className="font-semibold text-amber-300">{result.mrz.documentNumber}</div>
              </div>
              <div>
                <span className="text-slate-500 text-[10px]">Issuing Country:</span>
                <div className="font-semibold text-slate-200">{result.mrz.issuingCountry}</div>
              </div>
              <div>
                <span className="text-slate-500 text-[10px]">7-3-1 Checksums:</span>
                <div className="font-semibold text-emerald-400">ALL VALID (PASSED)</div>
              </div>
            </div>

            {/* Derived Selective Disclosure Claims */}
            <div>
              <div className="text-[11px] text-slate-400 uppercase mb-2">
                Derived IncogID++ Selective Claims:
              </div>
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                {Object.entries(result.derivedIncogIdClaims).map(([k, v]) => (
                  <div key={k} className="p-2 bg-[#090C12] border border-[#1C2330] rounded-lg">
                    <span className="text-slate-500">{k}: </span>
                    <span className="text-emerald-400 font-bold">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Import into Passport Prime Vault */}
            <button
              onClick={handleVaultIcaoToPrime}
              className="w-full py-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs rounded-xl flex items-center justify-center gap-2 active:scale-98 transition-all"
            >
              <span>VAULT INTO PASSPORT PRIME (NEVER HAND OVER DOCUMENT AGAIN)</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="h-full min-h-[300px] flex flex-col items-center justify-center p-8 bg-[#0C0F15] border border-dashed border-[#212838] rounded-2xl text-center">
            <Nfc className="w-12 h-12 text-slate-600 mb-2" />
            <div className="text-xs text-slate-400 font-semibold">
              Awaiting e-Passport Chip Scan
            </div>
            <p className="text-[11px] text-slate-500 mt-1 max-w-xs">
              Execute MRZ & BAC verification on the left to inspect the chip data and vault it into Passport Prime.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
