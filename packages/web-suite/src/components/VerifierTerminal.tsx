import React, { useState } from "react";
import confetti from "canvas-confetti";
import {
  ShieldCheck,
  ShieldX,
  Radio,
  CheckCircle2,
  XCircle,
  Clock,
  RotateCcw,
  Sparkles,
  FileSearch,
  ScanLine,
} from "lucide-react";
import {
  generateRandomKeyPair,
  KeyPair,
  signCanonicalObject,
} from "@core-crypto/secp256k1";
import {
  VerifierRequest,
  SignedAnswer,
  VerificationPipelineResult,
  RevocationList,
} from "@core-crypto/schemas";
import { executeVerificationPipeline } from "@core-crypto/pipeline";
import { QrCodeDisplay } from "./QrCodeDisplay";

interface VerifierTerminalProps {
  onBeamRequestToDevice?: (req: VerifierRequest) => void;
  incomingAnswer?: SignedAnswer | null;
  activeRevocationList?: RevocationList | null;
  compact?: boolean;
}

const GLOBAL_CHALLENGE_PRESETS = [
  {
    id: "age_over_18",
    title: "Age Assurance (Over 18)",
    requestedClaim: "over_18",
    description: "Proves legal majority without sharing birthdate, name, or document ID.",
  },
  {
    id: "student_status",
    title: "University Student Status",
    requestedClaim: "enrolled_student",
    description: "Proves student enrollment for student discounts without uploading ID cards.",
  },
  {
    id: "crypto_compliance",
    title: "DeFi / Exchange Compliance",
    requestedClaim: "verified_adult",
    description: "Proves KYC adult status without central honeypot passport uploads.",
  },
  {
    id: "sanctions_check",
    title: "Jurisdiction & Sanctions Check",
    requestedClaim: "restricted_region",
    description: "Proves user is NOT from a restricted region without revealing home address.",
  },
  {
    id: "icao_e_passport",
    title: "ICAO Verified e-Passport",
    requestedClaim: "icao_verified",
    description: "Proves user possesses a government-signed e-passport chip verified on Prime.",
  },
];

export const VerifierTerminal: React.FC<VerifierTerminalProps> = ({
  onBeamRequestToDevice,
  incomingAnswer,
  activeRevocationList,
  compact = false,
}) => {
  // Verifier Identity
  const [verifierKeypair] = useState<KeyPair>(() => generateRandomKeyPair());
  const [verifierName, setVerifierName] = useState<string>("Apex Exchange Compliance Terminal");
  const [requestedClaim, setRequestedClaim] = useState<string>("over_18");
  const [expiryMinutes, setExpiryMinutes] = useState<number>(5);

  // Active Challenge Request State
  const [activeRequest, setActiveRequest] = useState<VerifierRequest | null>(null);

  // Scanned / Received Answer State
  const [answerInputText, setAnswerInputText] = useState<string>("");
  const [pipelineResult, setPipelineResult] = useState<VerificationPipelineResult | null>(null);

  // Generate fresh challenge request (Step 3)
  const handleGenerateChallenge = () => {
    const now = Math.floor(Date.now() / 1000);
    const expires = now + expiryMinutes * 60;
    const nonce = "0x" + Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const payloadToSign = {
      request_id: "req_" + Math.random().toString(36).slice(2, 9),
      verifier_name: verifierName,
      verifier_pubKey: verifierKeypair.publicKeyHex,
      requested_claim: requestedClaim,
      nonce,
      expires,
    };

    const signature = signCanonicalObject(payloadToSign, verifierKeypair.privateKeyHex);

    const request: VerifierRequest = {
      ...payloadToSign,
      signature,
    };

    setActiveRequest(request);
    setPipelineResult(null);
  };

  // Run 4-Step Verification Pipeline on an Answer
  const handleVerifyAnswer = (answerObj: SignedAnswer) => {
    const result = executeVerificationPipeline(answerObj, {
      expectedNonce: activeRequest?.nonce,
      expectedVerifierPubKey: activeRequest?.verifier_pubKey,
      activeRevocationList: activeRevocationList || undefined,
    });

    setPipelineResult(result);

    if (result.isValid) {
      confetti({
        particleCount: 80,
        spread: 60,
        origin: { y: 0.6 },
        colors: ["#D4AF37", "#10B981", "#3B82F6"],
      });
    }
  };

  // Sync with incoming beamed answer from device simulator
  React.useEffect(() => {
    if (incomingAnswer) {
      handleVerifyAnswer(incomingAnswer);
    }
  }, [incomingAnswer]);

  return (
    <div
      className={
        compact
          ? "space-y-4 w-full"
          : "grid grid-cols-1 lg:grid-cols-12 gap-6 p-6 max-w-7xl mx-auto"
      }
    >
      {/* Left Column: Verifier Challenge Generator (Step 3) */}
      <div className={compact ? "space-y-4 w-full" : "lg:col-span-6 space-y-6"}>
        <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-4 sm:p-6 shadow-oled">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <div>
              <h2 className="text-sm sm:text-base font-bold text-slate-100 font-mono flex items-center gap-2">
                <FileSearch className="w-4 h-4 sm:w-5 sm:h-5 text-amber-400" />
                <span>VERIFIER TERMINAL (STEP 3)</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Dispatch signed cryptographic challenges with one-time nonces
              </p>
            </div>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Terminal Online
            </span>
          </div>

          {/* Verifier Identity Info */}
          <div className="p-3 bg-[#080A0E] border border-[#212838] rounded-xl mb-4 text-xs font-mono">
            <div className="text-slate-400 text-[10px] uppercase">Verifier Public Key (secp256k1)</div>
            <div className="text-[#D4AF37] break-all font-semibold mt-0.5">
              {verifierKeypair.publicKeyHex}
            </div>
          </div>

          {/* Form Settings */}
          <div className="space-y-4 mb-5">
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                Verifier Name
              </label>
              <input
                type="text"
                value={verifierName}
                onChange={(e) => setVerifierName(e.target.value)}
                className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-400"
              />
            </div>

            {/* Presets */}
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase mb-2">
                Select Verification Requirement
              </label>
              <div className="space-y-1.5">
                {GLOBAL_CHALLENGE_PRESETS.map((p) => (
                  <div
                    key={p.id}
                    onClick={() => setRequestedClaim(p.requestedClaim)}
                    className={`p-2.5 rounded-xl border text-xs cursor-pointer transition-all ${
                      requestedClaim === p.requestedClaim
                        ? "bg-amber-500/10 border-amber-400 text-amber-300"
                        : "bg-[#0E121A] border-[#212838] text-slate-300 hover:bg-[#141A24]"
                    }`}
                  >
                    <div className="font-semibold flex justify-between">
                      <span>{p.title}</span>
                      <span className="font-mono text-[10px] text-amber-400">
                        claim: {p.requestedClaim}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">{p.description}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex gap-4">
              <div className="flex-1">
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                  Target Claim Key
                </label>
                <input
                  type="text"
                  value={requestedClaim}
                  onChange={(e) => setRequestedClaim(e.target.value)}
                  className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-amber-300 font-semibold focus:outline-none"
                />
              </div>

              <div className="w-32">
                <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                  Expiry (Mins)
                </label>
                <input
                  type="number"
                  value={expiryMinutes}
                  onChange={(e) => setExpiryMinutes(parseInt(e.target.value, 10) || 5)}
                  className="w-full py-2 px-3 bg-[#080A0E] border border-[#232B3B] rounded-xl text-xs font-mono text-slate-200 focus:outline-none"
                />
              </div>
            </div>
          </div>

          <button
            onClick={handleGenerateChallenge}
            className="w-full py-3 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 text-slate-950 font-bold font-mono text-xs rounded-xl shadow-lg flex items-center justify-center gap-2 active:scale-98 transition-all"
          >
            <Sparkles className="w-4 h-4" />
            DISPATCH SIGNED CHALLENGE WITH NONCE (STEP 3 QR)
          </button>
        </div>

        {/* Display Step 3 Request QR */}
        {activeRequest && (
          <QrCodeDisplay
            data={activeRequest}
            title="Step 3: Verifier Request QR"
            subtitle="Passport Prime scans this offline, checks verifier signature, and shows disclosure prompt"
            size={210}
            onBeam={
              onBeamRequestToDevice ? () => onBeamRequestToDevice(activeRequest) : undefined
            }
            beamLabel="Beam to Passport Prime (Air-Gap Bridge)"
          />
        )}
      </div>

      {/* Right Column: Step 4 Answer Audit & 4-Step Pipeline Breakdown */}
      <div className={compact ? "space-y-4 w-full" : "lg:col-span-6 space-y-6"}>
        <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-6 shadow-oled">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-slate-100 font-mono flex items-center gap-2">
                <ScanLine className="w-5 h-5 text-emerald-400" />
                ANSWER AUDIT & 4-STEP CRYPTO PIPELINE
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Scan Step 4 Answer QR from Passport Prime for zero-mock cryptographic verification
              </p>
            </div>
          </div>

          {/* Manual / Paste Input */}
          <div className="mb-4">
            <textarea
              value={answerInputText}
              onChange={(e) => setAnswerInputText(e.target.value)}
              placeholder="Paste Step 4 Answer JSON payload or beam from device..."
              className="w-full h-16 bg-[#080A0E] border border-[#232B3B] rounded-xl p-2.5 text-xs font-mono text-slate-200 resize-none focus:outline-none focus:border-emerald-400"
            />
            <button
              onClick={() => {
                try {
                  const parsed = JSON.parse(answerInputText);
                  handleVerifyAnswer(parsed);
                } catch {
                  alert("Invalid JSON format in Answer payload.");
                }
              }}
              disabled={!answerInputText.trim()}
              className="w-full mt-2 py-2 bg-[#181F2C] hover:bg-[#222B3D] disabled:opacity-40 text-emerald-400 font-mono font-bold text-xs rounded-xl border border-[#2B3547] transition-colors"
            >
              Verify Pasted Answer Payload
            </button>
          </div>

          {/* 4-Step Pipeline Result Card */}
          {pipelineResult ? (
            <div className="space-y-4">
              {/* Verdict Header */}
              <div
                className={`p-4 rounded-2xl border flex items-center justify-between ${
                  pipelineResult.isValid
                    ? "bg-emerald-950/60 border-emerald-500/60 text-emerald-300"
                    : "bg-rose-950/60 border-rose-500/60 text-rose-300"
                }`}
              >
                <div className="flex items-center gap-3">
                  {pipelineResult.isValid ? (
                    <ShieldCheck className="w-8 h-8 text-emerald-400 shrink-0" />
                  ) : (
                    <ShieldX className="w-8 h-8 text-rose-400 shrink-0" />
                  )}
                  <div>
                    <h3 className="font-bold font-mono text-sm uppercase tracking-wide">
                      {pipelineResult.isValid
                        ? "ALL 4 CRYPTOGRAPHIC CHECKS PASSED"
                        : "VERIFICATION FAILED: INTEGRITY COMPROMISED"}
                    </h3>
                    <p className="text-xs opacity-90 mt-0.5">
                      {pipelineResult.reason}
                    </p>
                  </div>
                </div>

                {pipelineResult.disclosedClaim && (
                  <div className="text-right font-mono bg-black/40 px-3 py-1.5 rounded-xl border border-white/10">
                    <div className="text-[10px] opacity-75">PROVEN FACT:</div>
                    <div className="text-sm font-bold text-emerald-400">
                      {pipelineResult.disclosedClaim.key} = {pipelineResult.disclosedClaim.value}
                    </div>
                  </div>
                )}
              </div>

              {/* The 4 Cryptographic Checks Breakdown */}
              <div className="space-y-2.5">
                {pipelineResult.steps.map((st: any) => (
                  <div
                    key={st.step}
                    className="p-3.5 bg-[#090C12] border border-[#212838] rounded-xl text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <div className="font-bold flex items-center gap-2">
                        {st.status === "PASSED" ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                        )}
                        <span className={st.status === "PASSED" ? "text-slate-200" : "text-rose-300"}>
                          Step {st.step}: {st.name}
                        </span>
                      </div>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          st.status === "PASSED"
                            ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                            : "bg-rose-950 text-rose-400 border border-rose-800"
                        }`}
                      >
                        {st.status}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 pl-6">{st.description}</p>
                    <div className="text-[10px] text-amber-300/90 pl-6 break-all bg-black/30 p-2 rounded-lg mt-1">
                      {st.technical_details}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-8 bg-[#080A0E] border border-dashed border-[#232B3B] rounded-2xl text-center font-mono">
              <Clock className="w-10 h-10 text-slate-600 mx-auto mb-2" />
              <div className="text-xs text-slate-400 font-semibold">
                Awaiting Step 4 Answer QR from Passport Prime
              </div>
              <p className="text-[11px] text-slate-500 mt-1">
                Dispatch a challenge from the left, approve it on Passport Prime, and beam or scan the answer here.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
