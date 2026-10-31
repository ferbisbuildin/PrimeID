import React, { useState } from "react";
import {
  ShieldAlert,
  Flame,
  Bot,
  Copy,
  RotateCcw,
  FishSymbol,
  CheckCircle2,
  XCircle,
  Play,
  Terminal,
} from "lucide-react";
import {
  simulateAiFakeIdAttack,
  simulateCopiedCredentialAttack,
  simulateReplayedAnswerAttack,
  simulatePhishingRequesterAttack,
  AttackScenarioResult,
} from "@core-crypto/attacks";
import { generateRandomKeyPair, signCanonicalObject } from "@core-crypto/secp256k1";
import { createSaltedClaims } from "@core-crypto/salted-hash-tree";
import { CredentialPayload, SignedAnswer } from "@core-crypto/schemas";
import { KNOWN_TRUSTED_VERIFIERS } from "@keyos-app/registry";

interface SecurityTestbedProps {
  onSendPhishingToDevice?: (phishingReq: unknown) => void;
}

export const SecurityTestbed: React.FC<SecurityTestbedProps> = ({ onSendPhishingToDevice }) => {
  const [activeAttackResult, setActiveAttackResult] = useState<AttackScenarioResult | null>(null);
  const [phishingResult, setPhishingResult] = useState<unknown | null>(null);
  const [runningAttackId, setRunningAttackId] = useState<string | null>(null);

  /**
   * ATTACK 1: Forged Credential ("The AI Fake ID")
   */
  const handleRunAiFakeIdAttack = () => {
    setRunningAttackId("ai_fake_id");
    setPhishingResult(null);

    // Setup genuine authority key and holder key
    const genuineIssuer = generateRandomKeyPair();
    const holder = generateRandomKeyPair();
    const verifier = generateRandomKeyPair();

    const { disclosures, claimHashes } = createSaltedClaims({
      over_18: "true",
      name: "Synthetic AI Citizen",
      doc_number: "AI-9999-FAKE",
    });

    const activeNonce = "0x" + Math.random().toString(16).slice(2);

    const result = simulateAiFakeIdAttack(
      genuineIssuer.publicKeyHex,
      holder.publicKeyHex,
      claimHashes,
      disclosures[0],
      activeNonce,
      verifier.publicKeyHex
    );

    setActiveAttackResult(result);
    setRunningAttackId(null);
  };

  /**
   * ATTACK 2: Copied Credential in Another App (The Screenshot Thief)
   */
  const handleRunCopiedCredentialAttack = () => {
    setRunningAttackId("copied_credential");
    setPhishingResult(null);

    const genuineIssuer = generateRandomKeyPair();
    const victimHolder = generateRandomKeyPair();
    const verifier = generateRandomKeyPair();

    const { disclosures, claimHashes } = createSaltedClaims({
      over_18: "true",
      country: "US",
    });

    const payload = {
      credential_id: "cred_victim_legit_01",
      issuer_name: "California Department of Motor Vehicles",
      issuer: genuineIssuer.publicKeyHex,
      holder: victimHolder.publicKeyHex, // Bound to Victim's key
      issued_at: Math.floor(Date.now() / 1000) - 100,
      expires: Math.floor(Date.now() / 1000) + 86400,
      claims: claimHashes,
    };

    const signature = signCanonicalObject(payload, genuineIssuer.privateKeyHex);
    const validCred: CredentialPayload = { ...payload, signature };
    const activeNonce = "0x" + Math.random().toString(16).slice(2);

    const result = simulateCopiedCredentialAttack(
      validCred,
      disclosures[0],
      activeNonce,
      verifier.publicKeyHex
    );

    setActiveAttackResult(result);
    setRunningAttackId(null);
  };

  /**
   * ATTACK 3: Replayed Old Answer (Replay Attack)
   */
  const handleRunReplayAttack = () => {
    setRunningAttackId("replayed_answer");
    setPhishingResult(null);

    const genuineIssuer = generateRandomKeyPair();
    const holder = generateRandomKeyPair();
    const verifier = generateRandomKeyPair();

    const { disclosures, claimHashes } = createSaltedClaims({
      over_18: "true",
    });

    const credPayload = {
      credential_id: "cred_replay_test_01",
      issuer_name: "Global Identity Authority",
      issuer: genuineIssuer.publicKeyHex,
      holder: holder.publicKeyHex,
      issued_at: Math.floor(Date.now() / 1000) - 100,
      expires: Math.floor(Date.now() / 1000) + 86400,
      claims: claimHashes,
    };

    const credSig = signCanonicalObject(credPayload, genuineIssuer.privateKeyHex);
    const cred: CredentialPayload = { ...credPayload, signature: credSig };

    // Valid Answer generated in the PAST with old nonce
    const oldNonce = "0xOLD_NONCE_AIRPORT_CHECKPOINT";
    const oldContext = {
      nonce: oldNonce,
      verifier_pubKey: verifier.publicKeyHex,
      expires: Math.floor(Date.now() / 1000) + 300,
    };

    const answerPayload = {
      credential: cred,
      disclosed_claim: disclosures[0],
      request_context: oldContext,
    };

    const holderSig = signCanonicalObject(answerPayload, holder.privateKeyHex);
    const previousValidAnswer: SignedAnswer = {
      credential: cred,
      disclosed_claim: disclosures[0],
      request_context: oldContext,
      holder_signature: holderSig,
    };

    // Adversary replays old answer against a brand new challenge session
    const freshChallengeNonce = "0xFRESH_CHALLENGE_NONCE_CLUB_ENTRY";

    const result = simulateReplayedAnswerAttack(
      previousValidAnswer,
      freshChallengeNonce,
      verifier.publicKeyHex
    );

    setActiveAttackResult(result);
    setRunningAttackId(null);
  };

  /**
   * ATTACK 4: Fake Requester Posing as a Bank (Phishing Attack)
   */
  const handleRunPhishingAttack = () => {
    setRunningAttackId("phishing");
    setActiveAttackResult(null);

    const knownKeys = KNOWN_TRUSTED_VERIFIERS.map((v: any) => v.publicKeyHex);
    const result = simulatePhishingRequesterAttack(knownKeys, "over_18");

    setPhishingResult(result);
    setRunningAttackId(null);

    if (onSendPhishingToDevice) {
      onSendPhishingToDevice(result.request);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-6 shadow-oled flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-500 animate-pulse" />
            RED-TEAM SECURITY VERIFICATION & ATTACK SIMULATOR
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Test IncogID++ cryptographic defenses against real-world adversarial attack vectors.
            All scenarios execute genuine secp256k1 & SHA-256 math.
          </p>
        </div>
        <span className="text-[10px] font-mono px-3 py-1 bg-rose-950 text-rose-400 border border-rose-800 rounded-full font-bold">
          LIVE ADVERSARY TESTBED
        </span>
      </div>

      {/* The 4 Attack Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Attack 1 */}
        <div className="bg-[#0D1017] border border-[#222A3B] rounded-2xl p-5 flex flex-col justify-between hover:border-rose-500/50 transition-colors">
          <div>
            <div className="w-10 h-10 rounded-xl bg-rose-950/60 border border-rose-800/50 flex items-center justify-center text-rose-400 mb-3">
              <Bot className="w-5 h-5" />
            </div>
            <div className="text-[10px] font-mono text-rose-400 uppercase font-bold">Attack 1</div>
            <h3 className="text-sm font-bold text-slate-200 mt-0.5">The AI Fake ID</h3>
            <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">
              Adversary uses generative AI to forge ID data and signs with a rogue key, attempting to impersonate a government authority.
            </p>
            <div className="mt-3 text-[10px] font-mono text-amber-300">
              Defense: Step 1 (Issuer Signature Check)
            </div>
          </div>
          <button
            onClick={handleRunAiFakeIdAttack}
            disabled={runningAttackId === "ai_fake_id"}
            className="w-full mt-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-mono font-bold text-xs rounded-xl flex items-center justify-center gap-1.5 active:scale-98"
          >
            <Play className="w-3.5 h-3.5" /> Execute Attack 1
          </button>
        </div>

        {/* Attack 2 */}
        <div className="bg-[#0D1017] border border-[#222A3B] rounded-2xl p-5 flex flex-col justify-between hover:border-rose-500/50 transition-colors">
          <div>
            <div className="w-10 h-10 rounded-xl bg-rose-950/60 border border-rose-800/50 flex items-center justify-center text-rose-400 mb-3">
              <Copy className="w-5 h-5" />
            </div>
            <div className="text-[10px] font-mono text-rose-400 uppercase font-bold">Attack 2</div>
            <h3 className="text-sm font-bold text-slate-200 mt-0.5">The Screenshot Thief</h3>
            <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">
              Adversary photographs someone else's credential QR and attempts to present it from their own wallet application.
            </p>
            <div className="mt-3 text-[10px] font-mono text-amber-300">
              Defense: Step 3 (Holder Key Binding)
            </div>
          </div>
          <button
            onClick={handleRunCopiedCredentialAttack}
            disabled={runningAttackId === "copied_credential"}
            className="w-full mt-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-mono font-bold text-xs rounded-xl flex items-center justify-center gap-1.5 active:scale-98"
          >
            <Play className="w-3.5 h-3.5" /> Execute Attack 2
          </button>
        </div>

        {/* Attack 3 */}
        <div className="bg-[#0D1017] border border-[#222A3B] rounded-2xl p-5 flex flex-col justify-between hover:border-rose-500/50 transition-colors">
          <div>
            <div className="w-10 h-10 rounded-xl bg-rose-950/60 border border-rose-800/50 flex items-center justify-center text-rose-400 mb-3">
              <RotateCcw className="w-5 h-5" />
            </div>
            <div className="text-[10px] font-mono text-rose-400 uppercase font-bold">Attack 3</div>
            <h3 className="text-sm font-bold text-slate-200 mt-0.5">The Replay Attack</h3>
            <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">
              Adversary records a previously valid Answer QR (from CCTV or intercepted traffic) and tries to reuse it at a different terminal.
            </p>
            <div className="mt-3 text-[10px] font-mono text-amber-300">
              Defense: Step 4 (One-Time Nonce & Expiry)
            </div>
          </div>
          <button
            onClick={handleRunReplayAttack}
            disabled={runningAttackId === "replayed_answer"}
            className="w-full mt-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-mono font-bold text-xs rounded-xl flex items-center justify-center gap-1.5 active:scale-98"
          >
            <Play className="w-3.5 h-3.5" /> Execute Attack 3
          </button>
        </div>

        {/* Attack 4 */}
        <div className="bg-[#0D1017] border border-[#222A3B] rounded-2xl p-5 flex flex-col justify-between hover:border-rose-500/50 transition-colors">
          <div>
            <div className="w-10 h-10 rounded-xl bg-rose-950/60 border border-rose-800/50 flex items-center justify-center text-rose-400 mb-3">
              <FishSymbol className="w-5 h-5" />
            </div>
            <div className="text-[10px] font-mono text-rose-400 uppercase font-bold">Attack 4</div>
            <h3 className="text-sm font-bold text-slate-200 mt-0.5">Phishing Requester</h3>
            <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">
              A rogue verifier signs a request posing as a bank with an untrusted key to harvest user credentials.
            </p>
            <div className="mt-3 text-[10px] font-mono text-amber-300">
              Defense: KeyOS Hardware Warning
            </div>
          </div>
          <button
            onClick={handleRunPhishingAttack}
            disabled={runningAttackId === "phishing"}
            className="w-full mt-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-mono font-bold text-xs rounded-xl flex items-center justify-center gap-1.5 active:scale-98"
          >
            <Play className="w-3.5 h-3.5" /> Beam Phish to Prime
          </button>
        </div>
      </div>

      {/* Attack Results & Cryptographic Failure Diagnostics Terminal */}
      {activeAttackResult && (
        <div className="bg-[#0A0D14] border border-[#232B3B] rounded-2xl p-6 shadow-oled space-y-4 font-mono">
          <div className="flex items-center justify-between border-b border-[#1E2533] pb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-amber-400" />
              <span className="font-bold text-slate-100 text-sm">
                CRYPTOGRAPHIC FAILURE DIAGNOSTICS: {activeAttackResult.name}
              </span>
            </div>
            <span
              className={`text-xs px-2.5 py-0.5 rounded-full font-bold ${
                activeAttackResult.isDefenseSuccessful
                  ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                  : "bg-rose-950 text-rose-400 border border-rose-800"
              }`}
            >
              {activeAttackResult.isDefenseSuccessful ? "ATTACK BLOCKED" : "DEFENSE COMPROMISED"}
            </span>
          </div>

          <div className="p-4 bg-emerald-950/40 border border-emerald-800/50 rounded-xl text-emerald-300 text-xs">
            {activeAttackResult.securityVerdict}
          </div>

          {/* Target Check Breakdown */}
          <div className="space-y-2">
            <div className="text-[11px] text-slate-400 uppercase">
              Pipeline Diagnostic Trace:
            </div>
            {activeAttackResult.pipelineResult.steps.map((st: any) => (
              <div
                key={st.step}
                className={`p-3 rounded-xl border text-xs ${
                  st.status === "PASSED"
                    ? "bg-[#0B0E14] border-[#1D2433] text-slate-300"
                    : "bg-rose-950/50 border-rose-800/80 text-rose-200"
                }`}
              >
                <div className="flex justify-between items-center mb-1">
                  <span className="font-bold flex items-center gap-2">
                    {st.status === "PASSED" ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400" />
                    )}
                    Step {st.step}: {st.name}
                  </span>
                  <span className="font-bold">{st.status}</span>
                </div>
                <div className="text-[10px] opacity-80 pl-6 break-all">
                  {st.technical_details}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Phishing Simulation Alert */}
      {phishingResult && (
        <div className="bg-[#1A0A0E] border border-rose-800/60 rounded-2xl p-6 shadow-oled font-mono space-y-3">
          <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
            PHISHING ATTACK BEAMED TO PASSPORT PRIME SIMULATOR
          </div>
          <p className="text-xs text-rose-200 leading-relaxed">
            The rogue challenge claiming to be "First National Bank" has been beamed into the Passport Prime hardware engine.
            Observe the device screen: KeyOS detects the unknown public key and displays a prominent <strong>RED "Unknown Requester Alert"</strong> rather than a green verified badge!
          </p>
        </div>
      )}
    </div>
  );
};
