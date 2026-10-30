import React, { useState, useMemo } from "react";
import { KeyOsStore } from "../../keyos-incogid-app/store";
import { HardwareEngine } from "../../keyos-incogid-app/hardware-engine";
import { Header, ViewMode } from "./components/Header";
import { PassportPrimeDevice } from "./components/PassportPrimeDevice";
import { IssuerStudio } from "./components/IssuerStudio";
import { VerifierTerminal } from "./components/VerifierTerminal";
import { SecurityTestbed } from "./components/SecurityTestbed";
import { IcaoNfcModule } from "./components/IcaoNfcModule";
import {
  CredentialIssuancePackage,
  VerifierRequest,
  SignedAnswer,
  RevocationList,
} from "../../core-crypto/schemas";
import { ArrowRight, Layers, ShieldCheck, Zap } from "lucide-react";

export const App: React.FC = () => {
  // Shared KeyOS Store and Hardware Engine instance
  const store = useMemo(() => new KeyOsStore(), []);
  const engine = useMemo(() => new HardwareEngine(store), [store]);

  const [currentMode, setCurrentMode] = useState<ViewMode>("ECOSYSTEM");
  const [demoMode, setDemoMode] = useState<"GUIDED" | "GRID">("GUIDED");
  const [activeDemoStep, setActiveDemoStep] = useState<1 | 2 | 3 | 4>(1);

  // Cross-system air-gap bridge states
  const [activeCrl, setActiveCrl] = useState<RevocationList | null>(null);
  const [verifierIncomingAnswer, setVerifierIncomingAnswer] = useState<SignedAnswer | null>(null);

  // Holder public key derived from Passport Prime seed
  const holderPubKey = store.getHolderKey().publicKeyHex;

  // --- Air-gap Bridge Actions ---
  const handleBeamCredentialToDevice = (pkg: CredentialIssuancePackage) => {
    const rawJson = JSON.stringify(pkg);
    const res = engine.handleScannedIssuancePayload(rawJson);
    if (res.success) {
      if (currentMode !== "ECOSYSTEM") {
        setCurrentMode("DEVICE");
      }
    } else {
      alert("Bridge error: " + res.error);
    }
  };

  const handleBeamRequestToDevice = (req: VerifierRequest) => {
    const rawJson = JSON.stringify(req);
    const res = engine.handleScannedRequestPayload(rawJson);
    if (res.success) {
      if (currentMode !== "ECOSYSTEM") {
        setCurrentMode("DEVICE");
      }
    } else {
      alert("Bridge error: " + res.error);
    }
  };

  const handleBeamAnswerToVerifier = (answer: unknown) => {
    setVerifierIncomingAnswer(answer as SignedAnswer);
    if (currentMode !== "ECOSYSTEM") {
      setCurrentMode("VERIFIER");
    }
  };

  const handleSendPhishingToDevice = (phishingReq: unknown) => {
    const rawJson = JSON.stringify(phishingReq);
    engine.handleScannedRequestPayload(rawJson);
    if (currentMode !== "ECOSYSTEM") {
      setCurrentMode("DEVICE");
    }
  };

  const handleImportIcaoCredential = (pkg: CredentialIssuancePackage) => {
    store.importCredentialPackage(pkg, "Government e-Passport (ICAO 9303)");
    engine.navigate("VAULT_HOME");
    setCurrentMode("DEVICE");
  };

  return (
    <div className="min-h-screen bg-[#060709] text-slate-100 flex flex-col font-sans">
      <Header
        currentMode={currentMode}
        onSelectMode={setCurrentMode}
        holderPubKey={holderPubKey}
      />

      <main className="flex-1">
        {/* =================================================================== */}
        {/* VIEW 1: 3-PARTY ECOSYSTEM (SPLIT VIEW) */}
        {/* =================================================================== */}
        {currentMode === "ECOSYSTEM" && (
          <div className="p-4 lg:p-6 space-y-6 max-w-[1700px] mx-auto">
            {/* Ecosystem Flow Banner */}
            <div className="bg-[#0C0F15] border border-[#212838] rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 font-mono text-xs shadow-oled">
              <div className="flex items-center gap-2">
                <Layers className="w-5 h-5 text-amber-400" />
                <span className="font-bold text-slate-100">
                  INCOGID++ 4-STEP AIR-GAPPED PROTOCOL FLOW:
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-slate-400 text-[11px]">
                <span className="text-amber-400">1. Prime displays Key QR</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                <span className="text-amber-400">2. Issuer issues Salted Credential QR</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                <span className="text-amber-400">3. Verifier challenges with Nonce QR</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                <span className="text-emerald-400 font-bold">4. Prime signs Selective Answer QR</span>
              </div>
            </div>

            {/* Ecosystem View Mode Switcher: Guided Demo vs Full 3-Party Grid */}
            <div className="flex flex-wrap items-center justify-between gap-4 bg-[#0A0D13] p-3 rounded-2xl border border-[#1E2535]">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">DEMO PRESENTATION MODE:</span>
                <button
                  onClick={() => setDemoMode("GUIDED")}
                  className={`py-1 px-3 rounded-xl text-xs font-mono transition-all ${
                    demoMode === "GUIDED"
                      ? "bg-gradient-to-r from-amber-500 to-amber-600 text-slate-950 font-bold shadow-md"
                      : "bg-[#141A24] text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Interactive Guided Flow (Recommended)
                </button>
                <button
                  onClick={() => setDemoMode("GRID")}
                  className={`py-1 px-3 rounded-xl text-xs font-mono transition-all ${
                    demoMode === "GRID"
                      ? "bg-gradient-to-r from-amber-500 to-amber-600 text-slate-950 font-bold shadow-md"
                      : "bg-[#141A24] text-slate-400 hover:text-slate-200"
                  }`}
                >
                  All 3 Parties Live Grid
                </button>
              </div>

              {demoMode === "GUIDED" && (
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-slate-400">Step:</span>
                  <div className="flex items-center gap-1">
                    {[1, 2, 3, 4].map((step) => (
                      <button
                        key={step}
                        onClick={() => setActiveDemoStep(step as 1 | 2 | 3 | 4)}
                        className={`w-7 h-7 rounded-lg text-xs font-mono font-bold transition-all ${
                          activeDemoStep === step
                            ? "bg-amber-400 text-slate-950 ring-2 ring-amber-400/50"
                            : "bg-[#141A24] text-slate-400 hover:text-slate-200"
                        }`}
                      >
                        {step}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* GUIDED DEMO MODE: Focused 2-Column Stage */}
            {demoMode === "GUIDED" && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                {/* Left Side: Active Party for Current Step */}
                <div className="lg:col-span-7 space-y-6">
                  {activeDemoStep === 1 && (
                    <div className="bg-[#0C0F15] border border-[#212838] rounded-3xl p-6 space-y-4">
                      <div className="flex items-center justify-between border-b border-[#1E2535] pb-3">
                        <span className="text-xs font-mono font-bold text-amber-400 uppercase">
                          STEP 1: AIR-GAPPED DEVICE IDENTITY SETUP
                        </span>
                        <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-amber-950 text-amber-300">
                          Holder secp256k1 Key
                        </span>
                      </div>
                      <h3 className="text-base font-bold text-slate-100 font-mono">
                        Passport Prime Generates Deterministic Identity Key
                      </h3>
                      <p className="text-xs text-slate-400 leading-relaxed font-mono">
                        The holder's public key is derived from the hardware root seed (BIP32 <code className="text-amber-400">m/1337'/0'/0'/0/0</code>). In an air-gapped setup, the issuer scans this QR code first so credentials can be cryptographically bound to this physical device.
                      </p>
                      <div className="p-4 bg-[#080A0E] border border-[#1E2535] rounded-2xl text-xs font-mono space-y-2">
                        <div className="text-slate-400">Holder Public Key (secp256k1 compressed, 33 bytes):</div>
                        <div className="text-[#D4AF37] break-all font-semibold">
                          {holderPubKey}
                        </div>
                      </div>
                      <div className="flex justify-end pt-2">
                        <button
                          onClick={() => setActiveDemoStep(2)}
                          className="py-2.5 px-5 bg-gradient-to-r from-amber-500 to-amber-600 hover:brightness-110 text-slate-950 font-bold font-mono text-xs rounded-xl flex items-center gap-2 shadow-lg"
                        >
                          <span>Proceed to Step 2: Issue Credential</span>
                          <ArrowRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  )}

                  {activeDemoStep === 2 && (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between bg-[#0C0F15] border border-[#212838] rounded-2xl p-4">
                        <div>
                          <div className="text-xs font-mono font-bold text-amber-400">
                            STEP 2: CREDENTIAL ISSUANCE
                          </div>
                          <div className="text-xs text-slate-400">
                            Configure claims, compute salted hash tree, and beam to Passport Prime
                          </div>
                        </div>
                        <button
                          onClick={() => setActiveDemoStep(3)}
                          className="py-2 px-4 bg-[#141A24] hover:bg-[#1E2535] text-amber-300 font-mono text-xs rounded-xl flex items-center gap-1.5 border border-[#2D374A]"
                        >
                          <span>Next: Verifier Challenge</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                      <IssuerStudio
                        deviceHolderPubKey={holderPubKey}
                        onBeamCredentialToDevice={handleBeamCredentialToDevice}
                        onPublishRevocationList={setActiveCrl}
                      />
                    </div>
                  )}

                  {(activeDemoStep === 3 || activeDemoStep === 4) && (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between bg-[#0C0F15] border border-[#212838] rounded-2xl p-4">
                        <div>
                          <div className="text-xs font-mono font-bold text-emerald-400">
                            {activeDemoStep === 3 ? "STEP 3: VERIFIER CHALLENGE" : "STEP 4: PROOF & AUDIT"}
                          </div>
                          <div className="text-xs text-slate-400">
                            {activeDemoStep === 3
                              ? "Generate signed challenge with 128-bit nonce and beam to device"
                              : "Verify answer with 4-step cryptographic pipeline"}
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => setActiveDemoStep(3)}
                            className={`py-1.5 px-3 font-mono text-xs rounded-xl ${
                              activeDemoStep === 3 ? "bg-amber-500 text-slate-950 font-bold" : "bg-[#141A24] text-slate-400"
                            }`}
                          >
                            Step 3 Challenge
                          </button>
                          <button
                            onClick={() => setActiveDemoStep(4)}
                            className={`py-1.5 px-3 font-mono text-xs rounded-xl ${
                              activeDemoStep === 4 ? "bg-emerald-500 text-slate-950 font-bold" : "bg-[#141A24] text-slate-400"
                            }`}
                          >
                            Step 4 Audit
                          </button>
                        </div>
                      </div>
                      <VerifierTerminal
                        onBeamRequestToDevice={handleBeamRequestToDevice}
                        incomingAnswer={verifierIncomingAnswer}
                        activeRevocationList={activeCrl}
                      />
                    </div>
                  )}
                </div>

                {/* Right Side: Passport Prime Hardware Device */}
                <div className="lg:col-span-5 flex flex-col items-center sticky top-24">
                  <div className="w-full text-center mb-3">
                    <span className="text-xs font-bold font-mono text-[#D4AF37] uppercase tracking-wider">
                      PASSPORT PRIME (KEYOS AIR-GAPPED VAULT)
                    </span>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {activeDemoStep === 1 && "Displaying Holder Public Key QR"}
                      {activeDemoStep === 2 && "Awaiting Credential QR from Issuer"}
                      {activeDemoStep === 3 && "Awaiting Verifier Challenge QR"}
                      {activeDemoStep === 4 && "Review disclosure on trusted screen and tap OK"}
                    </p>
                  </div>
                  <PassportPrimeDevice
                    store={store}
                    engine={engine}
                    onBeamAnswerToVerifier={handleBeamAnswerToVerifier}
                  />
                </div>
              </div>
            )}

            {/* FULL 3-PARTY GRID MODE */}
            {demoMode === "GRID" && (
              <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
                {/* Party A: Issuer Studio (Left) */}
                <div className="xl:col-span-4 bg-[#0A0D13] border border-[#1E2535] rounded-3xl p-4 shadow-xl">
                  <div className="border-b border-[#1E2535] pb-2 mb-3 flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-amber-400 uppercase">
                      PARTY 1: ISSUER STUDIO
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300">
                      Step 2 QR
                    </span>
                  </div>
                  <IssuerStudio
                    compact={true}
                    deviceHolderPubKey={holderPubKey}
                    onBeamCredentialToDevice={handleBeamCredentialToDevice}
                    onPublishRevocationList={setActiveCrl}
                  />
                </div>

                {/* Party B: Passport Prime Device (Center) */}
                <div className="xl:col-span-4 flex flex-col items-center">
                  <div className="w-full text-center mb-2">
                    <span className="text-xs font-bold font-mono text-[#D4AF37] uppercase tracking-wider">
                      PARTY 2: PASSPORT PRIME (KEYOS)
                    </span>
                  </div>
                  <PassportPrimeDevice
                    store={store}
                    engine={engine}
                    onBeamAnswerToVerifier={handleBeamAnswerToVerifier}
                  />
                </div>

                {/* Party C: Verifier Terminal (Right) */}
                <div className="xl:col-span-4 bg-[#0A0D13] border border-[#1E2535] rounded-3xl p-4 shadow-xl">
                  <div className="border-b border-[#1E2535] pb-2 mb-3 flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-emerald-400 uppercase">
                      PARTY 3: VERIFIER TERMINAL
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300">
                      Steps 3 & 4
                    </span>
                  </div>
                  <VerifierTerminal
                    compact={true}
                    onBeamRequestToDevice={handleBeamRequestToDevice}
                    incomingAnswer={verifierIncomingAnswer}
                    activeRevocationList={activeCrl}
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {/* =================================================================== */}
        {/* VIEW 2: DEDICATED PASSPORT PRIME HARDWARE VIEW */}
        {/* =================================================================== */}
        {currentMode === "DEVICE" && (
          <div className="p-8 flex flex-col items-center justify-center min-h-[calc(100vh-80px)]">
            <div className="text-center mb-6 max-w-md">
              <h2 className="text-lg font-bold font-mono text-[#D4AF37] tracking-wider uppercase">
                Foundation Passport Prime Simulator
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Authentic KeyOS microkernel hardware interface. Uses physical d-pad and tactile action keys to approve or deny selective disclosures.
              </p>
            </div>
            <PassportPrimeDevice
              store={store}
              engine={engine}
              onBeamAnswerToVerifier={handleBeamAnswerToVerifier}
            />
          </div>
        )}

        {/* =================================================================== */}
        {/* VIEW 3: FULL SCREEN ISSUER STUDIO */}
        {/* =================================================================== */}
        {currentMode === "ISSUER" && (
          <IssuerStudio
            deviceHolderPubKey={holderPubKey}
            onBeamCredentialToDevice={handleBeamCredentialToDevice}
            onPublishRevocationList={setActiveCrl}
          />
        )}

        {/* =================================================================== */}
        {/* VIEW 4: FULL SCREEN VERIFIER TERMINAL */}
        {/* =================================================================== */}
        {currentMode === "VERIFIER" && (
          <VerifierTerminal
            onBeamRequestToDevice={handleBeamRequestToDevice}
            incomingAnswer={verifierIncomingAnswer}
            activeRevocationList={activeCrl}
          />
        )}

        {/* =================================================================== */}
        {/* VIEW 5: RED-TEAM SECURITY TESTBED */}
        {/* =================================================================== */}
        {currentMode === "RED_TEAM" && (
          <SecurityTestbed onSendPhishingToDevice={handleSendPhishingToDevice} />
        )}

        {/* =================================================================== */}
        {/* VIEW 6: ICAO e-PASSPORT NFC MODULE */}
        {/* =================================================================== */}
        {currentMode === "ICAO_NFC" && (
          <IcaoNfcModule
            deviceHolderPubKey={holderPubKey}
            onImportIcaoCredential={handleImportIcaoCredential}
          />
        )}
      </main>
    </div>
  );
};
