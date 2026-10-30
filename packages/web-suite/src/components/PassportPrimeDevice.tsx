import React, { useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Camera,
  QrCode,
  FileText,
  Key,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Eye,
  Radio,
  Lock,
  BatteryCharging,
  Cpu,
  Fingerprint,
} from "lucide-react";
import { KeyOsStore, StoredCredentialRecord } from "@keyos-app/store";
import { HardwareEngine, KeyOsScreen } from "@keyos-app/hardware-engine";
import { QrCodeDisplay } from "./QrCodeDisplay";
import { lookupVerifier } from "@keyos-app/registry";

interface PassportPrimeDeviceProps {
  store: KeyOsStore;
  engine: HardwareEngine;
  onAnswerGenerated?: (answer: unknown) => void;
  onBeamAnswerToVerifier?: (answer: unknown) => void;
}

export const PassportPrimeDevice: React.FC<PassportPrimeDeviceProps> = ({
  store,
  engine,
  onAnswerGenerated,
  onBeamAnswerToVerifier,
}) => {
  const [, setRenderTrigger] = useState(0);
  const rerender = () => setRenderTrigger((prev) => prev + 1);

  const [scanInputText, setScanInputText] = useState("");
  const [showSeedModal, setShowSeedModal] = useState(false);
  const [selectedReceipt, setSelectedReceipt] = useState<unknown | null>(null);

  const currentScreen = engine.currentScreen;
  const holderKey = store.getHolderKey();
  const credentials = store.getCredentials();
  const receipts = store.receipts.getAll();
  const stats = store.receipts.getStats();

  // Navigation handlers
  const handleNav = (screen: KeyOsScreen) => {
    engine.navigate(screen);
    rerender();
  };

  const handlePhysicalOk = () => {
    engine.pressHardwareOk();
    if (engine.activeAnswer && onAnswerGenerated) {
      onAnswerGenerated(engine.activeAnswer);
    }
    rerender();
  };

  const handlePhysicalBack = () => {
    engine.pressHardwareBack();
    rerender();
  };

  const handleSimulateScan = (rawJson: string) => {
    try {
      const parsed = JSON.parse(rawJson);
      if (parsed.requested_claim) {
        // Step 3: Verifier Request
        const res = engine.handleScannedRequestPayload(rawJson);
        if (!res.success) {
          alert("Scan Error: " + res.error);
        }
      } else if (parsed.credential && parsed.disclosures) {
        // Step 2: Credential Issuance Package
        const res = engine.handleScannedIssuancePayload(rawJson);
        if (!res.success) {
          alert("Scan Error: " + res.error);
        }
      } else {
        alert("Unrecognized QR payload format.");
      }
      setScanInputText("");
      rerender();
    } catch {
      alert("Invalid JSON format in QR code.");
    }
  };

  return (
    <div className="relative flex flex-col items-center">
      {/* ========================================================================= */}
      {/* PASSPORT PRIME HARDWARE CHASSIS (Foundation Industrial Design) */}
      {/* ========================================================================= */}
      <div className="w-[380px] bg-gradient-to-b from-[#181C24] via-[#12151C] to-[#0A0D12] rounded-[42px] p-5 shadow-2xl border-[3px] border-[#2A3140] relative overflow-hidden select-none">
        {/* Subtle Brushed Brass Outer Chamfer */}
        <div className="absolute inset-0 rounded-[39px] pointer-events-none border border-[#D4AF37]/20" />

        {/* Top Hardware Bezel: Camera Sensor & Mic */}
        <div className="flex items-center justify-between px-6 pt-1 pb-3">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500/80 animate-pulse" />
            <span className="text-[10px] font-mono text-slate-400 tracking-wider">AIR-GAPPED</span>
          </div>

          {/* Foundation Monogram */}
          <div className="text-center">
            <span className="text-xs font-bold font-mono tracking-widest text-[#D4AF37] opacity-90">
              PASSPORT PRIME
            </span>
          </div>

          {/* Hardware Camera Dot */}
          <div className="w-3.5 h-3.5 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center">
            <div className="w-1.5 h-1.5 rounded-full bg-blue-900/80" />
          </div>
        </div>

        {/* ========================================================================= */}
        {/* 3.5" OLED DISPLAY (True Black OLED 480x800 Form Factor) */}
        {/* ========================================================================= */}
        <div className="w-full h-[520px] bg-[#07090C] rounded-[24px] border-2 border-[#1E2430] p-4 flex flex-col justify-between overflow-hidden relative shadow-inner">
          {/* Hardware Scanline Atmosphere */}
          <div className="absolute inset-0 scanlines opacity-30 pointer-events-none z-10" />

          {/* KeyOS Status Bar */}
          <div className="flex items-center justify-between pb-2 border-b border-[#181F2C] text-[11px] font-mono text-slate-400 z-20">
            <div className="flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-[#D4AF37]" />
              <span>KeyOS 1.1</span>
            </div>
            <div className="text-[10px] text-slate-500">
              SCOPE: <span className="text-amber-400">/user/incogid</span>
            </div>
            <div className="flex items-center gap-1">
              <span>98%</span>
              <BatteryCharging className="w-3 h-3 text-emerald-400" />
            </div>
          </div>

          {/* ===================================================================== */}
          {/* SCREEN ROUTER */}
          {/* ===================================================================== */}
          <div className="flex-1 overflow-y-auto py-2 z-20">
            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 1: VAULT HOME */}
            {/* ----------------------------------------------------------------- */}
            {currentScreen === "VAULT_HOME" && (
              <div className="flex flex-col h-full justify-between">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h2 className="text-sm font-bold tracking-wider text-slate-100 font-mono flex items-center gap-2">
                      <Fingerprint className="w-4 h-4 text-[#D4AF37]" />
                      INCOGID++ VAULT
                    </h2>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#181F2C] text-amber-300 font-mono">
                      {credentials.length} CREDENTIALS
                    </span>
                  </div>

                  {/* Device Holder Key Card */}
                  <div className="bg-[#0E121A] border border-[#212838] rounded-xl p-3 mb-3">
                    <div className="text-[10px] font-mono text-slate-400 uppercase">
                      Hardware Bound Identity Key
                    </div>
                    <div className="text-[11px] font-mono text-[#D4AF37] break-all mt-0.5 font-semibold">
                      {holderKey.publicKeyHex.slice(0, 20)}...{holderKey.publicKeyHex.slice(-12)}
                    </div>
                    <div className="text-[9px] font-mono text-slate-500 mt-1 flex justify-between">
                      <span>BIP32: {store.settings.activeDerivationPath}</span>
                      <span className="text-emerald-400">ATECC608C SEED OK</span>
                    </div>
                  </div>

                  {/* Stored Credentials List */}
                  <div className="text-[10px] font-mono text-slate-400 uppercase mb-1.5">
                    Sandboxed Credentials ({credentials.length})
                  </div>
                  {credentials.length === 0 ? (
                    <div className="p-4 bg-[#0E121A] border border-dashed border-[#232B3B] rounded-xl text-center text-xs text-slate-500 font-mono">
                      No credentials loaded.
                      <br />
                      Scan Step 2 Credential QR from Issuer.
                    </div>
                  ) : (
                    <div className="flex flex-col gap-1.5 max-h-[170px] overflow-y-auto pr-1">
                      {credentials.map((cred: StoredCredentialRecord, idx: number) => (
                        <div
                          key={idx}
                          className="p-2.5 bg-[#0E121A] hover:bg-[#141A24] border border-[#212838] rounded-xl flex items-center justify-between text-xs"
                        >
                          <div>
                            <div className="font-semibold text-slate-200 text-[11px]">
                              {cred.credential.issuer_name}
                            </div>
                            <div className="text-[9px] text-slate-400 font-mono">
                              {cred.disclosures.length} salted claims |{" "}
                              {cred.isIcaoPassport ? "ICAO e-Passport" : "Standard"}
                            </div>
                          </div>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                            VALID
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Quick Hardware Actions */}
                <div className="grid grid-cols-2 gap-2 mt-2">
                  <button
                    onClick={() => handleNav("SCAN_REQUEST")}
                    className="flex items-center justify-center gap-1.5 py-2 px-3 bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-xl font-bold text-xs transition-transform active:scale-95"
                  >
                    <Camera className="w-3.5 h-3.5" />
                    <span>Scan QR</span>
                  </button>
                  <button
                    onClick={() => handleNav("DEVICE_KEY_QR")}
                    className="flex items-center justify-center gap-1.5 py-2 px-3 bg-[#181F2C] hover:bg-[#222B3D] border border-[#2D374A] text-slate-200 rounded-xl text-xs font-mono transition-transform active:scale-95"
                  >
                    <QrCode className="w-3.5 h-3.5 text-[#D4AF37]" />
                    <span>Device Key</span>
                  </button>
                  <button
                    onClick={() => handleNav("RECEIPTS_LOG")}
                    className="flex items-center justify-center gap-1.5 py-2 px-3 bg-[#121620] hover:bg-[#1A202C] border border-[#212838] text-slate-300 rounded-xl text-xs font-mono"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Receipts ({receipts.length})</span>
                  </button>
                  <button
                    onClick={() => handleNav("SEED_SETTINGS")}
                    className="flex items-center justify-center gap-1.5 py-2 px-3 bg-[#121620] hover:bg-[#1A202C] border border-[#212838] text-slate-300 rounded-xl text-xs font-mono"
                  >
                    <Key className="w-3.5 h-3.5" />
                    <span>Seed / Keys</span>
                  </button>
                </div>
              </div>
            )}

            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 2: DEVICE KEY QR (STEP 1) */}
            {/* ----------------------------------------------------------------- */}
            {currentScreen === "DEVICE_KEY_QR" && (
              <div className="flex flex-col items-center justify-between h-full">
                <div className="w-full text-center">
                  <div className="text-[10px] font-mono text-amber-400 uppercase tracking-wider">
                    Step 1: Present Device Public Key
                  </div>
                  <h3 className="text-xs font-bold text-slate-200 mt-0.5">
                    Issuer Scans to Bind Credential
                  </h3>
                </div>

                <div className="my-1">
                  <QrCodeDisplay
                    data={holderKey.publicKeyHex}
                    size={160}
                    showRawToggle={false}
                  />
                </div>

                <div className="w-full bg-[#0E121A] border border-[#212838] rounded-xl p-2 text-center">
                  <div className="text-[9px] font-mono text-slate-500">secp256k1 Compressed Key</div>
                  <div className="text-[10px] font-mono text-[#D4AF37] break-all font-semibold">
                    {holderKey.publicKeyHex}
                  </div>
                </div>

                <div className="w-full flex gap-2">
                  <button
                    onClick={handlePhysicalBack}
                    className="flex-1 py-1.5 px-3 bg-[#181F2C] hover:bg-[#222B3D] text-slate-300 rounded-xl text-xs font-mono"
                  >
                    Back to Vault
                  </button>
                </div>
              </div>
            )}

            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 3: SCAN QR (CAMERA VIEWPORT) */}
            {/* ----------------------------------------------------------------- */}
            {(currentScreen === "SCAN_REQUEST" || currentScreen === "SCAN_ISSUANCE") && (
              <div className="flex flex-col items-center justify-between h-full">
                <div className="w-full text-center">
                  <div className="text-[10px] font-mono text-amber-400 uppercase tracking-wider">
                    Offline Optical Scanner
                  </div>
                  <h3 className="text-xs font-bold text-slate-200 mt-0.5">
                    Align QR Code in Target Reticle
                  </h3>
                </div>

                {/* Reticle Viewfinder */}
                <div className="w-56 h-56 border-2 border-dashed border-[#D4AF37]/60 rounded-2xl relative flex flex-col items-center justify-center p-3 my-2 bg-[#090C12]">
                  <div className="absolute top-2 left-2 w-4 h-4 border-t-2 border-l-2 border-[#D4AF37]" />
                  <div className="absolute top-2 right-2 w-4 h-4 border-t-2 border-r-2 border-[#D4AF37]" />
                  <div className="absolute bottom-2 left-2 w-4 h-4 border-b-2 border-l-2 border-[#D4AF37]" />
                  <div className="absolute bottom-2 right-2 w-4 h-4 border-b-2 border-r-2 border-[#D4AF37]" />

                  <Camera className="w-8 h-8 text-[#D4AF37]/50 animate-pulse mb-2" />
                  <span className="text-[10px] font-mono text-slate-400 text-center">
                    Simulated Air-Gap Sensor Active
                  </span>
                </div>

                {/* Direct Payload Bridge Input */}
                <div className="w-full">
                  <textarea
                    value={scanInputText}
                    onChange={(e) => setScanInputText(e.target.value)}
                    placeholder="Paste QR JSON payload or use 'Beam' bridge..."
                    className="w-full h-14 bg-[#0A0D13] border border-[#212838] rounded-xl p-2 text-[10px] font-mono text-slate-200 resize-none focus:outline-none focus:border-amber-500"
                  />
                  <div className="flex gap-2 mt-1">
                    <button
                      onClick={handlePhysicalBack}
                      className="flex-1 py-1.5 bg-[#181F2C] text-slate-300 rounded-xl text-xs font-mono"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => handleSimulateScan(scanInputText)}
                      disabled={!scanInputText.trim()}
                      className="flex-1 py-1.5 bg-amber-500 hover:bg-amber-400 disabled:opacity-40 text-slate-950 font-bold rounded-xl text-xs font-mono"
                    >
                      Process Scan
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 4: CONFIRM CREDENTIAL IMPORT (STEP 2) */}
            {/* ----------------------------------------------------------------- */}
            {currentScreen === "CONFIRM_IMPORT" && engine.pendingImport && (
              <div className="flex flex-col justify-between h-full">
                <div>
                  <div className="text-center mb-3">
                    <span className="text-[10px] font-mono text-amber-400 uppercase tracking-wider">
                      Step 2: Incoming Credential
                    </span>
                    <h3 className="text-sm font-bold text-slate-100 mt-0.5">
                      Verify & Import to Sandboxed Vault
                    </h3>
                  </div>

                  <div className="bg-[#0E121A] border border-[#212838] rounded-xl p-3 mb-2 space-y-2">
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-slate-400">Issuer Authority:</span>
                      <span className="font-semibold text-slate-200 font-mono">
                        {engine.pendingImport.pkg.credential.issuer_name}
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-slate-400">Device Key Bound:</span>
                      {engine.pendingImport.isBoundToDevice ? (
                        <span className="text-emerald-400 font-mono flex items-center gap-1 text-[11px]">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Bound to This Prime
                        </span>
                      ) : (
                        <span className="text-rose-400 font-mono flex items-center gap-1 text-[11px]">
                          <XCircle className="w-3.5 h-3.5" /> Key Mismatch!
                        </span>
                      )}
                    </div>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-slate-400">Salted Claims:</span>
                      <span className="text-amber-300 font-mono">
                        {engine.pendingImport.pkg.disclosures.length} items signed
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-slate-400">Expires:</span>
                      <span className="text-slate-300 font-mono text-[10px]">
                        {new Date(engine.pendingImport.pkg.credential.expires * 1000).toLocaleDateString()}
                      </span>
                    </div>
                  </div>

                  {/* Claims to be stored securely */}
                  <div className="text-[10px] font-mono text-slate-400 mb-1">
                    Enclosed Claims (Will remain private on device):
                  </div>
                  <div className="bg-[#090C12] border border-[#1C2330] rounded-xl p-2 max-h-24 overflow-y-auto space-y-1 text-[10px] font-mono">
                    {engine.pendingImport.pkg.disclosures.map((d: any, i: number) => (
                      <div key={i} className="flex justify-between text-slate-300">
                        <span className="text-slate-400">{d.key}:</span>
                        <span className="text-amber-300">{d.value}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2 mt-2">
                  <button
                    onClick={handlePhysicalBack}
                    className="flex-1 py-2 bg-[#181F2C] hover:bg-[#222B3D] text-slate-300 font-mono text-xs rounded-xl"
                  >
                    Reject (Back)
                  </button>
                  <button
                    onClick={handlePhysicalOk}
                    disabled={!engine.pendingImport.isBoundToDevice}
                    className="flex-1 py-2 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-40 text-slate-950 font-bold font-mono text-xs rounded-xl"
                  >
                    Save to Vault (OK)
                  </button>
                </div>
              </div>
            )}

            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 5: REVIEW DISCLOSURE (STEP 3 CORE MOMENT) */}
            {/* ----------------------------------------------------------------- */}
            {currentScreen === "REVIEW_DISCLOSURE" && engine.pendingRequest && (
              <div className="flex flex-col justify-between h-full">
                <div>
                  {/* Requester Identity & Trust Status */}
                  <div className="mb-2.5">
                    {engine.pendingRequest.isVerifiedRequester ? (
                      <div className="bg-emerald-950/60 border border-emerald-500/50 rounded-xl p-2 flex items-center gap-2">
                        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                        <div>
                          <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 font-mono">
                            Verified Requester
                          </div>
                          <div className="text-xs font-semibold text-slate-100">
                            {engine.pendingRequest.request.verifier_name}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="bg-rose-950/70 border border-rose-500/60 rounded-xl p-2 flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 animate-pulse" />
                        <div>
                          <div className="text-[10px] font-bold uppercase tracking-wider text-rose-400 font-mono">
                            Unknown Requester Alert
                          </div>
                          <div className="text-xs font-semibold text-slate-100">
                            {engine.pendingRequest.request.verifier_name}
                          </div>
                          <div className="text-[9px] text-rose-300">
                            Key not in KeyOS on-device registry!
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* The Pivotal Claim Disclosure Diff */}
                  <div className="bg-[#0E121A] border border-[#212838] rounded-xl p-3 mb-2">
                    <div className="text-[10px] font-mono text-slate-400 uppercase mb-1">
                      Target Claim Requested:
                    </div>
                    <div className="text-sm font-bold text-amber-300 font-mono">
                      {engine.pendingRequest.revealedClaimKey} :{" "}
                      <span className="text-emerald-400 font-mono">
                        {String(engine.pendingRequest.revealedClaimValue)}
                      </span>
                    </div>
                  </div>

                  {/* What Leaves vs What Stays */}
                  <div className="space-y-1.5 text-xs font-mono">
                    <div className="p-2 bg-emerald-950/40 border border-emerald-800/40 rounded-xl">
                      <div className="text-[9px] uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Shared with Requester:
                      </div>
                      <div className="text-[11px] text-slate-200 mt-0.5 font-bold">
                        {engine.pendingRequest.revealedClaimKey} = {String(engine.pendingRequest.revealedClaimValue)}
                      </div>
                    </div>

                    <div className="p-2 bg-[#090C12] border border-[#1A212E] rounded-xl">
                      <div className="text-[9px] uppercase tracking-wider text-slate-400 font-bold flex items-center gap-1">
                        <Lock className="w-3 h-3 text-amber-400" /> Kept 100% Private on Passport Prime:
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5 line-through">
                        {engine.pendingRequest.concealedClaimKeys.join(", ")}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Hardware Physical Approve / Deny Buttons */}
                <div className="flex gap-2 mt-2">
                  <button
                    onClick={handlePhysicalBack}
                    className="flex-1 py-2 bg-rose-950/80 hover:bg-rose-900 border border-rose-800/60 text-rose-300 font-mono font-bold text-xs rounded-xl"
                  >
                    DENY (Back)
                  </button>
                  <button
                    onClick={handlePhysicalOk}
                    className="flex-1 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs rounded-xl"
                  >
                    APPROVE (Center)
                  </button>
                </div>
              </div>
            )}

            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 6: SHOW ANSWER QR (STEP 4) */}
            {/* ----------------------------------------------------------------- */}
            {currentScreen === "SHOW_ANSWER_QR" && engine.activeAnswer && (
              <div className="flex flex-col items-center justify-between h-full">
                <div className="w-full text-center">
                  <div className="text-[10px] font-mono text-emerald-400 uppercase tracking-wider">
                    Step 4: Present Signed Answer
                  </div>
                  <h3 className="text-xs font-bold text-slate-200 mt-0.5">
                    Verifier Scans to Check Proof
                  </h3>
                </div>

                <div className="my-1">
                  <QrCodeDisplay
                    data={engine.activeAnswer}
                    size={155}
                    showRawToggle={false}
                  />
                </div>

                <div className="w-full bg-[#0E121A] border border-[#212838] rounded-xl p-2 text-center text-[10px] font-mono">
                  <span className="text-slate-400">Revealed: </span>
                  <span className="text-emerald-400 font-bold">
                    {engine.activeAnswer.disclosed_claim.key} = {engine.activeAnswer.disclosed_claim.value}
                  </span>
                  <div className="text-[9px] text-slate-500 mt-0.5">
                    Nonce: {engine.activeAnswer.request_context.nonce.slice(0, 12)}...
                  </div>
                </div>

                <div className="w-full flex gap-2">
                  {onBeamAnswerToVerifier && (
                    <button
                      onClick={() => onBeamAnswerToVerifier(engine.activeAnswer)}
                      className="flex-1 py-1.5 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 text-slate-950 font-bold font-mono text-[11px] rounded-xl flex items-center justify-center gap-1"
                    >
                      <Radio className="w-3.5 h-3.5" /> Beam to Verifier
                    </button>
                  )}
                  <button
                    onClick={handlePhysicalBack}
                    className="py-1.5 px-3 bg-[#181F2C] hover:bg-[#222B3D] text-slate-300 font-mono text-xs rounded-xl"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}

            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 7: PRIVACY RECEIPTS LOG */}
            {/* ----------------------------------------------------------------- */}
            {currentScreen === "RECEIPTS_LOG" && (
              <div className="flex flex-col justify-between h-full">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xs font-bold font-mono text-slate-100 flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-[#D4AF37]" /> PRIVACY RECEIPTS AUDIT
                    </h3>
                    <span className="text-[10px] font-mono text-emerald-400">
                      {stats.privacyShieldRatio}% Data Shielded
                    </span>
                  </div>

                  <div className="bg-[#0E121A] border border-[#212838] rounded-xl p-2 mb-2 text-[10px] font-mono flex justify-between">
                    <div>Total: {stats.totalRequests}</div>
                    <div className="text-emerald-400">Approved: {stats.approvedCount}</div>
                    <div className="text-rose-400">Denied: {stats.deniedCount}</div>
                  </div>

                  {receipts.length === 0 ? (
                    <div className="p-4 bg-[#0E121A] border border-[#212838] rounded-xl text-center text-xs text-slate-500 font-mono">
                      No presentations yet.
                    </div>
                  ) : (
                    <div className="space-y-1.5 max-h-[220px] overflow-y-auto pr-1">
                      {receipts.map((r: any) => (
                        <div
                          key={r.id}
                          onClick={() => setSelectedReceipt(r)}
                          className="p-2 bg-[#0E121A] hover:bg-[#141A24] border border-[#212838] rounded-xl text-[10px] font-mono cursor-pointer"
                        >
                          <div className="flex justify-between items-center">
                            <span className="font-semibold text-slate-200">
                              {r.verifier_name.slice(0, 24)}
                            </span>
                            <span
                              className={`px-1.5 py-0.2 rounded ${
                                r.decision === "APPROVED"
                                  ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                                  : "bg-rose-950 text-rose-400 border border-rose-800"
                              }`}
                            >
                              {r.decision}
                            </span>
                          </div>
                          <div className="text-slate-400 mt-1 flex justify-between">
                            <span>Claim: {r.requested_claim}</span>
                            <span>{new Date(r.timestamp * 1000).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <button
                  onClick={handlePhysicalBack}
                  className="w-full py-2 bg-[#181F2C] hover:bg-[#222B3D] text-slate-300 font-mono text-xs rounded-xl mt-2"
                >
                  Back to Vault
                </button>
              </div>
            )}

            {/* ----------------------------------------------------------------- */}
            {/* SCREEN 8: SEED & SECURITY SETTINGS */}
            {/* ----------------------------------------------------------------- */}
            {currentScreen === "SEED_SETTINGS" && (
              <div className="flex flex-col justify-between h-full text-xs font-mono">
                <div>
                  <h3 className="font-bold text-slate-100 mb-2 flex items-center gap-1.5">
                    <Key className="w-3.5 h-3.5 text-[#D4AF37]" /> HARDWARE SEED & KEYS
                  </h3>

                  <div className="bg-[#0E121A] border border-[#212838] rounded-xl p-3 mb-2 space-y-2 text-[11px]">
                    <div>
                      <div className="text-slate-400 text-[10px]">Active Derivation Path:</div>
                      <div className="text-[#D4AF37] font-semibold">
                        {store.settings.activeDerivationPath}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">Unlinkable Batch Keys:</div>
                      <div className="text-slate-300">
                        {store.settings.useUnlinkableKeys ? "ENABLED" : "STANDARD (Static Identity)"}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">Secure Element Status:</div>
                      <div className="text-emerald-400">Microchip ATECC608C ONLINE</div>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <button
                      onClick={() => setShowSeedModal(true)}
                      className="w-full py-2 bg-[#121620] hover:bg-[#1A202C] border border-[#212838] text-amber-300 rounded-xl text-left px-3 flex items-center justify-between"
                    >
                      <span>View Mnemonic Seed Words</span>
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => {
                        const newMnemonic = store.generateNewSeed();
                        alert("Generated new fresh BIP39 seed!");
                        rerender();
                      }}
                      className="w-full py-2 bg-[#121620] hover:bg-[#1A202C] border border-[#212838] text-slate-300 rounded-xl text-left px-3 flex items-center justify-between"
                    >
                      <span>Generate Fresh Device Seed</span>
                      <RotateCcw className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <button
                  onClick={handlePhysicalBack}
                  className="w-full py-2 bg-[#181F2C] hover:bg-[#222B3D] text-slate-300 font-mono text-xs rounded-xl mt-2"
                >
                  Back to Vault
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ========================================================================= */}
        {/* PHYSICAL HARDWARE CONTROLS (Tactile D-Pad & Action Keys) */}
        {/* ========================================================================= */}
        <div className="pt-4 pb-1 flex flex-col items-center">
          {/* Hardware Navigation & Action Pad */}
          <div className="relative w-40 h-40 flex items-center justify-center">
            {/* D-Pad Background Circle with Metallic Ring */}
            <div className="absolute inset-0 rounded-full bg-gradient-to-b from-[#1C2028] to-[#0F1218] border-2 border-[#2F374A] shadow-lg" />

            {/* D-Pad Up */}
            <button
              onClick={() => engine.pressDpadUp()}
              className="absolute top-1.5 w-11 h-9 rounded-t-xl bg-[#242A36] hover:bg-[#2E3646] active:bg-[#181C24] text-slate-300 flex items-center justify-center text-xs font-mono transition-colors tactile-button border-t border-x border-[#384254]"
              title="Up"
            >
              ▲
            </button>

            {/* D-Pad Down */}
            <button
              onClick={() => engine.pressDpadDown()}
              className="absolute bottom-1.5 w-11 h-9 rounded-b-xl bg-[#242A36] hover:bg-[#2E3646] active:bg-[#181C24] text-slate-300 flex items-center justify-center text-xs font-mono transition-colors tactile-button border-b border-x border-[#384254]"
              title="Down"
            >
              ▼
            </button>

            {/* D-Pad Left */}
            <button
              onClick={handlePhysicalBack}
              className="absolute left-1.5 h-11 w-9 rounded-l-xl bg-[#242A36] hover:bg-[#2E3646] active:bg-[#181C24] text-slate-300 flex items-center justify-center text-xs font-mono transition-colors tactile-button border-l border-y border-[#384254]"
              title="Left / Back"
            >
              ◄
            </button>

            {/* D-Pad Right */}
            <button
              onClick={handlePhysicalOk}
              className="absolute right-1.5 h-11 w-9 rounded-r-xl bg-[#242A36] hover:bg-[#2E3646] active:bg-[#181C24] text-slate-300 flex items-center justify-center text-xs font-mono transition-colors tactile-button border-r border-y border-[#384254]"
              title="Right / Forward"
            >
              ►
            </button>

            {/* Center Hardware OK Button (Brushed Brass Finish) */}
            <button
              onClick={handlePhysicalOk}
              className="w-14 h-14 rounded-full bg-gradient-to-br from-[#E5B94E] via-[#D4AF37] to-[#8C6D14] hover:brightness-110 active:scale-95 text-slate-950 font-bold font-mono text-xs flex items-center justify-center shadow-md tactile-button border-2 border-[#FFF0B3]/40 z-10"
              title="Hardware OK / Approve"
            >
              OK
            </button>
          </div>

          {/* Dedicated Back & Scan Physical Buttons */}
          <div className="w-full flex justify-between px-6 mt-3">
            <button
              onClick={handlePhysicalBack}
              className="py-1.5 px-4 bg-[#1A202A] hover:bg-[#252E3C] border border-[#2E3747] text-slate-300 rounded-xl text-xs font-mono tactile-button"
            >
              BACK
            </button>

            <button
              onClick={() => handleNav("SCAN_REQUEST")}
              className="py-1.5 px-4 bg-[#1A202A] hover:bg-[#252E3C] border border-[#2E3747] text-amber-300 rounded-xl text-xs font-mono tactile-button flex items-center gap-1"
            >
              <Camera className="w-3.5 h-3.5" /> SCAN
            </button>
          </div>
        </div>
      </div>

      {/* Mnemonic Seed View Modal */}
      {showSeedModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-[#0E121A] border border-[#2A3345] rounded-2xl p-5 max-w-sm w-full text-slate-200">
            <h3 className="font-bold text-sm text-amber-300 font-mono mb-2">
              BIP39 Hardware Mnemonic
            </h3>
            <p className="text-xs text-slate-400 mb-3">
              These 12 words deterministically restore all holder keys and credentials.
            </p>
            <div className="p-3 bg-[#06080C] border border-[#1C2330] rounded-xl font-mono text-xs leading-relaxed text-emerald-400 select-all">
              {store.getMnemonic()}
            </div>
            <button
              onClick={() => setShowSeedModal(false)}
              className="w-full mt-4 py-2 bg-[#1A212E] hover:bg-[#252E3F] text-slate-200 text-xs font-mono rounded-xl"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
