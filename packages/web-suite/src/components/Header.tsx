import React from "react";
import {
  ShieldCheck,
  Building2,
  ScanLine,
  Smartphone,
  Flame,
  Nfc,
  Layers,
  Lock,
} from "lucide-react";

export type ViewMode =
  | "ECOSYSTEM"
  | "DEVICE"
  | "ISSUER"
  | "VERIFIER"
  | "RED_TEAM"
  | "ICAO_NFC";

interface HeaderProps {
  currentMode: ViewMode;
  onSelectMode: (mode: ViewMode) => void;
  holderPubKey: string;
}

export const Header: React.FC<HeaderProps> = ({
  currentMode,
  onSelectMode,
  holderPubKey,
}) => {
  return (
    <header className="border-b border-[#1E2433] bg-[#080A0E]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Logo & Tagline */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#E5B94E] to-[#997A15] p-0.5 flex items-center justify-center shadow-goldGlow">
            <div className="w-full h-full bg-[#080A0E] rounded-[10px] flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-amber-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold font-mono text-sm tracking-wider text-slate-100 uppercase">
                IncogID<span className="text-amber-400">++</span>
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#181F2C] text-slate-300 border border-[#2B3547]">
                Passport Prime (KeyOS)
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans italic">
              Prove the fact, keep the document.
            </p>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <nav className="flex items-center gap-1 bg-[#0E121A] p-1 rounded-xl border border-[#212838]">
          <button
            onClick={() => onSelectMode("ECOSYSTEM")}
            className={`flex items-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-mono transition-all ${
              currentMode === "ECOSYSTEM"
                ? "bg-amber-500 text-slate-950 font-bold shadow-md"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>3-Party Ecosystem</span>
          </button>

          <button
            onClick={() => onSelectMode("DEVICE")}
            className={`flex items-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-mono transition-all ${
              currentMode === "DEVICE"
                ? "bg-amber-500 text-slate-950 font-bold shadow-md"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Smartphone className="w-3.5 h-3.5" />
            <span>Passport Prime</span>
          </button>

          <button
            onClick={() => onSelectMode("ISSUER")}
            className={`flex items-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-mono transition-all ${
              currentMode === "ISSUER"
                ? "bg-amber-500 text-slate-950 font-bold shadow-md"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Building2 className="w-3.5 h-3.5" />
            <span>Issuer Studio</span>
          </button>

          <button
            onClick={() => onSelectMode("VERIFIER")}
            className={`flex items-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-mono transition-all ${
              currentMode === "VERIFIER"
                ? "bg-amber-500 text-slate-950 font-bold shadow-md"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <ScanLine className="w-3.5 h-3.5" />
            <span>Verifier Terminal</span>
          </button>

          <button
            onClick={() => onSelectMode("RED_TEAM")}
            className={`flex items-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-mono transition-all ${
              currentMode === "RED_TEAM"
                ? "bg-rose-500 text-white font-bold shadow-md"
                : "text-rose-400 hover:text-rose-300"
            }`}
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Red-Team Testbed</span>
          </button>

          <button
            onClick={() => onSelectMode("ICAO_NFC")}
            className={`flex items-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-mono transition-all ${
              currentMode === "ICAO_NFC"
                ? "bg-amber-500 text-slate-950 font-bold shadow-md"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Nfc className="w-3.5 h-3.5" />
            <span>ICAO e-Passport</span>
          </button>
        </nav>

        {/* Active Key Status */}
        <div className="hidden lg:flex items-center gap-2 font-mono text-[11px] bg-[#0E121A] py-1.5 px-3 rounded-xl border border-[#212838]">
          <Lock className="w-3 h-3 text-[#D4AF37]" />
          <span className="text-slate-400">Prime Key:</span>
          <span className="text-amber-400 font-semibold">
            {holderPubKey.slice(0, 10)}...{holderPubKey.slice(-6)}
          </span>
        </div>
      </div>
    </header>
  );
};
