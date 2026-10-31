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
          <img src="/logo.png" alt="PrimeID" className="w-9 h-9 rounded-full border border-white/20 bg-white/5 p-1" />
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold font-mono text-sm tracking-wider text-slate-100 uppercase">
                PrimeID
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

        </nav>

      </div>
    </header>
  );
};
