import React from "react";
import type { AnswerVerdict } from "@core-crypto";
import { registryEnabled } from "../lib/store";

export const VerdictView: React.FC<{ verdict: AnswerVerdict }> = ({ verdict }) => (
  <div className="space-y-2">
    <div className={`rounded-xl px-4 py-3 border text-sm font-semibold ${verdict.ok ? "border-emerald-600 bg-emerald-950/40 text-emerald-300" : "border-rose-600 bg-rose-950/40 text-rose-300"}`}>
      {verdict.ok ? `ACCEPTED: ${verdict.claim!.key} = ${verdict.claim!.value}` : "REJECTED"}
      {verdict.ok && <span className="block text-xs font-normal text-emerald-400/80 mt-1">Issued by {verdict.issuerName}. Nothing else about the holder was revealed.</span>}
    </div>
    <ol className="space-y-1">
      {verdict.steps.map((s, i) => (
        <li key={i} className="flex gap-2 text-xs">
          <span className={s.ok ? "text-emerald-400" : "text-rose-400"}>{s.ok ? "PASS" : "FAIL"}</span>
          <span className="text-slate-200 font-semibold w-36 shrink-0">{s.name}</span>
          <span className="text-slate-400">{s.detail}</span>
        </li>
      ))}
      {!registryEnabled && verdict.ok && (
        <li className="flex gap-2 text-xs">
          <span className="text-amber-400">SKIP</span>
          <span className="text-slate-200 font-semibold w-36 shrink-0">Revocation</span>
          <span className="text-slate-400">No registry configured (VITE_PRIMEID_REGISTRY)</span>
        </li>
      )}
    </ol>
  </div>
);
