import React from "react";
import { clsx } from "clsx";

export const Section: React.FC<{ title: string; step?: string; children: React.ReactNode; className?: string }> = ({ title, step, children, className }) => (
  <section className={clsx("bg-foundation-card border border-foundation-border rounded-2xl p-5", className)}>
    <h2 className="text-sm font-semibold tracking-wide text-foundation-gold uppercase mb-4 font-mono">
      {step && <span className="text-slate-500 mr-2">{step}</span>}
      {title}
    </h2>
    <div className="space-y-3">{children}</div>
  </section>
);

type BtnProps = React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" };

export const Btn: React.FC<BtnProps> = ({ variant = "primary", className, ...rest }) => (
  <button
    {...rest}
    className={clsx(
      "px-4 py-2 rounded-xl text-sm font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed",
      variant === "primary" && "bg-foundation-gold text-slate-950 hover:bg-foundation-accent",
      variant === "secondary" && "bg-[#181D26] border border-[#2B3342] text-slate-200 hover:bg-[#202733]",
      variant === "danger" && "bg-rose-600/90 text-white hover:bg-rose-500",
      className,
    )}
  />
);

export const Field: React.FC<React.InputHTMLAttributes<HTMLInputElement> & { label: string }> = ({ label, className, ...rest }) => (
  <label className="block">
    <span className="block text-xs text-slate-400 mb-1">{label}</span>
    <input
      {...rest}
      className={clsx("w-full bg-[#07090C] border border-foundation-border rounded-lg px-3 py-2 text-sm text-slate-100 font-mono focus:outline-none focus:border-foundation-gold", className)}
    />
  </label>
);

export const Note: React.FC<{ tone?: "info" | "ok" | "warn" | "bad"; children: React.ReactNode }> = ({ tone = "info", children }) => (
  <div
    className={clsx(
      "text-xs rounded-lg px-3 py-2 border",
      tone === "info" && "text-slate-300 border-foundation-border bg-[#0D1016]",
      tone === "ok" && "text-emerald-300 border-emerald-700/50 bg-emerald-950/30",
      tone === "warn" && "text-amber-300 border-amber-700/50 bg-amber-950/30",
      tone === "bad" && "text-rose-300 border-rose-700/50 bg-rose-950/30",
    )}
  >
    {children}
  </div>
);

export const Mono: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span className="font-mono text-foundation-goldLight break-all">{children}</span>
);

export const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
