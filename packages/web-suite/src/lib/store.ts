/**
 * Public, non-secret settings kept in localStorage: trusted issuer keys, the verifier's
 * certificate, answered nonces, and the issuer's log of credential ids. No claim values.
 */

import { useCallback, useState } from "react";
import { ZKSYNC_SEPOLIA, type VerifierCert } from "@core-crypto";

export interface TrustedIssuer { pub: string; name: string }
export interface IssuedRecord {
  id: string;
  issuer: string;
  holderPub: string;
  claimKeys: string[];
  iat: number;
  exp: number;
  revokeTx?: string;
  revoked?: boolean;
}

export const KEYS = {
  trusted: "primeid.trustedIssuers",
  cert: "primeid.verifierCert",
  nonces: "primeid.usedNonces",
  issued: "primeid.issued",
} as const;

export function load<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

export function save<T>(key: string, value: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable: settings stay in memory for this tab */
  }
}

export function usePersistent<T>(key: string, fallback: T): [T, (next: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => load(key, fallback));
  const set = useCallback(
    (next: T | ((prev: T) => T)) =>
      setValue((prev) => {
        const v = typeof next === "function" ? (next as (p: T) => T)(prev) : next;
        save(key, v);
        return v;
      }),
    [key],
  );
  return [value, set];
}

export type { VerifierCert };

const env = import.meta.env;
export const registryConfig = {
  rpcUrl: (env.VITE_ZKSYNC_RPC_URL as string | undefined) || ZKSYNC_SEPOLIA.rpcUrl,
  chainId: Number(env.VITE_ZKSYNC_CHAIN_ID || ZKSYNC_SEPOLIA.chainId),
  explorer: (env.VITE_ZKSYNC_EXPLORER as string | undefined) || ZKSYNC_SEPOLIA.explorer,
  /** Deployed PrimeIdRevocationRegistry address. Empty = revocation not configured. */
  address: ((env.VITE_PRIMEID_REGISTRY as string | undefined) || "").trim(),
};
export const registryEnabled = /^0x[0-9a-fA-F]{40}$/.test(registryConfig.address);
