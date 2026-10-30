/**
 * Client for the PrimeID revocation registry on ZKsync (contracts/PrimeIdRevocationRegistry.sol).
 *
 * The issuer's PrimeID key is secp256k1, so it maps to an Ethereum address. A revocation is a
 * signature by that key, checked on chain with ecrecover: any wallet may pay the gas, only the
 * issuer can revoke. Verifiers read it with a plain eth_call; no wallet needed.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { isHex } from "./crypto";

export const ZKSYNC_SEPOLIA = { chainId: 300, rpcUrl: "https://sepolia.era.zksync.dev", explorer: "https://sepolia.explorer.zksync.io" };

const strip0x = (h: string) => (h.startsWith("0x") ? h.slice(2) : h);

export function selector(signature: string): string {
  return bytesToHex(keccak_256(utf8ToBytes(signature))).slice(0, 8);
}

/** Ethereum address (lowercase 0x hex) of a compressed secp256k1 public key. */
export function ethAddressOf(pubHex: string): string {
  const uncompressed = secp256k1.ProjectivePoint.fromHex(pubHex).toRawBytes(false);
  return "0x" + bytesToHex(keccak_256(uncompressed.slice(1))).slice(-40);
}

/** PrimeID credential ids are 16 bytes; on chain they are left-padded to bytes32. */
export function credIdToBytes32(credId: string): string {
  if (!isHex(credId, 16)) throw new Error("Credential id must be 16-byte hex");
  return credId.padStart(64, "0");
}

function checkAddress(addr: string): string {
  const h = strip0x(addr).toLowerCase();
  if (!isHex(h, 20)) throw new Error("Not an Ethereum address");
  return h;
}

const uint256 = (n: number | bigint) => BigInt(n).toString(16).padStart(64, "0");

/** Matches PrimeIdRevocationRegistry.digest: EIP-191 hash of keccak(registry ‖ chainId ‖ id). */
export function revocationDigest(registry: string, chainId: number, credId: string): Uint8Array {
  const inner = keccak_256(
    concatBytes(hexToBytes(checkAddress(registry)), hexToBytes(uint256(chainId)), hexToBytes(credIdToBytes32(credId))),
  );
  return keccak_256(concatBytes(utf8ToBytes("\x19Ethereum Signed Message:\n32"), inner));
}

export interface RevocationSig { v: number; r: string; s: string }

export function signRevocation(issuerPriv: string, registry: string, chainId: number, credId: string): RevocationSig {
  const sig = secp256k1.sign(revocationDigest(registry, chainId, credId), hexToBytes(issuerPriv), { lowS: true });
  return { v: sig.recovery + 27, r: sig.r.toString(16).padStart(64, "0"), s: sig.s.toString(16).padStart(64, "0") };
}

/** Address that signed a revocation, as ecrecover computes it on chain. */
export function recoverRevoker(sig: RevocationSig, registry: string, chainId: number, credId: string): string {
  const s = new secp256k1.Signature(BigInt("0x" + sig.r), BigInt("0x" + sig.s)).addRecoveryBit(sig.v - 27);
  const pub = s.recoverPublicKey(revocationDigest(registry, chainId, credId));
  return ethAddressOf(pub.toHex(true));
}

export function encodeRevoke(credId: string, sig: RevocationSig): string {
  return "0x" + selector("revoke(bytes32,uint8,bytes32,bytes32)") + credIdToBytes32(credId) + uint256(sig.v) + sig.r + sig.s;
}

export function encodeIsRevoked(issuerAddress: string, credId: string): string {
  return "0x" + selector("isRevoked(address,bytes32)") + checkAddress(issuerAddress).padStart(64, "0") + credIdToBytes32(credId);
}

async function rpc(rpcUrl: string, method: string, params: unknown[], fetchFn: typeof fetch): Promise<unknown> {
  const res = await fetchFn(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
  if (body.error) throw new Error(body.error.message ?? "RPC error");
  return body.result;
}

/** true / false from the registry, or null if it could not be read (caller must fail closed). */
export async function checkRevoked(
  rpcUrl: string,
  registry: string,
  issuerPub: string,
  credId: string,
  fetchFn: typeof fetch = fetch,
): Promise<boolean | null> {
  try {
    const out = await rpc(rpcUrl, "eth_call", [{ to: registry, data: encodeIsRevoked(ethAddressOf(issuerPub), credId) }, "latest"], fetchFn);
    if (typeof out !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(out)) return null;
    return BigInt(out) !== 0n;
  } catch {
    return null;
  }
}

/** Polls for a transaction receipt. Returns true once mined successfully, false if it reverted. */
export async function waitForReceipt(rpcUrl: string, txHash: string, timeoutMs = 120_000, fetchFn: typeof fetch = fetch): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = (await rpc(rpcUrl, "eth_getTransactionReceipt", [txHash], fetchFn)) as { status?: string } | null;
    if (r && r.status) return r.status === "0x1";
    await new Promise((ok) => setTimeout(ok, 2000));
  }
  throw new Error("Timed out waiting for the transaction to be mined");
}
