/**
 * Relays an issuer-signed revocation through the user's own browser wallet (EIP-1193).
 * The wallet only pays gas; the revocation's authority is the issuer signature in the calldata.
 * No wallet key ever touches this app.
 */

import { encodeRevoke, signRevocation, waitForReceipt } from "@core-crypto";
import { registryConfig } from "./store";

interface Eip1193 { request(args: { method: string; params?: unknown[] }): Promise<unknown> }

export const walletAvailable = () => typeof window !== "undefined" && !!(window as unknown as { ethereum?: Eip1193 }).ethereum;

export async function relayRevocation(issuerPriv: string, credId: string, onTx: (hash: string) => void): Promise<boolean> {
  const eth = (window as unknown as { ethereum?: Eip1193 }).ethereum;
  if (!eth) throw new Error("No browser wallet found. Install one to pay gas on ZKsync Sepolia.");
  const [from] = (await eth.request({ method: "eth_requestAccounts" })) as string[];
  const chainHex = "0x" + registryConfig.chainId.toString(16);
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainHex }] });
  } catch {
    throw new Error(`Switch your wallet to chain ${registryConfig.chainId} (ZKsync Sepolia) and try again.`);
  }
  const sig = signRevocation(issuerPriv, registryConfig.address, registryConfig.chainId, credId);
  const hash = (await eth.request({
    method: "eth_sendTransaction",
    params: [{ from, to: registryConfig.address, data: encodeRevoke(credId, sig) }],
  })) as string;
  onTx(hash);
  return waitForReceipt(registryConfig.rpcUrl, hash);
}
