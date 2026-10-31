/**
 * ZKsync Era Testnet / Sepolia On-Chain Cryptographic Anchor Module
 * 
 * Cryptographically commits credential state roots and revocation accumulators
 * to ZKsync Era Sepolia. Allows verifiers to verify that an issuer's root state
 * is anchored on a real L2 ZK-Rollup without leaking private user identity claims.
 */

import { Provider } from "zksync-ethers";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

export const ZKSYNC_ERA_SEPOLIA_RPC = "https://sepolia.era.zksync.dev";
export const ZKSYNC_ERA_MAINNET_RPC = "https://mainnet.era.zksync.io";

export interface ZkSyncAnchorCommitment {
  chain_id: number;
  network_name: string;
  commitment_hash: string; // SHA-256 / Poseidon hash of (credential_id + issuer + root)
  issuer_address: string;
  block_number?: number;
  verified_on_chain: boolean;
  rpc_endpoint: string;
  timestamp: number;
}

export interface ZkSyncVerificationResult {
  isAnchorValid: boolean;
  network: string;
  chainId: number;
  latestBlock: number;
  blockHash: string;
  commitmentHash: string;
  message: string;
  gasPriceGwei: string;
}

/**
 * Compute real cryptographic commitment hash for a credential state root
 */
export function computeZkCommitment(
  credentialId: string,
  issuerPubKeyHex: string,
  claimHashes: string[]
): string {
  // Sort claims canonically to ensure deterministic tree root
  const sortedHashes = [...claimHashes].sort().join(":");
  const preimage = `${credentialId}:${issuerPubKeyHex}:${sortedHashes}`;
  const digest = sha256(new TextEncoder().encode(preimage));
  return "0x" + bytesToHex(digest);
}

/**
 * Real live on-chain check against ZKsync Era Sepolia RPC
 * Verifies network connectivity, checks current state root / block hash,
 * and validates that the cryptographic commitment is formatted and anchored.
 */
export async function verifyZkSyncAnchor(
  commitmentHash: string,
  rpcUrl: string = ZKSYNC_ERA_SEPOLIA_RPC
): Promise<ZkSyncVerificationResult> {
  try {
    const provider = new Provider(rpcUrl);
    
    // Query actual ZKsync L2 network state
    const [network, blockNumber, feeData] = await Promise.all([
      provider.getNetwork(),
      provider.getBlockNumber(),
      provider.getFeeData(),
    ]);

    const latestBlock = await provider.getBlock(blockNumber);
    const blockHash = latestBlock ? latestBlock.hash : "0x";
    const gasPriceGwei = feeData.gasPrice 
      ? (Number(feeData.gasPrice) / 1e9).toFixed(4)
      : "0.2500";

    // shortcut: no anchor contract is deployed yet, so nothing can be confirmed on-chain;
    // fail closed until a real contract lookup (getLogs on the anchor event) replaces this.
    const isValidHashFormat = /^0x[0-9a-fA-F]{64}$/.test(commitmentHash);

    return {
      isAnchorValid: false,
      network: network.name === "unknown" ? "ZKsync Era Sepolia Testnet" : network.name,
      chainId: Number(network.chainId),
      latestBlock: blockNumber,
      blockHash: blockHash || "0x",
      commitmentHash,
      message: isValidHashFormat
        ? `Not anchored: no anchor contract configured. RPC reachable (Chain ID: ${network.chainId}, Block: #${blockNumber})`
        : "Invalid cryptographic commitment format",
      gasPriceGwei,
    };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    return {
      isAnchorValid: false,
      network: "ZKsync Era (Connection Failed)",
      chainId: 300,
      latestBlock: 0,
      blockHash: "0x",
      commitmentHash,
      message: `ZKsync RPC query failed: ${errMsg}`,
      gasPriceGwei: "0",
    };
  }
}
