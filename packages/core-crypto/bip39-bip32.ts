/**
 * BIP39 / BIP32 Deterministic Seed & Key Derivation
 * Conforms to Foundation Passport Prime hardware security model:
 * Master seed derived from 12 or 24 mnemonic words.
 * IncogID++ key hierarchy:
 *   - Primary Vault Key: m/1337'/0'/0'/0/0 (Standard Holder Identity)
 *   - Unlinkable One-Time Keys: m/1337'/0'/0'/1/{index} (Batch presentations preventing linkability)
 */

import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HDKey } from "@scure/bip32";
import { bytesToHex } from "./secp256k1";
import { KeyPair } from "./secp256k1";

export const INCOGID_BASE_DERIVATION_PATH = "m/1337'/0'/0'/0/0";

/**
 * Generates a standard BIP39 12-word mnemonic phrase.
 */
export function generateMnemonic(words: 12 | 24 = 12): string {
  const strength = words === 24 ? 256 : 128;
  return bip39.generateMnemonic(wordlist, strength);
}

/**
 * Validates a BIP39 mnemonic phrase.
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic.trim(), wordlist);
}

/**
 * Converts mnemonic to 64-byte seed.
 */
export function mnemonicToSeed(mnemonic: string, passphrase = ""): Uint8Array {
  return bip39.mnemonicToSeedSync(mnemonic.trim(), passphrase);
}

/**
 * Derives a keypair at a specific BIP32 derivation path from a mnemonic.
 */
export function deriveKeyPairFromMnemonic(
  mnemonic: string,
  path: string = INCOGID_BASE_DERIVATION_PATH,
  passphrase = ""
): KeyPair {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  const root = HDKey.fromMasterSeed(seed);
  const child = root.derive(path);

  if (!child.privateKey) {
    throw new Error(`Failed to derive private key at path ${path}`);
  }

  const pubKeyHex = bytesToHex(child.publicKey!);
  const privKeyHex = bytesToHex(child.privateKey);

  return {
    privateKeyHex: privKeyHex,
    publicKeyHex: pubKeyHex,
  };
}

/**
 * Derives an unlinkable, one-time child key for batch privacy presentations.
 * Path: m/1337'/0'/0'/1/{index}
 */
export function deriveUnlinkableChildKey(
  mnemonic: string,
  index: number,
  passphrase = ""
): KeyPair {
  const path = `m/1337'/0'/0'/1/${index}`;
  return deriveKeyPairFromMnemonic(mnemonic, path, passphrase);
}
