import { generateRandomKeyPair, getPublicKeyFromPrivate, KeyPair } from "@core-crypto/secp256k1";

// shortcut: demo issuer/verifier keys live in this browser's localStorage so trust granted on Prime
// survives a reload; a real issuer keeps its key in an HSM or server-side KMS.
export function loadOrCreateKey(slot: string): KeyPair {
  try {
    const priv = localStorage.getItem(slot);
    if (priv && /^[0-9a-f]{64}$/.test(priv)) {
      return { privateKeyHex: priv, publicKeyHex: getPublicKeyFromPrivate(priv) };
    }
  } catch {
    // storage blocked: fall through to an ephemeral key
  }
  const kp = generateRandomKeyPair();
  try {
    localStorage.setItem(slot, kp.privateKeyHex);
  } catch {
    // ephemeral key only
  }
  return kp;
}

export function saveKey(slot: string, kp: KeyPair): KeyPair {
  try {
    localStorage.setItem(slot, kp.privateKeyHex);
  } catch {
    // ephemeral key only
  }
  return kp;
}

export const trustCard = (name: string, pubkey: string, role: "issuer" | "verifier") => ({
  primeid_trust: { name, pubkey, role },
});
