/**
 * On-Device Verifier & Issuer Registry (KeyOS Trust Store)
 * Manages trusted cryptographic authorities pre-loaded or user-approved on Passport Prime.
 * Drives the on-screen "Verified Requester" green badge vs "Unknown Requester" red alert.
 */

export interface RegisteredParty {
  id: string;
  name: string;
  category: "GOVERNMENT" | "FINANCIAL" | "ACADEMIC" | "EXCHANGE" | "AI_AGENT";
  publicKeyHex: string;
  reputation: "VERIFIED" | "SUSPICIOUS" | "CUSTOM";
  iconName: string;
  description: string;
}

export const KNOWN_TRUSTED_ISSUERS: RegisteredParty[] = [
  {
    id: "gov_identity_authority",
    name: "Global Identity Authority (G7 DPA Pilot)",
    category: "GOVERNMENT",
    publicKeyHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", // Deterministic demo authority
    reputation: "VERIFIED",
    iconName: "ShieldCheck",
    description: "Official G7 compliant privacy-preserving digital identity issuer.",
  },
  {
    id: "stanford_university",
    name: "Stanford University Registrar",
    category: "ACADEMIC",
    publicKeyHex: "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    reputation: "VERIFIED",
    iconName: "GraduationCap",
    description: "Academic enrollment and degree credentials issuer.",
  },
  {
    id: "apex_exchange",
    name: "Apex Exchange Compliance",
    category: "EXCHANGE",
    publicKeyHex: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    reputation: "VERIFIED",
    iconName: "Coins",
    description: "Regulated digital asset trading & KYC compliance provider.",
  },
];

export const KNOWN_TRUSTED_VERIFIERS: RegisteredParty[] = [
  {
    id: "apex_compliance_verifier",
    name: "Apex Exchange Compliance Terminal",
    category: "EXCHANGE",
    publicKeyHex: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    reputation: "VERIFIED",
    iconName: "Coins",
    description: "Verified institutional KYC verifier.",
  },
  {
    id: "club_entrance_verifier",
    name: "Metropolis Arena Age Verifier",
    category: "FINANCIAL",
    publicKeyHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    reputation: "VERIFIED",
    iconName: "ShieldCheck",
    description: "Zero-knowledge offline venue age-gate gateway.",
  },
  {
    id: "x401_agent_verifier",
    name: "Foundation x401 AI Agent Gateway",
    category: "AI_AGENT",
    publicKeyHex: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    reputation: "VERIFIED",
    iconName: "Cpu",
    description: "Foundation x401 hardware authority verification for autonomous agents.",
  },
];

/**
 * Checks if a verifier's public key is known in the device registry.
 */
export function lookupVerifier(
  publicKeyHex: string,
  customRegistry: RegisteredParty[] = []
): { isVerified: boolean; party?: RegisteredParty } {
  const combined = [...KNOWN_TRUSTED_VERIFIERS, ...customRegistry];
  const found = combined.find((p) => p.publicKeyHex.toLowerCase() === publicKeyHex.toLowerCase());

  if (found) {
    return { isVerified: true, party: found };
  }

  return { isVerified: false };
}
