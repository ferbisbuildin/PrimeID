//! secp256k1 ECDSA over SHA-256 of canonical JSON, plus key derivation from the KeyOS app seed.
//!
//! Signatures are 64-byte compact `r || s` (hex), low-S, RFC 6979 deterministic: the same
//! encoding `@noble/curves` produces with `sign(...).toCompactHex()` and accepts in `verify`.

use hmac::{Hmac, Mac};
use k256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{canonical::canonicalize, Error};

type HmacSha256 = Hmac<Sha256>;

pub fn sha256(data: &[u8]) -> [u8; 32] { Sha256::digest(data).into() }

pub fn sha256_hex(data: &[u8]) -> String { hex::encode(sha256(data)) }

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Parses a 33-byte compressed SEC1 public key in lowercase hex.
pub fn parse_public_key(hex_str: &str) -> Result<VerifyingKey, Error> {
    if hex_str.len() != 66 || !is_lower_hex(hex_str) {
        return Err(Error::Malformed("public key must be 33-byte compressed lowercase hex"));
    }
    let bytes = hex::decode(hex_str).map_err(|_| Error::Malformed("public key hex"))?;
    if bytes[0] != 0x02 && bytes[0] != 0x03 {
        return Err(Error::Malformed("public key must be compressed"));
    }
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| Error::Malformed("public key is not on secp256k1"))
}

pub fn public_key_hex(key: &VerifyingKey) -> String { hex::encode(key.to_encoded_point(true).as_bytes()) }

/// Short, human-checkable key fingerprint: first 8 bytes of SHA-256 of the compressed key.
pub fn fingerprint(pub_hex: &str) -> String {
    let bytes = hex::decode(pub_hex).unwrap_or_default();
    let digest = sha256(&bytes);
    let h = hex::encode(&digest[..8]).to_uppercase();
    format!("{} {} {} {}", &h[0..4], &h[4..8], &h[8..12], &h[12..16])
}

/// Digest that gets signed: SHA-256 over the canonical JSON of `payload`.
pub fn payload_digest(payload: &Value) -> Result<[u8; 32], Error> {
    Ok(sha256(canonicalize(payload)?.as_bytes()))
}

pub fn sign_payload(key: &SigningKey, payload: &Value) -> Result<String, Error> {
    let digest = payload_digest(payload)?;
    let sig: Signature = key.sign_prehash(&digest).map_err(|_| Error::Crypto("signing failed"))?;
    // k256 already emits low-S; normalizing again is a no-op that keeps the guarantee explicit.
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(hex::encode(sig.to_bytes()))
}

pub fn verify_payload(pub_hex: &str, payload: &Value, sig_hex: &str) -> Result<(), Error> {
    let key = parse_public_key(pub_hex)?;
    if sig_hex.len() != 128 || !is_lower_hex(sig_hex) {
        return Err(Error::BadSignature);
    }
    let bytes = hex::decode(sig_hex).map_err(|_| Error::BadSignature)?;
    let sig = Signature::from_slice(&bytes).map_err(|_| Error::BadSignature)?;
    if sig.normalize_s().is_some() {
        // High-S would be a second valid encoding of the same signature; noble rejects it too.
        return Err(Error::BadSignature);
    }
    let digest = payload_digest(payload)?;
    key.verify_prehash(&digest, &sig).map_err(|_| Error::BadSignature)
}

/// The holder key PrimeID binds credentials to, derived from the 32-byte KeyOS app seed.
///
/// The app seed is `GetAppSeed` output (per-app, derived by the secure element from the master
/// seed), so restoring the seed restores this key and every credential bound to it.
pub struct HolderKey {
    signing: SigningKey,
}

const HOLDER_KEY_DOMAIN: &[u8] = b"primeid/holder-key/v1";
const VAULT_KEY_DOMAIN: &[u8] = b"primeid/vault-key/v1";

impl HolderKey {
    pub fn from_app_seed(app_seed: &[u8; 32]) -> Self {
        // Rejection-sample the vanishingly rare out-of-range HMAC output instead of reducing it.
        for counter in 0u32.. {
            let mut msg = HOLDER_KEY_DOMAIN.to_vec();
            msg.extend_from_slice(&counter.to_be_bytes());
            let candidate = Zeroizing::new(hmac_sha256(app_seed, &msg));
            if let Ok(signing) = SigningKey::from_slice(candidate.as_slice()) {
                return Self { signing };
            }
        }
        unreachable!("HMAC output never stays outside the scalar range")
    }

    pub fn public_hex(&self) -> String { public_key_hex(self.signing.verifying_key()) }

    pub fn sign(&self, payload: &Value) -> Result<String, Error> { sign_payload(&self.signing, payload) }
}

/// 32-byte AES-256-GCM key for the on-device credential vault, derived from the app seed.
pub fn vault_key_from_app_seed(app_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hmac_sha256(app_seed, VAULT_KEY_DOMAIN))
}

pub(crate) fn is_lower_hex(s: &str) -> bool { s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
