//! On-device state: stored credentials, trusted issuers and privacy receipts.
//!
//! The whole vault is sealed with AES-256-GCM under a key derived from the KeyOS app seed before
//! it is written to the app's private `AppData` storage, so claim values and salts are never on
//! flash in plaintext, even beneath KeyOS's own disk encryption.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};

use crate::{
    protocol::{Credential, Disclosure},
    Error,
};

const MAGIC: &[u8; 6] = b"PIDV1\0";
const AAD: &[u8] = b"primeid/vault/v1";
const MAX_RECEIPTS: usize = 200;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultData {
    pub credentials: Vec<StoredCredential>,
    pub trusted_issuers: Vec<TrustedIssuer>,
    pub receipts: Vec<Receipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCredential {
    pub cred: Credential,
    pub disc: Vec<Disclosure>,
    pub stored_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedIssuer {
    #[serde(rename = "pub")]
    pub pub_key: String,
    pub name: String,
    pub trusted_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Approved,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub at: u64,
    pub requester: String,
    pub requester_key: String,
    pub verified: bool,
    pub claim: String,
    pub decision: Decision,
    /// Value that left the device, if approved.
    pub shared: Option<String>,
    /// Claim keys of the same credential that stayed on the device.
    pub withheld: Vec<String>,
    pub nonce: String,
}

impl VaultData {
    pub fn is_trusted(&self, issuer_pub: &str) -> bool { self.trusted_issuers.iter().any(|t| t.pub_key == issuer_pub) }

    pub fn trusted_issuer_keys(&self) -> Vec<String> {
        self.trusted_issuers.iter().map(|t| t.pub_key.clone()).collect()
    }

    pub fn trust_issuer(&mut self, pub_key: &str, name: &str, now: u64) {
        if !self.is_trusted(pub_key) {
            self.trusted_issuers.push(TrustedIssuer { pub_key: pub_key.into(), name: name.into(), trusted_at: now });
        }
    }

    /// Stores a verified credential, replacing an older copy with the same id.
    pub fn store(&mut self, cred: Credential, disc: Vec<Disclosure>, now: u64) {
        self.credentials.retain(|c| c.cred.id != cred.id);
        self.credentials.push(StoredCredential { cred, disc, stored_at: now });
    }

    /// The unexpired credential from a trusted issuer that can answer `claim`, newest first.
    pub fn find_for_claim(&self, claim: &str, now: u64) -> Option<(&StoredCredential, &Disclosure)> {
        self.credentials
            .iter()
            .rev()
            .filter(|c| now < c.cred.exp && self.is_trusted(&c.cred.iss))
            .find_map(|c| c.disc.iter().find(|d| d.k == claim).map(|d| (c, d)))
    }

    /// Whether this nonce was already answered: Prime never signs the same request twice.
    pub fn answered_nonce(&self, nonce: &str) -> bool {
        self.receipts.iter().any(|r| r.nonce == nonce && r.decision == Decision::Approved)
    }

    pub fn add_receipt(&mut self, receipt: Receipt) {
        self.receipts.push(receipt);
        if self.receipts.len() > MAX_RECEIPTS {
            let excess = self.receipts.len() - MAX_RECEIPTS;
            self.receipts.drain(..excess);
        }
    }

    pub fn seal(&self, key: &[u8; 32], nonce: [u8; 12]) -> Result<Vec<u8>, Error> {
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(self).map_err(|_| Error::Malformed("vault"))?);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("vault key"))?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: AAD })
            .map_err(|_| Error::Crypto("vault encrypt"))?;
        let mut out = Vec::with_capacity(MAGIC.len() + 12 + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// An empty blob is a fresh vault; anything else must decrypt and authenticate.
    pub fn open(key: &[u8; 32], blob: &[u8]) -> Result<Self, Error> {
        if blob.is_empty() {
            return Ok(Self::default());
        }
        if blob.len() < MAGIC.len() + 12 + 16 || &blob[..MAGIC.len()] != MAGIC {
            return Err(Error::VaultCorrupt);
        }
        let (nonce, ct) = blob[MAGIC.len()..].split_at(12);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("vault key"))?;
        let plaintext = zeroize::Zeroizing::new(
            cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: AAD }).map_err(|_| Error::VaultCorrupt)?,
        );
        serde_json::from_slice(&plaintext).map_err(|_| Error::VaultCorrupt)
    }
}
