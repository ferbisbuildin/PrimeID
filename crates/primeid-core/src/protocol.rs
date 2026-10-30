//! PrimeID wire formats (protocol v1) and the checks each party runs.
//!
//! Four QR payloads cross the air gap, each tagged by `typ`:
//! 1. `primeid/holder/v1`      Prime -> issuer:   the holder public key to bind credentials to.
//! 2. `primeid/offer/v1`       issuer -> Prime:   a signed credential plus its claim disclosures.
//! 3. `primeid/request/v1`     verifier -> Prime: a signed request for one claim, nonce, expiry.
//! 4. `primeid/answer/v1`      Prime -> verifier: one disclosure, signed by the holder key over
//!                             the credential, the nonce, the verifier key and the request hash.
//!
//! The issuer signs a set of salted claim hashes `sha256(salt ":" key ":" value)`, so Prime can
//! reveal one claim (with its salt) and keep the others on the device.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canonical::canonicalize,
    crypto::{is_lower_hex, parse_public_key, sha256_hex, verify_payload, HolderKey},
    Error,
};

pub const TYP_HOLDER: &str = "primeid/holder/v1";
pub const TYP_OFFER: &str = "primeid/offer/v1";
pub const TYP_CREDENTIAL: &str = "primeid/credential/v1";
pub const TYP_VERIFIER_CERT: &str = "primeid/verifier-cert/v1";
pub const TYP_REQUEST: &str = "primeid/request/v1";
pub const TYP_ANSWER: &str = "primeid/answer/v1";

/// Tolerated clock difference between Prime and a verifier, in seconds.
pub const CLOCK_SKEW_SECS: u64 = 300;
/// A request may not ask Prime to keep it valid for longer than this.
pub const MAX_REQUEST_LIFETIME_SECS: u64 = 15 * 60;

const MAX_CLAIMS: usize = 32;
const MAX_NAME_LEN: usize = 64;
const MAX_VALUE_LEN: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderKeyQr {
    pub typ: String,
    #[serde(rename = "pub")]
    pub pub_key: String,
}

impl HolderKeyQr {
    pub fn new(holder: &HolderKey) -> Self { Self { typ: TYP_HOLDER.into(), pub_key: holder.public_hex() } }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub typ: String,
    pub id: String,
    /// Issuer public key.
    pub iss: String,
    pub iss_name: String,
    /// Holder public key the credential is bound to.
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    /// Salted claim hashes, sorted so their order reveals nothing.
    pub claims: Vec<String>,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosure {
    pub k: String,
    pub v: String,
    /// 16-byte salt, lowercase hex.
    pub s: String,
}

impl Disclosure {
    pub fn hash(&self) -> String { claim_hash(&self.s, &self.k, &self.v) }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialOffer {
    pub typ: String,
    pub cred: Credential,
    pub disc: Vec<Disclosure>,
}

/// An issuer's statement that a verifier key belongs to a named organisation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierCert {
    pub typ: String,
    pub name: String,
    #[serde(rename = "pub")]
    pub pub_key: String,
    pub iss: String,
    pub iss_name: String,
    pub exp: u64,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub typ: String,
    pub id: String,
    /// Verifier public key; the answer is bound to it.
    pub aud: String,
    pub aud_name: String,
    pub claim: String,
    pub nonce: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<VerifierCert>,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub typ: String,
    pub cred: Credential,
    pub disc: Disclosure,
    /// SHA-256 (hex) of the canonical JSON of the full signed request.
    pub req: String,
    pub nonce: String,
    pub aud: String,
    pub sig: String,
}

/// Anything Prime can scan.
#[derive(Clone, Debug)]
pub enum Scanned {
    Offer(CredentialOffer),
    Request(Request),
}

pub fn claim_hash(salt: &str, key: &str, value: &str) -> String {
    sha256_hex(format!("{salt}:{key}:{value}").as_bytes())
}

/// The value with `sig` removed: what the signer signed.
fn unsigned_payload<T: Serialize>(item: &T) -> Result<Value, Error> {
    let mut value = serde_json::to_value(item).map_err(|_| Error::Malformed("serialize"))?;
    value.as_object_mut().ok_or(Error::Malformed("payload must be an object"))?.remove("sig");
    Ok(value)
}

pub fn to_canonical_json<T: Serialize>(item: &T) -> Result<String, Error> {
    canonicalize(&serde_json::to_value(item).map_err(|_| Error::Malformed("serialize"))?)
}

pub fn parse_scanned(data: &[u8]) -> Result<Scanned, Error> {
    let value: Value = serde_json::from_slice(data).map_err(|_| Error::Malformed("not PrimeID JSON"))?;
    match value.get("typ").and_then(Value::as_str) {
        Some(TYP_OFFER) => Ok(Scanned::Offer(
            serde_json::from_value(value).map_err(|_| Error::Malformed("credential offer fields"))?,
        )),
        Some(TYP_REQUEST) => {
            Ok(Scanned::Request(serde_json::from_value(value).map_err(|_| Error::Malformed("request fields"))?))
        }
        _ => Err(Error::Malformed("not a PrimeID credential or request")),
    }
}

fn check_hex(s: &str, bytes: usize, what: &'static str) -> Result<(), Error> {
    if s.len() == bytes * 2 && is_lower_hex(s) {
        Ok(())
    } else {
        Err(Error::Malformed(what))
    }
}

pub fn check_claim_key(k: &str) -> Result<(), Error> {
    let mut chars = k.chars();
    let ok = k.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(Error::Malformed("claim key must match ^[a-z][a-z0-9_]{0,31}$"))
    }
}

fn check_name(s: &str) -> Result<(), Error> {
    if s.trim().is_empty() || s.chars().count() > MAX_NAME_LEN || s.chars().any(char::is_control) {
        Err(Error::Malformed("name must be 1-64 printable characters"))
    } else {
        Ok(())
    }
}

impl Credential {
    /// Shape, issuer signature and validity window. Does not decide whether the issuer is trusted.
    pub fn verify_signature_and_time(&self, now: u64) -> Result<(), Error> {
        if self.typ != TYP_CREDENTIAL {
            return Err(Error::Malformed("credential typ"));
        }
        check_hex(&self.id, 16, "credential id must be 16-byte hex")?;
        check_name(&self.iss_name)?;
        parse_public_key(&self.sub)?;
        if self.claims.is_empty() || self.claims.len() > MAX_CLAIMS {
            return Err(Error::Malformed("credential must carry 1-32 claims"));
        }
        for h in &self.claims {
            check_hex(h, 32, "claim hash must be 32-byte hex")?;
        }
        if self.claims.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::Malformed("claim hashes must be sorted and unique"));
        }
        verify_payload(&self.iss, &unsigned_payload(self)?, &self.sig).map_err(|_| Error::IssuerSignature)?;
        if self.iat > now + CLOCK_SKEW_SECS || self.exp <= self.iat {
            return Err(Error::Malformed("credential validity window"));
        }
        if now >= self.exp {
            return Err(Error::Expired("credential"));
        }
        Ok(())
    }
}

impl CredentialOffer {
    /// Everything Prime checks before storing a credential: issuer signature, holder binding to
    /// this Prime's key, expiry, and that every disclosure matches a signed hash (and vice versa).
    pub fn verify_for_holder(&self, holder_pub: &str, now: u64) -> Result<(), Error> {
        if self.typ != TYP_OFFER {
            return Err(Error::Malformed("offer typ"));
        }
        self.cred.verify_signature_and_time(now)?;
        if self.cred.sub != holder_pub {
            return Err(Error::NotBoundToThisDevice);
        }
        if self.disc.len() != self.cred.claims.len() {
            return Err(Error::Malformed("one disclosure per signed claim"));
        }
        let mut seen_keys = Vec::new();
        for d in &self.disc {
            check_claim_key(&d.k)?;
            check_hex(&d.s, 16, "salt must be 16-byte hex")?;
            if d.v.chars().count() > MAX_VALUE_LEN {
                return Err(Error::Malformed("claim value too long"));
            }
            if seen_keys.contains(&d.k) {
                return Err(Error::Malformed("duplicate claim key"));
            }
            seen_keys.push(d.k.clone());
            if self.cred.claims.binary_search(&d.hash()).is_err() {
                return Err(Error::DisclosureMismatch);
            }
        }
        Ok(())
    }
}

impl VerifierCert {
    pub fn verify(&self, now: u64) -> Result<(), Error> {
        if self.typ != TYP_VERIFIER_CERT {
            return Err(Error::Malformed("verifier cert typ"));
        }
        check_name(&self.name)?;
        check_name(&self.iss_name)?;
        parse_public_key(&self.pub_key)?;
        verify_payload(&self.iss, &unsigned_payload(self)?, &self.sig).map_err(|_| Error::BadSignature)?;
        if now >= self.exp {
            return Err(Error::Expired("verifier certificate"));
        }
        Ok(())
    }
}

/// How Prime labels who is asking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requester {
    /// The request key is certified by an issuer this Prime trusts.
    Verified { name: String, certified_by: String },
    /// Validly signed, but nobody this Prime trusts vouches for the key or the name.
    Unknown { claimed_name: String, reason: &'static str },
}

impl Request {
    /// Hard checks: a request failing these is refused outright, before the user is asked.
    pub fn verify_signature_and_time(&self, now: u64) -> Result<(), Error> {
        if self.typ != TYP_REQUEST {
            return Err(Error::Malformed("request typ"));
        }
        check_hex(&self.id, 16, "request id must be 16-byte hex")?;
        check_hex(&self.nonce, 16, "nonce must be 16-byte hex")?;
        check_claim_key(&self.claim)?;
        check_name(&self.aud_name)?;
        verify_payload(&self.aud, &unsigned_payload(self)?, &self.sig).map_err(|_| Error::RequestSignature)?;
        if self.iat > now + CLOCK_SKEW_SECS || self.exp <= self.iat || self.exp - self.iat > MAX_REQUEST_LIFETIME_SECS
        {
            return Err(Error::Malformed("request validity window"));
        }
        if now >= self.exp {
            return Err(Error::Expired("request"));
        }
        Ok(())
    }

    /// Who is asking, judged against the issuers the user has chosen to trust on this Prime.
    pub fn requester(&self, trusted_issuers: &[String], now: u64) -> Requester {
        let unknown = |reason| Requester::Unknown { claimed_name: self.aud_name.clone(), reason };
        let Some(cert) = &self.cert else {
            return unknown("No certificate from an issuer you trust");
        };
        if cert.verify(now).is_err() {
            return unknown("Certificate is invalid or expired");
        }
        if !trusted_issuers.iter().any(|t| *t == cert.iss) {
            return unknown("Certificate is from an issuer you have not trusted");
        }
        if cert.pub_key != self.aud {
            return unknown("Certificate is for a different key");
        }
        if cert.name != self.aud_name {
            return unknown("Name does not match the certificate");
        }
        Requester::Verified { name: cert.name.clone(), certified_by: cert.iss_name.clone() }
    }

    pub fn digest_hex(&self) -> Result<String, Error> { Ok(sha256_hex(to_canonical_json(self)?.as_bytes())) }
}

/// Builds the answer Prime shows as a QR after the user approves. Only `disclosure` leaves the device.
pub fn build_answer(
    holder: &HolderKey,
    cred: &Credential,
    disclosure: &Disclosure,
    req: &Request,
) -> Result<Answer, Error> {
    if cred.sub != holder.public_hex() {
        return Err(Error::NotBoundToThisDevice);
    }
    if disclosure.k != req.claim || cred.claims.binary_search(&disclosure.hash()).is_err() {
        return Err(Error::DisclosureMismatch);
    }
    let mut answer = Answer {
        typ: TYP_ANSWER.into(),
        cred: cred.clone(),
        disc: disclosure.clone(),
        req: req.digest_hex()?,
        nonce: req.nonce.clone(),
        aud: req.aud.clone(),
        sig: String::new(),
    };
    answer.sig = holder.sign(&unsigned_payload(&answer)?)?;
    Ok(answer)
}

/// Verifier-side checks, mirrored from `packages/core-crypto/pipeline.ts` (used by tests).
/// `outstanding` is the request this verifier issued and has not yet seen answered.
pub fn verify_answer(
    answer: &Answer,
    outstanding: &Request,
    trusted_issuers: &[String],
    now: u64,
) -> Result<(String, String), Error> {
    if answer.typ != TYP_ANSWER {
        return Err(Error::Malformed("answer typ"));
    }
    answer.cred.verify_signature_and_time(now)?;
    if !trusted_issuers.contains(&answer.cred.iss) {
        return Err(Error::UntrustedIssuer);
    }
    verify_payload(&answer.cred.sub, &unsigned_payload(answer)?, &answer.sig).map_err(|_| Error::HolderSignature)?;
    if answer.cred.claims.binary_search(&answer.disc.hash()).is_err() {
        return Err(Error::DisclosureMismatch);
    }
    if answer.nonce != outstanding.nonce || answer.req != outstanding.digest_hex()? {
        return Err(Error::NonceMismatch);
    }
    if answer.aud != outstanding.aud || answer.disc.k != outstanding.claim {
        return Err(Error::NonceMismatch);
    }
    if now >= outstanding.exp {
        return Err(Error::Expired("request"));
    }
    Ok((answer.disc.k.clone(), answer.disc.v.clone()))
}
