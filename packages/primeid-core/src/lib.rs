//! PrimeID device-side logic. Wire format matches packages/core-crypto:
//! signature = secp256k1 compact(r||s) over SHA-256(RFC 8785 canonical JSON).

pub use k256;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Credential {
    pub credential_id: String,
    pub issuer_name: String,
    pub issuer: String,
    pub holder: String,
    pub issued_at: u64,
    pub expires: u64,
    pub claims: Vec<String>,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Disclosure {
    pub key: String,
    pub value: String,
    pub salt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuancePackage {
    pub credential: Credential,
    pub disclosures: Vec<Disclosure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub request_id: String,
    pub verifier_name: String,
    #[serde(rename = "verifier_pubKey")]
    pub verifier_pubkey: String,
    pub requested_claim: String,
    pub nonce: String,
    pub expires: u64,
    pub signature: String,
}

/// Stored credential: the issuer-signed part plus the private salts that never leave the device
/// except the one claim the user approves.
pub type StoredCredential = IssuancePackage;

#[derive(Debug, PartialEq)]
pub enum Error {
    Malformed(String),
    IssuerSignature,
    NotBoundToThisDevice,
    Expired,
    DisclosureMismatch(String),
    RequestSignature,
    RequestExpired,
    NoCredentialHasClaim(String),
    UntrustedIssuer,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "Unreadable QR: {m}"),
            Error::IssuerSignature => write!(f, "Issuer signature invalid: forged or tampered credential"),
            Error::NotBoundToThisDevice => write!(f, "Credential is bound to a different device key"),
            Error::Expired => write!(f, "Credential has expired"),
            Error::DisclosureMismatch(k) => write!(f, "Claim '{k}' does not match the issuer-signed hash"),
            Error::RequestSignature => write!(f, "Request signature invalid"),
            Error::RequestExpired => write!(f, "Request has expired"),
            Error::NoCredentialHasClaim(k) => write!(f, "No valid credential contains '{k}' (none stored, or expired or revoked)"),
            Error::UntrustedIssuer => write!(f, "Issuer key is not in your trusted issuers"),
        }
    }
}

/// RFC 8785 canonical JSON for the value shapes PrimeID uses (objects, arrays, strings, integers, bools).
pub fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", Value::String((*k).clone()), canonical(&m[*k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

fn digest(v: &Value) -> [u8; 32] {
    Sha256::digest(canonical(v).as_bytes()).into()
}

pub fn sign(v: &Value, key: &SigningKey) -> String {
    let sig: Signature = key.sign_prehash(&digest(v)).expect("32-byte prehash");
    hex::encode(sig.to_bytes())
}

pub fn verify(v: &Value, sig_hex: &str, pub_hex: &str) -> bool {
    let (Ok(sig), Ok(pk)) = (hex::decode(sig_hex), hex::decode(pub_hex)) else { return false };
    let (Ok(sig), Ok(pk)) = (Signature::from_slice(&sig), VerifyingKey::from_sec1_bytes(&pk)) else {
        return false;
    };
    pk.verify_prehash(&digest(v), &sig).is_ok()
}

/// Holder key derived from the secure element's per-app seed, so a seed restore recovers it.
pub fn holder_key(app_seed: &[u8; 32]) -> SigningKey {
    let mut h = Sha256::new();
    h.update(b"primeid/holder/v1");
    h.update(app_seed);
    SigningKey::from_bytes(&h.finalize()).expect("SHA-256 output is a valid scalar with overwhelming probability")
}

pub fn pubkey_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
}

pub fn claim_hash(d: &Disclosure) -> String {
    hex::encode(Sha256::digest(format!("{}:{}:{}", d.salt, d.key, d.value).as_bytes()))
}

fn credential_body(c: &Credential) -> Value {
    json!({
        "credential_id": c.credential_id, "issuer_name": c.issuer_name, "issuer": c.issuer,
        "holder": c.holder, "issued_at": c.issued_at, "expires": c.expires, "claims": c.claims,
    })
}

fn request_body(r: &Request) -> Value {
    json!({
        "request_id": r.request_id, "verifier_name": r.verifier_name, "verifier_pubKey": r.verifier_pubkey,
        "requested_claim": r.requested_claim, "nonce": r.nonce, "expires": r.expires,
    })
}

/// Receive step: check issuer signature, holder binding, expiry and every salted disclosure.
pub fn import_credential(
    qr: &[u8],
    my_pubkey: &str,
    trusted_issuers: &[&str],
    now: u64,
) -> Result<IssuancePackage, Error> {
    let pkg: IssuancePackage = serde_json::from_slice(qr).map_err(|e| Error::Malformed(e.to_string()))?;
    let c = &pkg.credential;
    if !verify(&credential_body(c), &c.signature, &c.issuer) {
        return Err(Error::IssuerSignature);
    }
    // A valid signature only proves key possession; the issuer must also be one the user trusts.
    if !trusted_issuers.iter().any(|k| k.eq_ignore_ascii_case(&c.issuer)) {
        return Err(Error::UntrustedIssuer);
    }
    if !c.holder.eq_ignore_ascii_case(my_pubkey) {
        return Err(Error::NotBoundToThisDevice);
    }
    if now > c.expires {
        return Err(Error::Expired);
    }
    for d in &pkg.disclosures {
        if !c.claims.contains(&claim_hash(d)) {
            return Err(Error::DisclosureMismatch(d.key.clone()));
        }
    }
    Ok(pkg)
}

/// Answer step, part 1: authenticate the request. Trust (green badge) is decided by the caller
/// against the user's on-device trust list; a valid signature alone only proves key possession.
pub fn parse_request(qr: &[u8], now: u64) -> Result<Request, Error> {
    let r: Request = serde_json::from_slice(qr).map_err(|e| Error::Malformed(e.to_string()))?;
    if !verify(&request_body(&r), &r.signature, &r.verifier_pubkey) {
        return Err(Error::RequestSignature);
    }
    if now > r.expires {
        return Err(Error::RequestExpired);
    }
    Ok(r)
}

/// Issuer-signed list of revoked credential IDs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Revocation {
    pub issuer: String,
    pub revoked: Vec<String>,
    pub published_at: u64,
}

/// Accept a revocation list only if a trusted issuer signed it.
pub fn parse_revocation(qr: &[u8], trusted_issuers: &[&str]) -> Result<Revocation, Error> {
    let v: Value = serde_json::from_slice(qr).map_err(|e| Error::Malformed(e.to_string()))?;
    let body = v.get("primeid_revocation").ok_or_else(|| Error::Malformed("not a revocation list".into()))?;
    let rev: Revocation = serde_json::from_value(body.clone()).map_err(|e| Error::Malformed(e.to_string()))?;
    let sig = v["signature"].as_str().unwrap_or_default();
    if !verify(body, sig, &rev.issuer) {
        return Err(Error::IssuerSignature);
    }
    if !trusted_issuers.iter().any(|k| k.eq_ignore_ascii_case(&rev.issuer)) {
        return Err(Error::UntrustedIssuer);
    }
    Ok(rev)
}

pub fn is_revoked(c: &Credential, lists: &[Revocation]) -> bool {
    lists.iter().any(|l| l.issuer.eq_ignore_ascii_case(&c.issuer) && l.revoked.contains(&c.credential_id))
}

/// Newest unexpired, unrevoked credential that holds the requested claim.
pub fn find_claim<'a>(
    store: &'a [StoredCredential],
    revocations: &[Revocation],
    claim: &str,
    now: u64,
) -> Result<(&'a StoredCredential, &'a Disclosure), Error> {
    store
        .iter()
        .rev()
        .filter(|s| now <= s.credential.expires && !is_revoked(&s.credential, revocations))
        .find_map(|s| s.disclosures.iter().find(|d| d.key == claim).map(|d| (s, d)))
        .ok_or_else(|| Error::NoCredentialHasClaim(claim.to_string()))
}

/// Answer step, part 2 (only after on-device approval): reveal one claim, bind to the nonce, sign.
pub fn build_answer(cred: &Credential, d: &Disclosure, req: &Request, key: &SigningKey) -> String {
    let body = json!({
        "credential": cred,
        "disclosed_claim": d,
        "request_context": { "nonce": req.nonce, "verifier_pubKey": req.verifier_pubkey, "expires": req.expires },
    });
    let mut answer = body.clone();
    answer["holder_signature"] = Value::String(sign(&body, key));
    answer.to_string()
}

#[cfg(test)]
mod tests;
