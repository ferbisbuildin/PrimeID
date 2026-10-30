//! PrimeID core: the protocol and cryptography behind "prove the fact, keep the document".
//!
//! No KeyOS dependencies, so it is unit-tested on the host and cross-checked against the
//! TypeScript issuer/verifier (`tests/vectors.rs`, `packages/core-crypto`).

pub mod canonical;
pub mod crypto;
pub mod protocol;
pub mod vault;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Malformed(&'static str),
    Crypto(&'static str),
    BadSignature,
    IssuerSignature,
    RequestSignature,
    HolderSignature,
    NotBoundToThisDevice,
    DisclosureMismatch,
    UntrustedIssuer,
    NonceMismatch,
    Expired(&'static str),
    VaultCorrupt,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "Malformed data: {what}"),
            Error::Crypto(what) => write!(f, "Cryptography error: {what}"),
            Error::BadSignature => write!(f, "Signature is invalid"),
            Error::IssuerSignature => write!(f, "Issuer signature is invalid. This credential was not made with the issuer's key."),
            Error::RequestSignature => write!(f, "Request signature is invalid"),
            Error::HolderSignature => write!(f, "Holder signature is invalid"),
            Error::NotBoundToThisDevice => write!(f, "Credential is bound to a different key, not this Passport"),
            Error::DisclosureMismatch => write!(f, "Disclosed claim does not match the signed claim hashes"),
            Error::UntrustedIssuer => write!(f, "Issuer is not trusted"),
            Error::NonceMismatch => write!(f, "Answer is not for the outstanding request (nonce, verifier or claim mismatch)"),
            Error::Expired(what) => write!(f, "The {what} has expired"),
            Error::VaultCorrupt => write!(f, "Vault could not be decrypted"),
        }
    }
}

impl std::error::Error for Error {}
