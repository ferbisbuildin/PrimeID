//! The demo script from the idea document, end to end: one honest flow, four attacks that fail.

use k256::ecdsa::SigningKey;
use primeid_core::{
    crypto::{public_key_hex, sign_payload, HolderKey},
    protocol::*,
    vault::VaultData,
    Error,
};
use serde_json::Value;

const NOW: u64 = 1_793_000_000;

fn key(byte: u8) -> SigningKey { SigningKey::from_slice(&[byte; 32]).unwrap() }

fn pub_hex(k: &SigningKey) -> String { public_key_hex(k.verifying_key()) }

fn signed<T: serde::Serialize + serde::de::DeserializeOwned>(item: &T, k: &SigningKey) -> T {
    let mut v = serde_json::to_value(item).unwrap();
    v.as_object_mut().unwrap().remove("sig");
    let sig = sign_payload(k, &v).unwrap();
    v.as_object_mut().unwrap().insert("sig".into(), Value::String(sig));
    serde_json::from_value(v).unwrap()
}

fn issue(issuer: &SigningKey, holder_pub: &str, claims: &[(&str, &str)]) -> CredentialOffer {
    let disc: Vec<Disclosure> = claims
        .iter()
        .enumerate()
        .map(|(i, (k, v))| Disclosure { k: k.to_string(), v: v.to_string(), s: format!("{:032x}", i + 1) })
        .collect();
    let mut hashes: Vec<String> = disc.iter().map(Disclosure::hash).collect();
    hashes.sort();
    let cred = Credential {
        typ: TYP_CREDENTIAL.into(),
        id: "00112233445566778899aabbccddeeff".into(),
        iss: pub_hex(issuer),
        iss_name: "Demo Issuer".into(),
        sub: holder_pub.into(),
        iat: NOW - 60,
        exp: NOW + 86_400,
        claims: hashes,
        sig: String::new(),
    };
    CredentialOffer { typ: TYP_OFFER.into(), cred: signed(&cred, issuer), disc }
}

fn request(verifier: &SigningKey, name: &str, cert: Option<VerifierCert>, nonce: &str) -> Request {
    let req = Request {
        typ: TYP_REQUEST.into(),
        id: "ffeeddccbbaa99887766554433221100".into(),
        aud: pub_hex(verifier),
        aud_name: name.into(),
        claim: "over_18".into(),
        nonce: nonce.into(),
        iat: NOW - 5,
        exp: NOW + 300,
        cert,
        sig: String::new(),
    };
    signed(&req, verifier)
}

fn cert_for(issuer: &SigningKey, verifier: &SigningKey, name: &str) -> VerifierCert {
    let cert = VerifierCert {
        typ: TYP_VERIFIER_CERT.into(),
        name: name.into(),
        pub_key: pub_hex(verifier),
        iss: pub_hex(issuer),
        iss_name: "Demo Issuer".into(),
        exp: NOW + 86_400,
        sig: String::new(),
    };
    signed(&cert, issuer)
}

#[test]
fn honest_flow_and_four_attacks() {
    let issuer = key(1);
    let verifier = key(2);
    let holder = HolderKey::from_app_seed(&[7u8; 32]);
    let trusted = vec![pub_hex(&issuer)];

    // Steps 1-3: Prime shows its key, the issuer binds a credential to it, Prime verifies and stores it.
    let offer = issue(&issuer, &holder.public_hex(), &[("over_18", "true"), ("country", "IN"), ("name", "A. Person")]);
    offer.verify_for_holder(&holder.public_hex(), NOW).unwrap();
    let mut vault = VaultData::default();
    vault.trust_issuer(&offer.cred.iss, &offer.cred.iss_name, NOW);
    vault.store(offer.cred.clone(), offer.disc.clone(), NOW);

    // Steps 4-5: a certified verifier asks; Prime shows a verified badge.
    let req = request(&verifier, "Club Entry", Some(cert_for(&issuer, &verifier, "Club Entry")), "0123456789abcdef0123456789abcdef");
    req.verify_signature_and_time(NOW).unwrap();
    assert_eq!(
        req.requester(&vault.trusted_issuer_keys(), NOW),
        Requester::Verified { name: "Club Entry".into(), certified_by: "Demo Issuer".into() }
    );

    // Steps 6-7: only over_18 leaves the device; the verifier accepts the answer.
    let (stored, disc) = vault.find_for_claim(&req.claim, NOW).unwrap();
    let answer = build_answer(&holder, &stored.cred, disc, &req).unwrap();
    let json = to_canonical_json(&answer).unwrap();
    assert!(json.contains("\"over_18\"") && !json.contains("A. Person") && !json.contains("\"IN\""));
    assert_eq!(verify_answer(&answer, &req, &trusted, NOW).unwrap(), ("over_18".into(), "true".into()));

    // Attack 1, the AI fake ID: same claims, signed by a key that is not the issuer's.
    let mut forged = issue(&key(9), &holder.public_hex(), &[("over_18", "true")]);
    forged.cred.iss = pub_hex(&issuer);
    assert_eq!(forged.verify_for_holder(&holder.public_hex(), NOW), Err(Error::IssuerSignature));

    // Attack 2, a copied credential loaded into another wallet: the copier cannot sign as the holder.
    let thief = HolderKey::from_app_seed(&[8u8; 32]);
    assert_eq!(offer.verify_for_holder(&thief.public_hex(), NOW), Err(Error::NotBoundToThisDevice));
    assert_eq!(build_answer(&thief, &stored.cred, disc, &req).unwrap_err(), Error::NotBoundToThisDevice);
    let mut stolen = answer.clone();
    stolen.sig = thief.sign(&serde_json::to_value(&answer).unwrap()).unwrap();
    assert_eq!(verify_answer(&stolen, &req, &trusted, NOW), Err(Error::HolderSignature));

    // Attack 3, a replayed answer: yesterday's answer does not match today's nonce.
    let today = request(&verifier, "Club Entry", None, "fedcba9876543210fedcba9876543210");
    assert_eq!(verify_answer(&answer, &today, &trusted, NOW), Err(Error::NonceMismatch));

    // Attack 4, a fake bank: a validly signed request with no certificate from a trusted issuer.
    let phish = request(&key(5), "Global Bank", None, "00000000000000000000000000000001");
    phish.verify_signature_and_time(NOW).unwrap();
    assert!(matches!(phish.requester(&vault.trusted_issuer_keys(), NOW), Requester::Unknown { .. }));
    // ...or one that borrows a real certificate for another key.
    let borrowed = request(&key(5), "Club Entry", Some(cert_for(&issuer, &verifier, "Club Entry")), "00000000000000000000000000000002");
    assert!(matches!(borrowed.requester(&vault.trusted_issuer_keys(), NOW), Requester::Unknown { .. }));

    // Tampering with a disclosed value breaks the hash commitment.
    let mut lied = answer.clone();
    lied.disc.v = "false".into();
    assert!(verify_answer(&lied, &req, &trusted, NOW).is_err());
}

#[test]
fn request_edits_break_its_signature() {
    let mut req = request(&key(2), "Club Entry", None, "0123456789abcdef0123456789abcdef");
    req.claim = "name".into();
    assert_eq!(req.verify_signature_and_time(NOW), Err(Error::RequestSignature));
}

#[test]
fn expired_inputs_are_refused() {
    let issuer = key(1);
    let holder = HolderKey::from_app_seed(&[7u8; 32]);
    let offer = issue(&issuer, &holder.public_hex(), &[("over_18", "true")]);
    assert_eq!(offer.verify_for_holder(&holder.public_hex(), NOW + 86_400), Err(Error::Expired("credential")));
    let req = request(&key(2), "Club Entry", None, "0123456789abcdef0123456789abcdef");
    assert_eq!(req.verify_signature_and_time(NOW + 301), Err(Error::Expired("request")));
}

#[test]
fn vault_round_trips_and_detects_tampering() {
    let seed = [3u8; 32];
    let key = primeid_core::crypto::vault_key_from_app_seed(&seed);
    let mut vault = VaultData::default();
    vault.trust_issuer(&pub_hex(&self::key(1)), "Demo Issuer", NOW);
    let blob = vault.seal(&key, [9u8; 12]).unwrap();
    assert!(!blob.windows(11).any(|w| w == b"Demo Issuer"));
    assert_eq!(VaultData::open(&key, &blob).unwrap(), vault);

    let mut tampered = blob.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(VaultData::open(&key, &tampered), Err(Error::VaultCorrupt));
    let other = primeid_core::crypto::vault_key_from_app_seed(&[4u8; 32]);
    assert_eq!(VaultData::open(&other, &blob), Err(Error::VaultCorrupt));
    assert_eq!(VaultData::open(&key, &[]).unwrap(), VaultData::default());
}

#[test]
fn holder_key_is_deterministic_per_seed() {
    let a = HolderKey::from_app_seed(&[7u8; 32]).public_hex();
    assert_eq!(a, HolderKey::from_app_seed(&[7u8; 32]).public_hex());
    assert_ne!(a, HolderKey::from_app_seed(&[6u8; 32]).public_hex());
}
