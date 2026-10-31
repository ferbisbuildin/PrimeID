use super::*;

const FIX: &str = include_str!("../tests/fixtures.json");
const NOW: u64 = 1_800_000_000;

fn fx(name: &str) -> Vec<u8> {
    let v: Value = serde_json::from_str(FIX).unwrap();
    v[name].to_string().into_bytes()
}

fn issuer() -> String {
    let v: Value = serde_json::from_str(FIX).unwrap();
    v["valid"]["credential"]["issuer"].as_str().unwrap().to_string()
}

fn imp(name: &str, pubk: &str, now: u64) -> Result<IssuancePackage, Error> {
    let iss = issuer();
    import_credential(&fx(name), pubk, &[iss.as_str()], now)
}

fn me() -> (SigningKey, String) {
    let k = holder_key(&[7u8; 32]);
    let p = pubkey_hex(&k);
    (k, p)
}

#[test]
fn holder_key_matches_noble_derivation() {
    let v: Value = serde_json::from_str(FIX).unwrap();
    assert_eq!(me().1, v["holder_pub"].as_str().unwrap());
}

#[test]
fn import_checks_issuer_binding_and_expiry() {
    let (_, pubk) = me();
    let pkg = imp("valid", &pubk, NOW).unwrap();
    assert_eq!(pkg.disclosures.len(), 3);
    assert_eq!(imp("forged", &pubk, NOW).unwrap_err(), Error::IssuerSignature);
    assert_eq!(imp("other_holder", &pubk, NOW).unwrap_err(), Error::NotBoundToThisDevice);
    assert_eq!(imp("valid", &pubk, 5_000_000_000).unwrap_err(), Error::Expired);
    assert_eq!(import_credential(&fx("valid"), &pubk, &[], NOW).unwrap_err(), Error::UntrustedIssuer);
    assert!(matches!(import_credential(b"not json", &pubk, &[], NOW), Err(Error::Malformed(_))));
}

#[test]
fn import_rejects_salt_that_does_not_match_signed_hash() {
    let (_, pubk) = me();
    let mut v: Value = serde_json::from_str(FIX).unwrap();
    v["valid"]["disclosures"][0]["value"] = "false".into();
    let bad = v["valid"].to_string();
    assert_eq!(import_credential(bad.as_bytes(), &pubk, &[issuer().as_str()], NOW).unwrap_err(), Error::DisclosureMismatch("over_18".into()));
}

#[test]
fn request_signature_and_expiry() {
    assert!(parse_request(&fx("request"), NOW).is_ok());
    assert_eq!(parse_request(&fx("tampered_request"), NOW).unwrap_err(), Error::RequestSignature);
    assert_eq!(parse_request(&fx("request"), 5_000_000_000).unwrap_err(), Error::RequestExpired);
}

#[test]
fn answer_reveals_one_claim_and_is_written_for_js_check() {
    let (k, pubk) = me();
    let store = vec![imp("valid", &pubk, NOW).unwrap()];
    let req = parse_request(&fx("request"), NOW).unwrap();
    let (cred, d) = find_claim(&store, &[], &req.requested_claim, NOW).unwrap();
    let answer = build_answer(&cred.credential, d, &req, &k);
    assert!(!answer.contains("Asha Rao") && !answer.contains("\"IN\""));
    std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/target-answer.json"), &answer).unwrap();
    assert!(find_claim(&store, &[], "income", NOW).is_err());
}

#[test]
fn revocation_must_be_issuer_signed_and_hides_credential() {
    let (_, pubk) = me();
    let iss = issuer();
    let store = vec![imp("valid", &pubk, NOW).unwrap()];
    let rev = parse_revocation(&fx("revocation"), &[iss.as_str()]).unwrap();
    assert_eq!(parse_revocation(&fx("revocation_forged"), &[iss.as_str()]).unwrap_err(), Error::IssuerSignature);
    assert_eq!(parse_revocation(&fx("revocation"), &[]).unwrap_err(), Error::UntrustedIssuer);
    assert!(is_revoked(&store[0].credential, &[rev.clone()]));
    assert!(find_claim(&store, &[rev], "over_18", NOW).is_err());
}
