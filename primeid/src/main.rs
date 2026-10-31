// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

mod theme;

use std::cell::RefCell;
use std::rc::Rc;

use primeid_core::{self as core, k256::ecdsa::SigningKey, Request, StoredCredential};
use serde::{Deserialize, Serialize};
use slint_keyos_platform::fs::Location;
use slint_keyos_platform::gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult};
use slint_keyos_platform::slint::{Color, ComponentHandle, ModelRc, SharedString, VecModel};
use slint_keyos_platform::{app_ui2, navigation::open_qr_scanner};

app_ui2!("PrimeID");
security::use_api!();

const STATE_FILE: &str = "primeid.json";

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Vault {
    credentials: Vec<StoredCredential>,
    trusted: Vec<Trusted>,
    receipts: Vec<Receipt>,
    revocations: Vec<core::Revocation>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Trusted {
    name: String,
    pubkey: String,
    issuer: bool,
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    time: u64,
    verifier_name: String,
    verifier_pubkey: String,
    trusted: bool,
    claim: String,
    approved: bool,
    shared: Option<String>,
    credential_id: String,
    nonce: String,
}

/// What the user is being asked to approve on the device screen.
enum Pending {
    Disclose { req: Request, trusted: bool, cred_idx: usize },
    Trust(Trusted),
}

struct State {
    key: SigningKey,
    pubkey: String,
    vault: Vault,
    pending: Option<Pending>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn short(hex: &str) -> String {
    if hex.len() > 16 { format!("{}…{}", &hex[..8], &hex[hex.len() - 8..]) } else { hex.to_string() }
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    theme::init(&ui);

    // Ask for the seed only once our window is live: GetAppSeed is grant-on-first-use, and KeyOS
    // can only show its permission prompt over an app that has drawn a frame.
    ui.set_screen("UNLOCK".into());
    let ui_weak = ui.as_weak();
    slint_keyos_platform::slint::Timer::single_shot(std::time::Duration::from_millis(200), move || {
        if let Some(ui) = ui_weak.upgrade() {
            unlock(cx, &ui);
        }
    });
    ui.run().expect("UI running");
}

fn unlock(cx: AppContext, ui: &AppWindow) {
    // The holder key exists only in memory, derived from the secure element's per-app seed.
    log::info!("requesting app seed from secure element");
    let key = match Security::default().app_seed() {
        Ok(seed) => core::holder_key(seed.as_bytes()),
        Err(_) => {
            log::warn!("app seed denied");
            ui.set_fatal("The secure element did not release PrimeID's app seed (permission denied or device locked). PrimeID cannot run without its device-bound key.".into());
            ui.set_screen("FATAL".into());
            return;
        }
    };
    let pubkey = core::pubkey_hex(&key);
    log::info!("holder key ready, public key {pubkey}");
    let vault = match cx.fs.durable_file_read(STATE_FILE, Location::AppData) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            log::error!("vault unreadable, starting empty: {e}");
            Vault::default()
        }),
        Err(_) => Vault::default(),
    };
    let state = Rc::new(RefCell::new(State { key, pubkey, vault, pending: None }));
    let fs = cx.fs.clone();
    let save = Rc::new(move |v: &Vault| -> bool {
        log::info!("saving vault");
        let res = fs.durable_file_write(STATE_FILE, Location::AppData, &serde_json::to_vec(v).unwrap());
        log::info!("vault save result ok={}", res.is_ok());
        let ok = res.is_ok();
        if !ok {
            log::error!("vault write failed");
        }
        ok
    });

    refresh(ui, &state.borrow());
    ui.set_holder_pubkey(state.borrow().pubkey.clone().into());
    ui.set_key_qr(slint_keyos_platform::qrcode::render(&state.borrow().pubkey, Color::from_rgb_u8(0, 0, 0), Color::from_rgb_u8(255, 255, 255)));

    let handle_payload = {
        let (ui, state, save) = (ui.as_weak(), state.clone(), save.clone());
        Rc::new(move |bytes: Vec<u8>| {
            let Some(ui) = ui.upgrade() else { return };
            on_payload(&ui, &mut state.borrow_mut(), &*save, bytes.trim_ascii());
        })
    };

    {
        let (ui_weak, handle) = (ui.as_weak(), handle_payload.clone());
        ui.on_scan(move || {
            let opts = ScanQrOptions { header_title: "PrimeID".into(), message: "Scan a credential or verifier request".into(), ..Default::default() };
            match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr { data, .. })) => handle(data),
                Ok(Some(ScanQrResult::Ur2 { .. })) => show_msg(&ui_weak.unwrap(), false, "Unsupported QR", "PrimeID reads plain QR payloads, not UR."),
                Ok(_) => {} // cancelled
                Err(e) => show_msg(&ui_weak.unwrap(), false, "Scanner unavailable", &format!("{e:?}")),
            }
        });
    }
    {
        let handle = handle_payload.clone();
        ui.on_submit_text(move |text| handle(text.as_bytes().to_vec()));
    }
    {
        let (ui_weak, state, save) = (ui.as_weak(), state.clone(), save.clone());
        ui.on_wipe(move || {
            let ui = ui_weak.unwrap();
            let mut s = state.borrow_mut();
            s.vault = Vault::default();
            s.pending = None;
            if !save(&s.vault) {
                return show_msg(&ui, false, "Storage error", "Could not erase the vault.");
            }
            refresh(&ui, &s);
            show_msg(&ui, true, "Erased", "All credentials, trusted parties and receipts were removed from this Prime. Your holder key is unchanged: it comes from the device seed.");
        });
    }
    {
        let (ui_weak, state, save) = (ui.as_weak(), state.clone(), save.clone());
        ui.on_decide(move |approved| {
            let ui = ui_weak.unwrap();
            decide(&ui, &mut state.borrow_mut(), &*save, approved);
        });
    }
    ui.set_screen("HOME".into());
}

fn refresh(ui: &AppWindow, s: &State) {
    let v = &s.vault;
    ui.set_credential_count(v.credentials.len() as i32);
    ui.set_receipt_count(v.receipts.len() as i32);
    let creds: Vec<SharedString> = v
        .credentials
        .iter()
        .map(|c| {
            let keys: Vec<&str> = c.disclosures.iter().map(|d| d.key.as_str()).collect();
            let state = if core::is_revoked(&c.credential, &v.revocations) {
                "REVOKED"
            } else if now() > c.credential.expires {
                "EXPIRED"
            } else {
                "valid"
            };
            format!("{} · {} · {}", c.credential.issuer_name, keys.join(", "), state).into()
        })
        .collect();
    ui.set_credentials(ModelRc::new(VecModel::from(creds)));
    let receipts: Vec<SharedString> = v
        .receipts
        .iter()
        .rev()
        .map(|r| {
            let who = if r.trusted { "Trusted" } else { "Untrusted" };
            let what = match (&r.shared, r.approved) {
                (Some(val), true) => format!("shared {} = {}", r.claim, val),
                _ => format!("DENIED {}", r.claim),
            };
            format!(
                "{}  ·  {} UTC\n{} requester · {}\n{}",
                r.verifier_name,
                hhmm(r.time),
                who,
                short(&r.verifier_pubkey),
                what
            )
            .into()
        })
        .collect();
    ui.set_receipts(ModelRc::new(VecModel::from(receipts)));
}

fn show_msg(ui: &AppWindow, ok: bool, title: &str, body: &str) {
    ui.set_msg_ok(ok);
    ui.set_msg_title(title.into());
    ui.set_msg_body(body.into());
    ui.set_screen("MESSAGE".into());
}

fn on_payload(ui: &AppWindow, s: &mut State, save: &dyn Fn(&Vault) -> bool, bytes: &[u8]) {
    log::info!("payload received, {} bytes", bytes.len());
    let v: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return show_msg(ui, false, "Not a PrimeID payload", "The data is not valid JSON."),
    };
    let t = now();
    if v.get("credential").is_some() {
        let issuers: Vec<&str> = s.vault.trusted.iter().filter(|tr| tr.issuer).map(|tr| tr.pubkey.as_str()).collect();
        match core::import_credential(bytes, &s.pubkey, &issuers, t) {
            Ok(pkg) => {
                let keys: Vec<String> = pkg.disclosures.iter().map(|d| d.key.clone()).collect();
                let issuer = pkg.credential.issuer_name.clone();
                if s.vault.credentials.iter().any(|c| c.credential.credential_id == pkg.credential.credential_id && c.credential.issuer != pkg.credential.issuer) {
                    return show_msg(ui, false, "Credential rejected", "A credential with this ID from a different issuer is already stored.");
                }
                s.vault.credentials.retain(|c| c.credential.credential_id != pkg.credential.credential_id);
                s.vault.credentials.push(pkg);
                if !save(&s.vault) {
                    return show_msg(ui, false, "Storage error", "The credential verified but could not be saved.");
                }
                refresh(ui, s);
                show_msg(ui, true, "Credential stored", &format!("Issuer signature valid. Bound to this Prime's key.\nIssuer: {issuer}\nClaims: {}", keys.join(", ")));
            }
            Err(e) => show_msg(ui, false, "Credential rejected", &e.to_string()),
        }
    } else if v.get("nonce").is_some() {
        let req = match core::parse_request(bytes, t) {
            Ok(r) => r,
            Err(e) => return show_msg(ui, false, "Request rejected", &e.to_string()),
        };
        let trusted = s.vault.trusted.iter().any(|tr| !tr.issuer && tr.pubkey.eq_ignore_ascii_case(&req.verifier_pubkey));
        let found = core::find_claim(&s.vault.credentials, &s.vault.revocations, &req.requested_claim, t)
            .map(|(c, d)| (c.credential.credential_id.clone(), d.value.clone(), c.disclosures.iter().filter(|o| o.key != d.key).map(|o| o.key.clone()).collect::<Vec<_>>()));
        let (cred_id, value, kept) = match found {
            Ok(f) => f,
            Err(e) => return show_msg(ui, false, "Cannot answer", &e.to_string()),
        };
        let cred_idx = s.vault.credentials.iter().position(|c| c.credential.credential_id == cred_id).unwrap();
        ui.set_req_trusted(trusted);
        ui.set_req_name(req.verifier_name.clone().into());
        ui.set_req_key(short(&req.verifier_pubkey).into());
        ui.set_req_claim(req.requested_claim.clone().into());
        ui.set_req_value(value.into());
        ui.set_req_kept(if kept.is_empty() { "nothing else".into() } else { kept.join(", ").into() });
        ui.set_req_expires_in(req.expires.saturating_sub(t) as i32);
        s.pending = Some(Pending::Disclose { req, trusted, cred_idx });
        ui.set_screen("REVIEW".into());
    } else if v.get("primeid_revocation").is_some() {
        let issuers: Vec<&str> = s.vault.trusted.iter().filter(|tr| tr.issuer).map(|tr| tr.pubkey.as_str()).collect();
        let rev = match core::parse_revocation(bytes, &issuers) {
            Ok(r) => r,
            Err(e) => return show_msg(ui, false, "Revocation list rejected", &e.to_string()),
        };
        if s.vault.revocations.iter().any(|l| l.issuer.eq_ignore_ascii_case(&rev.issuer) && l.published_at > rev.published_at) {
            return show_msg(ui, false, "Revocation list rejected", "A newer list from this issuer is already stored.");
        }
        let hit = s.vault.credentials.iter().filter(|c| core::is_revoked(&c.credential, std::slice::from_ref(&rev))).count();
        s.vault.revocations.retain(|l| !l.issuer.eq_ignore_ascii_case(&rev.issuer));
        s.vault.revocations.push(rev);
        if !save(&s.vault) {
            return show_msg(ui, false, "Storage error", "The revocation list verified but could not be saved.");
        }
        refresh(ui, s);
        show_msg(ui, true, "Revocation list applied", &format!("Issuer signature valid. {hit} stored credential(s) revoked and can no longer answer requests."));
    } else if let Some(tr) = v.get("primeid_trust") {
        let (Some(name), Some(pubkey), Some(role)) = (tr["name"].as_str(), tr["pubkey"].as_str(), tr["role"].as_str()) else {
            return show_msg(ui, false, "Invalid trust card", "Expected a name, a public key and a role.");
        };
        if role != "issuer" && role != "verifier" {
            return show_msg(ui, false, "Invalid trust card", "Role must be issuer or verifier.");
        }
        if hex::decode(pubkey).ok().and_then(|b| core::k256::PublicKey::from_sec1_bytes(&b).ok()).is_none() {
            return show_msg(ui, false, "Invalid trust card", "The public key is not a valid secp256k1 key.");
        }
        ui.set_req_name(name.into());
        ui.set_req_key(short(pubkey).into());
        ui.set_req_claim(role.into());
        s.pending = Some(Pending::Trust(Trusted { name: name.into(), pubkey: pubkey.to_lowercase(), issuer: role == "issuer" }));
        ui.set_screen("TRUST".into());
    } else {
        show_msg(ui, false, "Not a PrimeID payload", "Expected a credential, a verifier request, a trust card, or a revocation list.");
    }
}

fn decide(ui: &AppWindow, s: &mut State, save: &dyn Fn(&Vault) -> bool, approved: bool) {
    match s.pending.take() {
        Some(Pending::Disclose { req, trusted, cred_idx }) => {
            let t = now();
            if approved && t > req.expires {
                return show_msg(ui, false, "Request expired", "The request expired while waiting for approval. Ask the verifier for a new one.");
            }
            let stored = &s.vault.credentials[cred_idx];
            let d = stored.disclosures.iter().find(|d| d.key == req.requested_claim).cloned().unwrap();
            let answer = approved.then(|| core::build_answer(&stored.credential, &d, &req, &s.key));
            s.vault.receipts.push(Receipt {
                time: t,
                verifier_name: req.verifier_name.clone(),
                verifier_pubkey: req.verifier_pubkey.clone(),
                trusted,
                claim: req.requested_claim.clone(),
                approved,
                shared: approved.then(|| d.value.clone()),
                credential_id: stored.credential.credential_id.clone(),
                nonce: req.nonce.clone(),
            });
            let saved = save(&s.vault);
            refresh(ui, s);
            match answer {
                Some(a) => {
                    ui.set_answer_qr(slint_keyos_platform::qrcode::render(&a, Color::from_rgb_u8(0, 0, 0), Color::from_rgb_u8(255, 255, 255)));
                    ui.set_answer_text(a.into());
                    ui.set_screen("ANSWER".into());
                    if !saved {
                        log::error!("receipt not persisted");
                    }
                }
                None => show_msg(ui, true, "Denied", "Nothing was shared. The denial is in your privacy receipts."),
            }
        }
        Some(Pending::Trust(tr)) => {
            if approved {
                s.vault.trusted.retain(|t| !(t.pubkey == tr.pubkey && t.issuer == tr.issuer));
                s.vault.trusted.push(tr.clone());
                if !save(&s.vault) {
                    return show_msg(ui, false, "Storage error", "Could not save the trusted verifier.");
                }
                let what = if tr.issuer { "Credentials it signs can now be imported." } else { "Its requests will show as a verified requester." };
                show_msg(ui, true, "Trusted", &format!("{}: {what}", tr.name));
            } else {
                ui.set_screen("HOME".into());
            }
        }
        None => ui.set_screen("HOME".into()),
    }
}

fn hhmm(t: u64) -> String {
    format!("{:02}:{:02}", (t / 3600) % 24, (t / 60) % 60)
}
