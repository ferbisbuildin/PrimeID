//! PrimeID device logic: holder key, encrypted vault, offer import, and request approval.
//!
//! Secrets never leave this module: the app seed is used once to derive the holder key and the
//! vault key, then dropped. Nothing secret or personal is logged.

use std::{
    cell::RefCell,
    io::Read,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use primeid_core::{
    crypto::{fingerprint, vault_key_from_app_seed, HolderKey},
    protocol::{build_answer, parse_scanned, to_canonical_json, CredentialOffer, HolderKeyQr, Request, Requester, Scanned},
    vault::{Decision, Receipt, VaultData},
};
use slint_keyos_platform::{
    file_backed::FileBacked,
    gui_server_api::navigation::{
        filepicker::{AllowedExtensions, AllowedLocations, Location, SelectFileOptions},
        qrscanner::{ScanQrOptions, ScanQrResult},
    },
    navigation::{open_qr_scanner, select_file},
    slint::{self, ComponentHandle, Image, ModelRc, SharedString, VecModel},
};
use zeroize::Zeroizing;

use crate::{
    fs_permissions::FileSystemPermissions, gui_permissions::GuiPermissions, AppState, AppWindow, Callbacks,
    ClaimRow, CredRow, FileSystem, ReceiptRow, Screen,
};

security::use_api!();

const VAULT_FILE: &str = "primeid_vault.bin";
/// Byte-mode QR capacity at the lowest error-correction level is 2953; stay well under it.
const MAX_QR_BYTES: usize = 2300;
const MAX_IMPORT_BYTES: u64 = 16 * 1024;

type VaultFile = FileBacked<Vec<u8>, FileSystemPermissions>;

/// Unlocked state. Exists only after GetAppSeed succeeded and the vault decrypted.
struct Unlocked {
    holder: HolderKey,
    vault_key: Zeroizing<[u8; 32]>,
    file: VaultFile,
    data: VaultData,
}

enum Pending {
    None,
    Offer(CredentialOffer),
    Request(Request, Requester),
}

struct App {
    ui: slint::Weak<AppWindow>,
    unlocked: Option<Unlocked>,
    pending: Pending,
}

pub fn init(ui: &AppWindow) {
    let app = Rc::new(RefCell::new(App { ui: ui.as_weak(), unlocked: None, pending: Pending::None }));
    let cb = ui.global::<Callbacks>();

    cb.on_show_key(with(&app, App::show_key));
    cb.on_accept_offer(with(&app, App::accept_offer));
    cb.on_approve(with(&app, App::approve));
    cb.on_deny(with(&app, App::deny));
    cb.on_go_home(with(&app, |a| a.go_home("")));
    cb.on_show_credentials(with(&app, App::show_credentials));
    cb.on_show_receipts(with(&app, App::show_receipts));
    cb.on_dismiss_error(with(&app, App::dismiss_error));
    // Modal pickers run without holding the state borrow; the result is handled afterwards.
    cb.on_scan({
        let app = app.clone();
        move || {
            if let Some(data) = scan_qr(&app) {
                app.borrow_mut().handle_payload(&data);
            }
        }
    });
    cb.on_import_file({
        let app = app.clone();
        move || match pick_file() {
            Ok(Some(data)) => app.borrow_mut().handle_payload(&data),
            Ok(None) => {}
            Err(msg) => app.borrow().fail(msg),
        }
    });

    // GetAppSeed is grantOnFirstUse and may show a system prompt, so it must run on the UI
    // thread after the event loop has started, never before ui.run().
    slint::Timer::single_shot(Duration::ZERO, {
        let app = app.clone();
        move || app.borrow_mut().unlock()
    });
}

fn with(app: &Rc<RefCell<App>>, f: impl Fn(&mut App) + 'static) -> impl Fn() + 'static {
    let app = app.clone();
    move || f(&mut app.borrow_mut())
}

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

impl App {
    fn ui(&self) -> AppWindow { self.ui.upgrade().expect("app window alive") }

    fn set_screen(&self, screen: Screen) { self.ui().global::<AppState>().set_screen(screen); }

    fn fail(&self, msg: impl Into<SharedString>) {
        let ui = self.ui();
        ui.global::<AppState>().set_message(msg.into());
        ui.global::<AppState>().set_screen(Screen::Error);
    }

    fn unlock(&mut self) {
        let seed = match Security::default().app_seed() {
            Ok(seed) => seed,
            Err(_) => {
                self.fail("PrimeID needs its app key from the secure element. Access was denied, so nothing was created.");
                return;
            }
        };
        let holder = HolderKey::from_app_seed(seed.as_bytes());
        let vault_key = vault_key_from_app_seed(seed.as_bytes());
        drop(seed);

        let (file, _existed) = match VaultFile::try_new(VAULT_FILE, fs::Location::AppData) {
            Ok(f) => f,
            Err(e) => {
                log::error!("vault file unavailable: {e}");
                self.fail("The vault file could not be opened on this device.");
                return;
            }
        };
        // A blob that fails to decrypt is refused, never overwritten, so nothing is lost.
        let data = match VaultData::open(&vault_key, &file) {
            Ok(d) => d,
            Err(e) => {
                self.fail(format!("Vault could not be opened: {e}"));
                return;
            }
        };
        self.unlocked = Some(Unlocked { holder, vault_key, file, data });
        self.go_home("");
    }

    fn dismiss_error(&mut self) {
        if self.unlocked.is_some() {
            self.go_home("");
        } else {
            self.ui().global::<AppState>().set_message("Unlocking PrimeID...".into());
            self.set_screen(Screen::Loading);
            self.unlock();
        }
    }

    fn go_home(&mut self, notice: &str) {
        self.pending = Pending::None;
        let Some(u) = &self.unlocked else { return };
        let state = self.ui().global::<AppState>();
        state.set_holder_fingerprint(fingerprint(&u.holder.public_hex()).into());
        state.set_credential_count(u.data.credentials.len() as i32);
        state.set_issuer_count(u.data.trusted_issuers.len() as i32);
        state.set_notice(notice.into());
        state.set_screen(Screen::Home);
    }

    fn show_qr(&self, title: &str, caption: &str, payload: &str, screen: Screen) {
        if payload.len() > MAX_QR_BYTES {
            self.fail(format!("This code is {} bytes, too large for one QR ({MAX_QR_BYTES} max).", payload.len()));
            return;
        }
        let image: Image = slint_keyos_platform::qrcode::render(
            payload.as_bytes(),
            slint::Color::from_rgb_u8(0, 0, 0),
            slint::Color::from_rgb_u8(255, 255, 255),
        );
        let state = self.ui().global::<AppState>();
        state.set_qr_image(image);
        state.set_qr_title(title.into());
        state.set_qr_caption(caption.into());
        state.set_screen(screen);
    }

    fn show_key(&mut self) {
        let Some(u) = &self.unlocked else { return };
        match to_canonical_json(&HolderKeyQr::new(&u.holder)) {
            Ok(json) => self.show_qr(
                "My holder key",
                &format!("Public key only. Let the issuer scan it.\n{}", fingerprint(&u.holder.public_hex())),
                &json,
                Screen::HolderQr,
            ),
            Err(e) => self.fail(e.to_string()),
        }
    }

    fn handle_payload(&mut self, raw: &[u8]) {
        let Some(u) = &self.unlocked else { return };
        let now = now();
        match parse_scanned(raw) {
            Err(e) => self.fail(e.to_string()),
            Ok(Scanned::Offer(offer)) => {
                if let Err(e) = offer.verify_for_holder(&u.holder.public_hex(), now) {
                    self.fail(e.to_string());
                    return;
                }
                let trusted = u.data.is_trusted(&offer.cred.iss);
                let warning = if trusted {
                    String::new()
                } else if u.data.trusted_issuers.iter().any(|t| t.name == offer.cred.iss_name) {
                    "WARNING: a different key already uses this issuer name. This may be an impostor.".into()
                } else {
                    "First credential from this issuer. Check the key matches the one shown on the issuer's screen.".into()
                };
                let claims: Vec<ClaimRow> = offer
                    .disc
                    .iter()
                    .map(|d| ClaimRow { key: d.k.as_str().into(), value: d.v.as_str().into() })
                    .collect();
                let state = self.ui().global::<AppState>();
                state.set_offer_issuer(offer.cred.iss_name.as_str().into());
                state.set_offer_issuer_fingerprint(fingerprint(&offer.cred.iss).into());
                state.set_offer_issuer_trusted(trusted);
                state.set_offer_warning(warning.into());
                state.set_offer_expires(date(offer.cred.exp).into());
                state.set_offer_claims(ModelRc::new(VecModel::from(claims)));
                state.set_screen(Screen::ImportReview);
                self.pending = Pending::Offer(offer);
            }
            Ok(Scanned::Request(req)) => {
                if let Err(e) = req.verify_signature_and_time(now) {
                    self.fail(e.to_string());
                    return;
                }
                if u.data.answered_nonce(&req.nonce) {
                    self.fail("This request was already answered. Ask the verifier for a fresh one.");
                    return;
                }
                let requester = req.requester(&u.data.trusted_issuer_keys(), now);
                let (name, verified, detail) = match &requester {
                    Requester::Verified { name, certified_by } => {
                        (name.clone(), true, format!("Certified by {certified_by}"))
                    }
                    Requester::Unknown { claimed_name, reason } => {
                        (format!("\"{claimed_name}\" (unconfirmed)"), false, (*reason).to_string())
                    }
                };
                let found = u.data.find_for_claim(&req.claim, now);
                let (can_answer, share, withheld) = match found {
                    Some((sc, d)) => (
                        true,
                        format!("Will share: {} = {}\nSigned by this Prime, bound to this request only.", d.k, d.v),
                        sc.cred_keys_except(&d.k),
                    ),
                    None => (false, "No valid credential from a trusted issuer holds this claim.".to_string(), vec![]),
                };
                let state = self.ui().global::<AppState>();
                state.set_req_name(name.into());
                state.set_req_verified(verified);
                state.set_req_detail(detail.into());
                state.set_req_fingerprint(fingerprint(&req.aud).into());
                state.set_req_claim(req.claim.as_str().into());
                state.set_req_expires(time_of_day(req.exp).into());
                state.set_req_can_answer(can_answer);
                state.set_req_share(share.into());
                let withheld: Vec<SharedString> = withheld.into_iter().map(Into::into).collect();
                state.set_req_withheld(ModelRc::new(VecModel::from(withheld)));
                state.set_screen(Screen::RequestReview);
                self.pending = Pending::Request(req, requester);
            }
        }
    }

    fn accept_offer(&mut self) {
        let Pending::Offer(offer) = std::mem::replace(&mut self.pending, Pending::None) else { return };
        let Some(u) = &mut self.unlocked else { return };
        let now = now();
        // Re-check at the moment of saving; the screen may have been open for a while.
        if let Err(e) = offer.verify_for_holder(&u.holder.public_hex(), now) {
            self.fail(e.to_string());
            return;
        }
        u.data.trust_issuer(&offer.cred.iss, &offer.cred.iss_name, now);
        let issuer = offer.cred.iss_name.clone();
        u.data.store(offer.cred, offer.disc, now);
        match u.persist() {
            Ok(()) => self.go_home(&format!("Saved credential from {issuer}.")),
            Err(msg) => self.fail(msg),
        }
    }

    fn approve(&mut self) {
        let Pending::Request(req, requester) = std::mem::replace(&mut self.pending, Pending::None) else { return };
        let Some(u) = &mut self.unlocked else { return };
        let now = now();
        if let Err(e) = req.verify_signature_and_time(now) {
            self.fail(e.to_string());
            return;
        }
        if u.data.answered_nonce(&req.nonce) {
            self.fail("This request was already answered.");
            return;
        }
        let Some((sc, disc)) = u.data.find_for_claim(&req.claim, now) else {
            self.fail("No valid credential holds this claim any more.");
            return;
        };
        let (cred, disc, withheld) = (sc.cred.clone(), disc.clone(), sc.cred_keys_except(&disc.k));
        let answer = match build_answer(&u.holder, &cred, &disc, &req).and_then(|a| to_canonical_json(&a)) {
            Ok(json) => json,
            Err(e) => {
                self.fail(e.to_string());
                return;
            }
        };
        if answer.len() > MAX_QR_BYTES {
            self.fail(format!("Answer is {} bytes, too large for one QR. Nothing was shared.", answer.len()));
            return;
        }
        u.data.add_receipt(receipt(&req, &requester, Decision::Approved, Some(disc.v.clone()), withheld, now));
        if let Err(msg) = u.persist() {
            self.fail(msg);
            return;
        }
        self.show_qr(
            "Signed answer",
            &format!("Let {} scan this. It shares {} only.", req.aud_name, disc.k),
            &answer,
            Screen::AnswerQr,
        );
    }

    fn deny(&mut self) {
        let Pending::Request(req, requester) = std::mem::replace(&mut self.pending, Pending::None) else { return };
        let Some(u) = &mut self.unlocked else { return };
        u.data.add_receipt(receipt(&req, &requester, Decision::Denied, None, vec![], now()));
        match u.persist() {
            Ok(()) => self.go_home("Request denied. Nothing was shared."),
            Err(msg) => self.fail(msg),
        }
    }

    fn show_credentials(&mut self) {
        let Some(u) = &self.unlocked else { return };
        let now = now();
        let rows: Vec<CredRow> = u
            .data
            .credentials
            .iter()
            .rev()
            .map(|c| CredRow {
                issuer: c.cred.iss_name.as_str().into(),
                issuer_fingerprint: fingerprint(&c.cred.iss).into(),
                claims: c.disc.iter().map(|d| format!("{}: {}", d.k, d.v)).collect::<Vec<_>>().join("\n").into(),
                expires: date(c.cred.exp).into(),
                expired: c.cred.exp < now,
            })
            .collect();
        let state = self.ui().global::<AppState>();
        state.set_credentials(ModelRc::new(VecModel::from(rows)));
        state.set_screen(Screen::Credentials);
    }

    fn show_receipts(&mut self) {
        let Some(u) = &self.unlocked else { return };
        let rows: Vec<ReceiptRow> = u
            .data
            .receipts
            .iter()
            .rev()
            .map(|r| ReceiptRow {
                when: format!("{} {}", date(r.at), time_of_day(r.at)).into(),
                requester: r.requester.as_str().into(),
                verified: r.verified,
                claim: r.claim.as_str().into(),
                outcome: match (&r.decision, &r.shared) {
                    (Decision::Approved, Some(v)) => format!("shared \"{v}\""),
                    (Decision::Approved, None) => "shared".into(),
                    (Decision::Denied, _) => "denied".into(),
                }
                .into(),
                withheld: if r.withheld.is_empty() {
                    SharedString::new()
                } else {
                    format!("Kept on Prime: {}", r.withheld.join(", ")).into()
                },
            })
            .collect();
        let state = self.ui().global::<AppState>();
        state.set_receipts(ModelRc::new(VecModel::from(rows)));
        state.set_screen(Screen::Receipts);
    }
}

impl Unlocked {
    /// Re-seals the whole vault under a fresh nonce and writes it to AppData.
    fn persist(&mut self) -> Result<(), String> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| "No randomness available; nothing was saved.".to_string())?;
        let blob = self.data.seal(&self.vault_key, nonce).map_err(|e| e.to_string())?;
        // The guard writes on drop; FileBacked treats a failed write as fatal by design.
        *self.file.guard() = blob;
        Ok(())
    }
}

trait CredKeys {
    fn cred_keys_except(&self, shared: &str) -> Vec<String>;
}

impl CredKeys for primeid_core::vault::StoredCredential {
    fn cred_keys_except(&self, shared: &str) -> Vec<String> {
        self.disc.iter().filter(|d| d.k != shared).map(|d| d.k.clone()).collect()
    }
}

fn receipt(
    req: &Request,
    requester: &Requester,
    decision: Decision,
    shared: Option<String>,
    withheld: Vec<String>,
    at: u64,
) -> Receipt {
    let (name, verified) = match requester {
        Requester::Verified { name, .. } => (name.clone(), true),
        Requester::Unknown { claimed_name, .. } => (claimed_name.clone(), false),
    };
    Receipt {
        at,
        requester: name,
        requester_key: req.aud.clone(),
        verified,
        claim: req.claim.clone(),
        decision,
        shared,
        withheld,
        nonce: req.nonce.clone(),
    }
}

/// Opens the system QR scanner. Returns the raw payload, or None if the user backed out.
fn scan_qr(app: &Rc<RefCell<App>>) -> Option<Vec<u8>> {
    if app.borrow().unlocked.is_none() {
        return None;
    }
    let opts = ScanQrOptions {
        header_title: "Scan PrimeID code".into(),
        message: "Credential offer from an issuer, or proof request from a verifier".into(),
        header_left_icon: String::from("chevron-left"),
        ..ScanQrOptions::default()
    };
    match open_qr_scanner::<GuiPermissions>(opts) {
        Ok(Some(ScanQrResult::Qr { data, .. })) => Some(data),
        Ok(Some(ScanQrResult::LeftClicked)) | Ok(None) => None,
        Ok(Some(_)) => {
            app.borrow().fail("That code is not a PrimeID QR.");
            None
        }
        Err(e) => {
            log::error!("qr scanner error: {e:?}");
            app.borrow().fail("The QR scanner could not be opened. Use Import from file instead.");
            None
        }
    }
}

/// Lets the user pick a .json offer/request from internal storage or USB and reads it.
fn pick_file() -> Result<Option<Vec<u8>>, String> {
    const LOCATIONS: &[Location] = &[Location::Internal, Location::External];
    let options = SelectFileOptions::default()
        .with_hidden_allowed(false)
        .with_start_location(LOCATIONS[0])
        .with_allowed_locations(AllowedLocations::specific(LOCATIONS.to_owned()))
        .with_allowed_extensions(AllowedExtensions::specific::<&str, Vec<&str>>(vec!["json"]));
    let picked = select_file::<GuiPermissions>(options).map_err(|e| {
        log::error!("file picker error: {e:?}");
        "The file picker could not be opened.".to_string()
    })?;
    let Some((path, location)) = picked.and_then(|p| p.files().get(0).cloned()) else { return Ok(None) };
    let location = match location {
        Location::Internal => fs::Location::User,
        Location::External => fs::Location::Usb,
        Location::Airlock => fs::Location::Airlock,
    };
    let file = FileSystem::default()
        .open_file(path.trim_matches('/'), location, fs::OpenFlags { read: true, write: false, create: false })
        .map_err(|e| {
            log::warn!("open selected file failed: {e:?}");
            "That file could not be opened.".to_string()
        })?;
    let mut data = Vec::new();
    file.take(MAX_IMPORT_BYTES + 1).read_to_end(&mut data).map_err(|_| "That file could not be read.".to_string())?;
    if data.len() as u64 > MAX_IMPORT_BYTES {
        return Err("That file is too large to be a PrimeID offer or request.".into());
    }
    Ok(Some(data))
}

/// UTC calendar date for a unix timestamp (Howard Hinnant's civil_from_days).
fn date(ts: u64) -> String {
    let z = (ts / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn time_of_day(ts: u64) -> String {
    let s = ts % 86_400;
    format!("{:02}:{:02} UTC", s / 3600, (s % 3600) / 60)
}
