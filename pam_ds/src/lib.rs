// pam_ds: the PAM duress module + attempt-limit enforcer. A Rust cdylib PAM dlopens; the exported PAM
// symbols are the only C boundary, everything else is safe Rust. Not enrolled (no duress hash) => it
// does nothing, so an un-provisioned system is completely unaffected.
//
// Mode-aware (via the PAM line's argument), mirroring pam_faillock's preauth/authfail/authsucc split so
// we can tell a wrong password (a real failure, seen only after pam_unix rejects it) from a right one:
//
//   (no arg) | "duress"  -- runs FIRST. (1) If locked out within the cooldown, deny. (2) If the entered
//                           password is the duress code, fire the wipe and fail (never a session).
//                           Otherwise IGNORE so pam_unix decides.
//   "authfail"           -- runs AFTER pam_unix, on the failure path only. Records one CONSECUTIVE
//                           failure; on the lockout line shows the wipe warning; at the wipe line fires.
//   "authsucc"           -- runs AFTER a successful pam_unix. Resets the counter (any success clears it).
//
// The wipe action is ds-erase, itself guarded to a machine marked disposable. DS_FIRE_CMD overrides it
// for testing. Thresholds come from DS_LOCKOUT_AT / DS_WIPE_AT / DS_COOLDOWN (else ds-core defaults).

use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::process::Command;

struct PamDs;

fn env_u32(k: &str, d: u32) -> u32 { std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d) }
fn env_u64(k: &str, d: u64) -> u64 { std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d) }
fn lockout_at() -> u32 { env_u32("DS_LOCKOUT_AT", ds_core::DEFAULT_LOCKOUT_AT) }
fn wipe_at()    -> u32 { env_u32("DS_WIPE_AT", ds_core::DEFAULT_WIPE_AT) }
fn cooldown()   -> u64 { env_u64("DS_COOLDOWN", ds_core::DEFAULT_COOLDOWN_SECS) }

/// Is the tool armed here (a duress verifier enrolled)? If not, the module is inert.
fn armed() -> bool { std::path::Path::new(&ds_core::duress_hash_path()).exists() }

impl PamServiceModule for PamDs {
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        if !armed() { return PamError::IGNORE; }
        match args.first().map(String::as_str) {
            Some("authfail") => on_authfail(),
            Some("authsucc") => { ds_core::reset_attempts(); PamError::IGNORE }
            _ => preauth_and_duress(pamh),   // default / "duress"
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError { PamError::IGNORE }
}

/// Runs first: detect the duress code. (Lockout is NOT enforced here as a hard-die: that would stop the
/// counter from ever reaching the wipe threshold, since a denied attempt never reaches `authfail`.
/// Instead we IGNORE and let pam_unix reject the wrong password -> authfail counts it -> escalation
/// still happens. The lockout's user-visible effect is the warning + the eventual wipe; if a
/// time-based cooldown is wanted it belongs on pam_unix/faillock, which does not block our escalation.)
fn preauth_and_duress(pamh: Pam) -> PamError {
    let stored = match std::fs::read_to_string(ds_core::duress_hash_path()) {
        Ok(s) => s, Err(_) => return PamError::IGNORE,
    };
    let verifier = match ds_core::DuressHash::parse(&stored) {
        Ok(v) => v, Err(_) => return PamError::IGNORE,
    };
    let authtok = match pamh.get_authtok(None) {
        Ok(Some(t)) => t, _ => return PamError::IGNORE,
    };
    match verifier.verify(authtok.to_bytes()) {
        Ok(true) => { fire(); PamError::AUTH_ERR }   // duress: instant wipe, never a session
        _ => PamError::IGNORE,                        // real password: let pam_unix decide
    }
}

/// Runs only on the pam_unix failure path: this was a genuine wrong password. Count it, warn + pace at
/// the lockout line, and fire the wipe at the wipe line. Returns AUTH_ERR so the failure stands.
///
/// The "lockout for a while" is a pacing DELAY here rather than a hard time-window deny, for two
/// reasons: (1) a hard preauth deny would stop the counter ever reaching the wipe threshold (a denied
/// attempt never reaches this line), defeating the escalation; (2) a time-window lock on a local
/// console is trivially bypassed by rebooting anyway. A per-attempt delay slows a brute-force just as
/// well and cannot break escalation. DS_LOCKOUT_DELAY sets the delay (seconds; 0 in tests).
fn on_authfail() -> PamError {
    let count = ds_core::record_failure().unwrap_or(0);
    if ds_core::should_wipe(count, wipe_at()) {
        eprintln!("\nDEATHSTROKE: attempt limit reached. Destroying this system.");
        fire();
    } else if ds_core::crossed_lockout(count, lockout_at()) {
        eprintln!("\nDEATHSTROKE WARNING: too many failed attempts. Further failures will DESTROY this system.");
        let delay = env_u64("DS_LOCKOUT_DELAY", 10);   // seconds of pacing past the lockout line
        if delay > 0 { std::thread::sleep(std::time::Duration::from_secs(delay)); }
    }
    PamError::AUTH_ERR
}

/// Launch the wipe action without waiting (auth must not hang). Default is the guarded erase actor.
fn fire() {
    if let Ok(cmd) = std::env::var("DS_FIRE_CMD") {
        let mut parts = cmd.split_whitespace();
        if let Some(prog) = parts.next() { let _ = Command::new(prog).args(parts).spawn(); }
        return;
    }
    let _ = Command::new(format!("{}/ds-erase", ds_core::LIB_DIR)).arg("--fire").spawn();
}

pam_module!(PamDs);
