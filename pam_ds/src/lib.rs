// pam_ds: the PAM duress module. A Rust cdylib that PAM dlopens; the exported PAM symbols are the
// only C boundary, everything else is safe Rust. It sits in the auth stack AFTER pam_unix, so a normal
// password authenticates normally and only an unmatched password reaches this module.
//
// Behaviour:
//   - not enrolled (no duress hash on disk) -> PAM_IGNORE. Zero effect on a normal system.
//   - entered password matches the enrolled duress hash (constant-time) -> run the duress action, then
//     return an auth failure. It NEVER returns success, so a duress code never opens a session.
//   - anything else -> PAM_IGNORE, so the rest of the stack decides.
//
// The duress action is the erase actor, which is itself guarded so it only destroys on a machine
// marked disposable. `DS_FIRE_CMD` overrides the action (used by the test harness to observe the
// trigger without running anything destructive).

use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::process::Command;

struct PamDs;

impl PamServiceModule for PamDs {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        // Load the enrolled verifier. Absent => the tool is not armed here: do nothing, let the stack
        // proceed. This is what keeps an un-provisioned system completely unaffected.
        let stored = match std::fs::read_to_string(ds_core::duress_hash_path()) {
            Ok(s) => s,
            Err(_) => return PamError::IGNORE,
        };
        let verifier = match ds_core::DuressHash::parse(&stored) {
            Ok(v) => v,
            Err(_) => return PamError::IGNORE,
        };

        // The password the user just typed (pam_unix already tried and rejected it, or we run first
        // with try_first_pass). No prompt of our own, so a duress entry looks like a normal login.
        let authtok = match pamh.get_authtok(None) {
            Ok(Some(t)) => t,
            _ => return PamError::IGNORE,
        };

        match verifier.verify(authtok.to_bytes()) {
            Ok(true) => {
                fire();                 // run the duress action (guarded downstream)
                PamError::AUTH_ERR      // never SUCCESS: a duress code must not grant a session
            }
            // no match, or a hashing error: stay out of the way and let the stack decide.
            _ => PamError::IGNORE,
        }
    }

    // We do not manage credentials or sessions; be explicit so the stack is not disturbed.
    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError { PamError::IGNORE }
}

/// Launch the duress action and return without waiting on it (auth must not hang). Default action is
/// the erase actor (guarded); `DS_FIRE_CMD` overrides it for testing.
fn fire() {
    if let Ok(cmd) = std::env::var("DS_FIRE_CMD") {
        // split on whitespace: "prog arg arg". Enough for a test hook.
        let mut parts = cmd.split_whitespace();
        if let Some(prog) = parts.next() {
            let _ = Command::new(prog).args(parts).spawn();
        }
        return;
    }
    let _ = Command::new(format!("{}/ds-erase", ds_core::LIB_DIR)).arg("--fire").spawn();
}

pam_module!(PamDs);
