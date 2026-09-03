// dsctl: the setup and control CLI. The non-destructive parts (set the duress code as a hash, verify
// a candidate, show status) are real and testable anywhere. The destructive and system-altering parts
// (enroll a LUKS recovery keyslot, insert the PAM line, enable the resume unit, i.e. "arm") only run
// on a machine marked disposable while they are under development. dsctl never stores the duress code,
// only its PBKDF2 hash. It reads and writes only the state dir; arming shells to stock cryptsetup and
// edits /etc/pam.d.

use anyhow::{bail, Context, Result};
use ds_core::{derive_and_zero, DuressHash, DEFAULT_ITERATIONS};
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Value of a `--name value` flag, if present.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

const DISPOSABLE_MARKER: &str = "/etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY";

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("dsctl: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("set-duress") => set_duress(),
        Some("verify")     => verify(args.get(1).map(String::as_str)),
        Some("status")     => status(),
        Some("enroll-recovery") => enroll_recovery(&args),
        Some("arm")        => arm(),
        Some("disarm")     => disarm(),
        _ => { eprintln!("usage: dsctl set-duress | verify [code] | status | enroll-recovery --device <dev> | arm | disarm"); std::process::exit(2); }
    }
}

// Where PAM finds the module and where the resume unit lives.
const PAM_MODULE: &str = "/usr/lib/security/pam_ds.so";
const SYSTEM_AUTH: &str = "/etc/pam.d/system-auth";
const ARM_MARKER: &str = "deathstr0ke-arm";
const RESUME_UNIT_SRC: &str = "/usr/lib/arxos/deathstroke/deathstroke-resume.service.disabled";
const RESUME_UNIT_DST: &str = "/etc/systemd/system/deathstroke-resume.service";

/// Add a LUKS recovery keyslot so the user can always get back in after a keyslot destruction. Needs
/// an existing passphrase to authorise the add (cryptsetup requirement). Destructive-adjacent, so it
/// runs only where marked disposable while under development.
fn enroll_recovery(args: &[String]) -> Result<()> {
    require_root()?;
    guard_disposable("enroll-recovery")?;
    let device = flag(args, "--device").context("enroll-recovery needs --device <luks-dev>")?;
    // key-files keep the test non-interactive: --existing-keyfile authorises, --new-keyfile is enrolled.
    let existing = flag(args, "--existing-keyfile").context("need --existing-keyfile <path>")?;
    let newkey = flag(args, "--new-keyfile").context("need --new-keyfile <path>")?;
    let st = Command::new("cryptsetup")
        .args(["luksAddKey", &device, &newkey, "--key-file", &existing])
        .status().context("cryptsetup luksAddKey")?;
    if !st.success() { bail!("luksAddKey failed on {device}"); }
    // record the device in state (metadata only, never the key). recovery.device documents where the
    // recovery slot lives; target.device is what ds-erase destroys on a duress trigger (the same LUKS
    // root), so pam_ds can fire `ds-erase --fire` with no arguments.
    let _ = std::fs::write(format!("{}/recovery.device", ds_core::state_dir()), &device);
    let _ = std::fs::write(format!("{}/target.device", ds_core::state_dir()), &device);
    println!("dsctl: recovery keyslot enrolled on {device} (erase target set).");
    Ok(())
}

/// Arm: place pam_ds into the auth stack and enable the boot-resume unit. Reversible via `disarm`.
/// The PAM line is inserted as the FIRST auth rule with a control map that treats our module's IGNORE
/// as "fall through" and its AUTH_ERR (a duress match) as "fail now", so a normal password is
/// unaffected and a duress code fails auth after firing. This ordering needs no fragile offset maths.
fn arm() -> Result<()> {
    require_root()?;
    guard_disposable("arm")?;
    if !Path::new(PAM_MODULE).exists() { bail!("{PAM_MODULE} not deployed"); }
    if !Path::new(&ds_core::duress_hash_path()).exists() { bail!("no duress code enrolled (dsctl set-duress)"); }
    let content = std::fs::read_to_string(SYSTEM_AUTH).with_context(|| format!("read {SYSTEM_AUTH}"))?;
    if content.contains(ARM_MARKER) { println!("dsctl: already armed."); return Ok(()); }
    std::fs::copy(SYSTEM_AUTH, format!("{SYSTEM_AUTH}.deathstr0ke.bak")).context("backup system-auth")?;
    let line = format!("auth      [success=ignore ignore=ignore default=die]     {PAM_MODULE}   # {ARM_MARKER}\n");
    // insert before the first existing `auth` line so it runs first; fall back to prepending.
    let new = match content.lines().position(|l| l.trim_start().starts_with("auth")) {
        Some(i) => { let mut v: Vec<String> = content.lines().map(String::from).collect(); v.insert(i, line.trim_end().to_string()); v.join("\n") + "\n" }
        None => format!("{line}{content}"),
    };
    write_atomic(SYSTEM_AUTH, &new)?;
    enable_resume_unit()?;
    println!("dsctl: armed. Duress code is live at the auth prompt; boot-resume enabled.");
    Ok(())
}

/// Disarm: remove the pam_ds line (restoring the backup) and disable the resume unit. Login returns to
/// stock. Always leaves a working auth stack.
fn disarm() -> Result<()> {
    require_root()?;
    let content = std::fs::read_to_string(SYSTEM_AUTH).with_context(|| format!("read {SYSTEM_AUTH}"))?;
    if !content.contains(ARM_MARKER) { println!("dsctl: not armed."); }
    else {
        let bak = format!("{SYSTEM_AUTH}.deathstr0ke.bak");
        if Path::new(&bak).exists() {
            let orig = std::fs::read_to_string(&bak)?;
            write_atomic(SYSTEM_AUTH, &orig)?;
            let _ = std::fs::remove_file(&bak);
        } else {
            // no backup: strip the marked line surgically.
            let kept: Vec<&str> = content.lines().filter(|l| !l.contains(ARM_MARKER)).collect();
            write_atomic(SYSTEM_AUTH, &(kept.join("\n") + "\n"))?;
        }
        println!("dsctl: PAM line removed, stock auth restored.");
    }
    disable_resume_unit();
    Ok(())
}

fn enable_resume_unit() -> Result<()> {
    if Path::new(RESUME_UNIT_SRC).exists() {
        std::fs::copy(RESUME_UNIT_SRC, RESUME_UNIT_DST).context("install resume unit")?;
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        let _ = Command::new("systemctl").args(["enable", "deathstroke-resume.service"]).status();
    }
    Ok(())
}
fn disable_resume_unit() {
    let _ = Command::new("systemctl").args(["disable", "deathstroke-resume.service"]).status();
    let _ = std::fs::remove_file(RESUME_UNIT_DST);
    let _ = Command::new("systemctl").arg("daemon-reload").status();
}
fn write_atomic(path: &str, data: &str) -> Result<()> {
    let tmp = format!("{path}.dstmp");
    std::fs::write(&tmp, data).with_context(|| format!("write {tmp}"))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {path}"))?;
    Ok(())
}

/// Prompt for a duress code (twice), derive a PBKDF2 verifier, write it to the state dir 0600. The
/// plaintext code is scrubbed from memory immediately after derivation (zeroize). Non-destructive.
fn set_duress() -> Result<()> {
    require_root()?;
    let code = read_secret("Duress code: ")?;
    let again = read_secret("Confirm duress code: ")?;
    if code != again { bail!("codes did not match"); }
    if code.len() < 6 { bail!("duress code too short (min 6 chars)"); }
    let h = derive_and_zero(code, DEFAULT_ITERATIONS)?;
    let path = ds_core::duress_hash_path();
    ensure_state_dir()?;
    write_0600(&path, h.serialize().as_bytes())?;
    println!("dsctl: duress verifier written to {path} (hash only; the code is not stored).");
    Ok(())
}

/// Verify a candidate code against the stored verifier (constant-time). For a self-check that the
/// enrolled code is what the user thinks — NEVER fires anything. Reads the code interactively unless
/// passed (passing on argv is only for scripted tests, discouraged in real use).
fn verify(arg: Option<&str>) -> Result<()> {
    let stored = std::fs::read_to_string(ds_core::duress_hash_path())
        .context("no duress verifier enrolled (run `dsctl set-duress`)")?;
    let h = DuressHash::parse(&stored)?;
    let cand = match arg {
        Some(s) => s.as_bytes().to_vec(),
        None => read_secret("Code to check: ")?,
    };
    let ok = h.verify(&cand)?;
    let mut cand = cand; cand.zeroize_now();
    if ok { println!("dsctl: MATCH — this code is the enrolled duress code."); }
    else   { println!("dsctl: no match."); }
    Ok(())
}

fn status() -> Result<()> {
    let enrolled = Path::new(&ds_core::duress_hash_path()).exists();
    let armed = std::fs::read_to_string(SYSTEM_AUTH).map(|c| c.contains(ARM_MARKER)).unwrap_or(false);
    let recov = std::fs::read_to_string(format!("{}/recovery.device", ds_core::state_dir())).ok();
    let marker = Path::new(DISPOSABLE_MARKER).exists();
    println!("status");
    println!("  duress code enrolled : {}", yesno(enrolled));
    println!("  armed (in auth path) : {}", yesno(armed));
    println!("  recovery keyslot     : {}", recov.as_deref().map(|d| format!("enrolled on {}", d.trim())).unwrap_or_else(|| "none".into()));
    println!("  environment          : {}", if marker { "disposable (destructive ops permitted)" } else { "not marked disposable (destructive ops refused)" });
    Ok(())
}

/// Destructive and system-altering operations run only on a machine marked disposable while they are
/// under development.
fn guard_disposable(op: &str) -> Result<()> {
    if !Path::new(DISPOSABLE_MARKER).exists() {
        bail!("SAFETY GUARD: `{op}` refused. This machine is not marked disposable ({DISPOSABLE_MARKER} absent).");
    }
    Ok(())
}

// ---- helpers (non-destructive) ----
fn require_root() -> Result<()> {
    // reads the euid without extra crates.
    let euid = std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:").map(|v| v.split_whitespace().nth(1).unwrap_or("1").to_string())))
        .unwrap_or_else(|| "1".into());
    if euid != "0" { bail!("must run as root (it manages the reserved state dir)"); }
    Ok(())
}
fn ensure_state_dir() -> Result<()> {
    std::fs::create_dir_all(ds_core::STATE_DIR).context("create state dir")?;
    let _ = std::process::Command::new("chmod").args(["700", ds_core::STATE_DIR]).status();
    Ok(())
}
fn write_0600(path: &str, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("write {path}"))?;
    let _ = std::process::Command::new("chmod").args(["600", path]).status();
    Ok(())
}
fn read_secret(prompt: &str) -> Result<Vec<u8>> {
    // reads a line without echo suppression for now; terminal no-echo (termios) is planned.
    // kept minimal and dependency-free.
    print!("{prompt}"); std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).context("read code")?;
    Ok(s.trim_end_matches(['\n', '\r']).as_bytes().to_vec())
}
fn yesno(b: bool) -> &'static str { if b { "yes" } else { "no" } }

// tiny helper so we can scrub a Vec without importing the trait everywhere.
trait ZeroizeNow { fn zeroize_now(&mut self); }
impl ZeroizeNow for Vec<u8> { fn zeroize_now(&mut self) { use zeroize::Zeroize; self.zeroize(); } }
