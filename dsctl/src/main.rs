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
        Some("enroll-recovery") => guarded("enroll-recovery",
            "add a LUKS recovery keyslot via `cryptsetup luksAddKey` on the encrypted root"),
        Some("arm")        => guarded("arm",
            "insert the pam_ds.so line into system-auth + enable the resume unit"),
        Some("disarm")     => guarded("disarm",
            "remove the pam_ds.so line + disable the resume unit"),
        _ => { eprintln!("usage: dsctl set-duress | verify [code] | status | enroll-recovery | arm | disarm"); std::process::exit(2); }
    }
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
    let marker = Path::new(DISPOSABLE_MARKER).exists();
    println!("status");
    println!("  duress code enrolled : {}", yesno(enrolled));
    println!("  armed (in auth path) : {}  (arming is in development)", yesno(false));
    println!("  recovery keyslot     : none  (enroll is in development)");
    println!("  environment          : {}", if marker { "disposable (destructive ops permitted)" } else { "not marked disposable (destructive ops refused)" });
    Ok(())
}

/// Destructive and system-altering operations run only on a machine marked disposable while they are
/// under development; otherwise they print what they would do.
fn guarded(op: &str, what: &str) -> Result<()> {
    require_root()?;
    if !Path::new(DISPOSABLE_MARKER).exists() {
        bail!("SAFETY GUARD: `{op}` would {what}. Refused: this machine is not marked disposable ({DISPOSABLE_MARKER} absent).");
    }
    println!("dsctl: [{op}] disposable marker present. Would: {what}.");
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
