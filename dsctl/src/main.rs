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
        Some("factors")    => factors(),
        Some("enroll")     => enroll_factor(&args),
        Some("harden")     => harden(&args),
        Some("harden-check") => harden_check(),
        Some("arm")        => arm(),
        Some("disarm")     => disarm(),
        _ => { eprintln!("usage: dsctl set-duress | verify [code] | status | factors | enroll <fido2|tpm2|passphrase> --device <dev> [--pin] | enroll-recovery --device <dev> | arm | disarm"); std::process::exit(2); }
    }
}

// Where PAM finds the module and where the resume unit lives.
const PAM_MODULE: &str = "/usr/lib/security/pam_ds.so";
const SYSTEM_AUTH: &str = "/etc/pam.d/system-auth";
const ARM_MARKER: &str = "deathstr0ke-arm";
const RESUME_UNIT_SRC: &str = "/usr/lib/arxos/deathstroke/deathstroke-resume.service.disabled";
const RESUME_UNIT_DST: &str = "/etc/systemd/system/deathstroke-resume.service";

// ---- factor menu: detect hardware + enroll unlock factors via systemd-cryptenroll ----

/// Detect which unlock factors the machine supports, so the installer / Control Center only offers what
/// the hardware can do (DEATHSTROKE.md §12.1). Non-destructive, read-only.
fn factors() -> Result<()> {
    let tpm2 = Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists();
    // a FIDO2 hidraw device is the practical signal; systemd-cryptenroll needs libfido2 too.
    let fido2 = Command::new("sh").arg("-c")
        .arg("systemd-cryptenroll --fido2-device=list 2>/dev/null | grep -qiE '/dev|token' && echo y")
        .output().map(|o| o.stdout.starts_with(b"y")).unwrap_or(false);
    let cryptenroll = Path::new("/usr/bin/systemd-cryptenroll").exists();
    println!("supported unlock factors");
    println!("  passphrase     : yes  (always available; the knowledge fallback)");
    println!("  fido2/yubikey  : {}", yesno(fido2));
    println!("  tpm2           : {}", yesno(tpm2));
    println!("  duress code    : yes  (dsctl set-duress)");
    println!("  backup yubikey : {}  (enroll a second fido2 key; replaces a written recovery key)", yesno(fido2));
    println!();
    println!("  systemd-cryptenroll: {}", yesno(cryptenroll));
    println!("  policy (recommended): passphrase + yubikey + backup yubikey + duress code");
    if !fido2 { println!("  note: no FIDO2 token detected right now; plug the key in and re-run `dsctl factors`."); }
    Ok(())
}

/// Enroll one unlock factor into a LUKS device via systemd-cryptenroll. Each factor is an independent
/// keyslot, so factors coexist (add a YubiKey without removing the passphrase). Never removes the
/// passphrase slot -- the knowledge fallback must always remain, so the user can never be bricked.
fn enroll_factor(args: &[String]) -> Result<()> {
    require_root()?;
    guard_disposable("enroll")?;
    let device = flag(args, "--device").context("enroll needs --device <luks-dev>")?;
    let kind = args.get(1).map(String::as_str).unwrap_or("");
    let pin = args.iter().any(|a| a == "--pin");   // require a PIN alongside the factor (MFA)
    let simulate = args.iter().any(|a| a == "--simulate");

    // --simulate proves the KEYSLOT mechanics without USB hardware. A real FIDO2 token enrolls an
    // HMAC-derived secret as a LUKS keyslot; here we derive that secret in software (from a stored
    // per-device credential + salt) and enroll it as a keyfile keyslot, so the same "the token's secret
    // unlocks the disk" property is exercised end to end. It does NOT exercise the physical USB
    // handshake (that needs a real key, or the VM USB-HID sim). Only fido2 is simulated.
    if simulate {
        if kind != "fido2" { bail!("--simulate only applies to fido2"); }
        return enroll_fido2_simulated(&device, flag(args, "--existing-keyfile"));
    }

    // systemd-cryptenroll needs an existing passphrase to authorise adding a slot; it prompts for it.
    let mut ce = vec!["systemd-cryptenroll".to_string()];
    match kind {
        "fido2" => {
            ce.push("--fido2-device=auto".into());
            ce.push(format!("--fido2-with-client-pin={}", if pin { "yes" } else { "no" }));
        }
        "tpm2" => {
            ce.push("--tpm2-device=auto".into());
            // seal to measured-boot PCRs: firmware+secureboot (7), kernel/initramfs (4,8,9) -> the disk
            // unlocks only on our unmodified boot chain (DEATHSTROKE.md §12.2 A).
            ce.push("--tpm2-pcrs=0+2+4+7".into());
            if pin { ce.push("--tpm2-with-pin=yes".into()); }
        }
        "passphrase" => ce.push("--password".into()),
        _ => bail!("unknown factor '{kind}' (fido2 | tpm2 | passphrase)"),
    }
    ce.push(device.clone());
    println!("dsctl: enrolling {kind}{} on {device} (passphrase slot is kept)",
             if pin { " + PIN" } else { "" });
    let st = Command::new(&ce[0]).args(&ce[1..]).status().context("systemd-cryptenroll")?;
    if !st.success() { bail!("enroll {kind} failed"); }
    // record the factor as enabled (metadata only; no secret).
    let _ = std::fs::write(format!("{}/factor.{kind}", ds_core::state_dir()), "enrolled");
    println!("dsctl: {kind} enrolled. Keep the passphrase + a backup factor so you are never locked out.");
    Ok(())
}

/// Simulated FIDO2 enrollment: model the token as a per-device credential file (what a real token's
/// non-extractable secret stands in for here) and enroll the secret it "returns" as a LUKS keyslot via
/// `cryptsetup luksAddKey --key-file`. Proves that a token-derived secret becomes a working keyslot,
/// without any USB hardware. --existing-keyfile authorises the add non-interactively (for the self-test).
fn enroll_fido2_simulated(device: &str, existing_keyfile: Option<String>) -> Result<()> {
    let dir = ds_core::state_dir();
    // the "credential": a random 32-byte secret that a real token would hold non-extractably. We store
    // it here ONLY because this is a simulation; a real token never exposes it.
    let cred = format!("{dir}/fido2-sim.cred");
    if !Path::new(&cred).exists() {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).map_err(|e| anyhow::anyhow!("csprng: {e}"))?;
        std::fs::write(&cred, buf)?;
        let _ = Command::new("chmod").args(["600", &cred]).status();
    }
    // the secret the "token" returns for this device = the keyslot's key material.
    let keyfile = format!("{dir}/fido2-sim.key");
    std::fs::copy(&cred, &keyfile)?;
    let _ = Command::new("chmod").args(["600", &keyfile]).status();

    let mut a = vec!["luksAddKey".to_string(), device.to_string(), keyfile.clone()];
    if let Some(ek) = existing_keyfile { a.push("--key-file".into()); a.push(ek); }
    let st = Command::new("cryptsetup").args(&a).status().context("cryptsetup luksAddKey (sim)")?;
    if !st.success() { bail!("simulated fido2 luksAddKey failed"); }
    let _ = std::fs::write(format!("{dir}/factor.fido2"), "enrolled (simulated)");
    println!("dsctl: fido2 (SIMULATED) enrolled on {device}. The token secret now unlocks a keyslot.");
    println!("       (physical USB handshake unproven in sim; verify with a real key or the VM USB-HID sim.)");
    Ok(())
}

/// The configured erase/LUKS target device (written by enroll-recovery), if any.
fn configured_target() -> Option<String> {
    std::fs::read_to_string(format!("{}/target.device", ds_core::state_dir())).ok()
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

// ---- offline hardening: strong LUKS KDF + anti-forensic posture (DEATHSTROKE.md §12.2/§10.1) ----
//
// This is the layer that actually resists an OFFLINE attacker (who images the disk and never runs our
// initramfs/greeter, so the attempt-limit does not touch them). Two parts:
//   - crank the LUKS Argon2id KDF cost so brute-forcing the passphrase offline is expensive;
//   - set the kernel/swap posture so keys cannot be scavenged (init_on_free, no plaintext swap/hibernate).

/// Audit the offline-hardening posture (read-only, safe anywhere).
fn harden_check() -> Result<()> {
    println!("offline-hardening audit");
    // LUKS KDF of the configured target device (if any).
    if let Some(dev) = configured_target() {
        let dump = Command::new("cryptsetup").args(["luksDump", &dev]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let pbkdf = dump.lines().find(|l| l.trim_start().starts_with("PBKDF:")).map(|l| l.trim()).unwrap_or("PBKDF: ?");
        let mem = dump.lines().find(|l| l.trim_start().starts_with("Memory:")).map(|l| l.trim()).unwrap_or("Memory: ?");
        println!("  LUKS device       : {dev}");
        println!("  {pbkdf}  ({})", if pbkdf.contains("argon2id") { "argon2id: good" } else { "not argon2id: weak vs offline GPU" });
        println!("  {mem}");
    } else {
        println!("  LUKS device       : (none configured; run enroll-recovery first)");
    }
    // kernel key-scavenging posture. init_on_free zeroes freed memory so a LUKS key can't be scavenged
    // from the slab; it is a boot-param / CONFIG_INIT_ON_FREE_DEFAULT_ON setting (no writable sysfs).
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let iof = if cmdline.contains("init_on_free=1") { "on (cmdline): good" }
              else if cmdline.contains("init_on_free=0") { "OFF (cmdline): freed key memory not zeroed" }
              else { "not on cmdline (relies on CONFIG_INIT_ON_FREE_DEFAULT_ON; add init_on_free=1 to be sure)" };
    println!("  init_on_free      : {iof}");
    println!("  hibernation       : {}", if Path::new("/sys/power/disk").exists() && std::fs::read_to_string("/sys/power/disk").map(|s| s.contains("[disabled]")).unwrap_or(false) { "disabled: good" } else { "check: a swsusp image can leak the key unless swap is encrypted/off" });
    // swap: any active swap that is not on a dm-crypt device is a plaintext-key hole.
    let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    let plain_swap = swaps.lines().skip(1).any(|l| { let dev = l.split_whitespace().next().unwrap_or(""); !dev.is_empty() && !dev.contains("dm-") && !dev.contains("zram") });
    println!("  swap              : {}", if swaps.lines().count() <= 1 { "none active: good".into() } else if plain_swap { "PLAINTEXT swap active: keys can leak to disk".to_string() } else { "encrypted/zram only: good".into() });
    Ok(())
}

/// Apply the offline hardening: re-PBKDF the LUKS keyslots to a strong Argon2id cost, and write the
/// kernel/swap posture recommendations. Argon2 re-key is destructive-adjacent (rewrites keyslots), so
/// it is guarded to a disposable machine while under development.
fn harden(args: &[String]) -> Result<()> {
    require_root()?;
    guard_disposable("harden")?;
    let device = flag(args, "--device").or_else(configured_target)
        .context("harden needs --device <dev> or a configured target")?;
    // Argon2id cost: memory (KiB) + iterations. Defaults are strong-but-bootable; tune per hardware.
    let mem_kib = flag(args, "--argon-mem").unwrap_or_else(|| "1048576".into());   // 1 GiB
    let iter_ms = flag(args, "--argon-time").unwrap_or_else(|| "2000".into());     // 2s target
    println!("dsctl: raising LUKS KDF to argon2id (mem {mem_kib} KiB, ~{iter_ms} ms) on {device}");
    // cryptsetup luksConvertKey re-derives an existing keyslot with the new KDF. Needs the passphrase.
    let st = Command::new("cryptsetup")
        .args(["luksConvertKey", "--pbkdf", "argon2id", "--pbkdf-memory", &mem_kib,
               "--iter-time", &iter_ms, &device])
        .status().context("cryptsetup luksConvertKey")?;
    if !st.success() { bail!("luksConvertKey failed (wrong passphrase, or already at this KDF)"); }
    // record the recommended kernel posture for the installer/kernel config to enforce.
    let dir = ds_core::state_dir();
    let _ = std::fs::write(format!("{dir}/harden.recommend"),
        "kernel_cmdline: init_on_free=1 init_on_alloc=1 slab_nomerge lockdown=confidentiality\n\
         hibernation: disabled (or encrypted swap with a random per-boot key)\n\
         swap: none, zram, or dm-crypt only (never plaintext)\n");
    println!("dsctl: KDF hardened. Kernel/swap posture written to {dir}/harden.recommend (audit with `dsctl harden-check`).");
    Ok(())
}

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

    // A faillock-style 3-line stack so we can tell a wrong password (a real failure, seen only AFTER
    // pam_unix rejects it) from a right one:
    //   PREAUTH (first): enforce a lockout + detect the duress code. IGNORE lets the stack proceed;
    //                    a duress match / active lockout returns AUTH_ERR (default=die -> fail).
    //   AUTHFAIL (after pam_unix, failure path only): count the consecutive failure + escalate.
    //   AUTHSUCC (after a success): reset the counter.
    let preauth  = format!("auth      [success=ignore ignore=ignore default=die]     {PAM_MODULE}                # {ARM_MARKER}");
    let authfail = format!("auth      [default=die]                                  {PAM_MODULE}   authfail     # {ARM_MARKER}");
    let authsucc = format!("auth      sufficient                                     {PAM_MODULE}   authsucc     # {ARM_MARKER}");

    let mut v: Vec<String> = content.lines().map(String::from).collect();
    // preauth goes before the first auth line (runs first); authfail/authsucc go after the LAST auth
    // line (so they run after pam_unix has decided).
    let first_auth = v.iter().position(|l| l.trim_start().starts_with("auth"));
    let last_auth = v.iter().rposition(|l| l.trim_start().starts_with("auth"));
    match (first_auth, last_auth) {
        (Some(fa), Some(la)) => {
            v.insert(la + 1, authsucc);
            v.insert(la + 1, authfail);
            v.insert(fa, preauth);
        }
        _ => { v.insert(0, authsucc); v.insert(0, authfail); v.insert(0, preauth); }
    }
    write_atomic(SYSTEM_AUTH, &(v.join("\n") + "\n"))?;
    enable_resume_unit()?;
    println!("dsctl: armed. Duress code + attempt-limit are live at every PAM surface; boot-resume enabled.");
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
