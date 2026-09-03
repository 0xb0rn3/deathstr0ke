// ds-unlock: the pre-boot LUKS unlock manager, run from the initramfs BEFORE the encrypted root is
// mounted (DEATHSTROKE.md §11.F pre-boot layer). It enforces the 3-strikes-then-wipe policy at the boot
// passphrase, with a counter that PERSISTS across reboots on the unencrypted ESP (an attacker must not
// reset it by power-cycling).
//
// Per attempt, reading from an ESP directory (counter, duress.hash, config):
//   - the entered secret matches the enrolled duress verifier -> instant crypto-erase (ds-erase).
//   - it opens the LUKS device (cryptsetup) -> RESET the counter, done (root can be mounted).
//   - it does neither (wrong) -> INCREMENT + fsync the counter; warn at lockout_at; at wipe_at, erase.
//
// The counter + duress verifier live on the ESP because the encrypted /var/lib is unavailable pre-boot.
// HONEST LIMIT (documented, not hidden): the ESP is plaintext, so an OFFLINE attacker who images the
// disk can reset the counter or delete the duress verifier. This layer defends a powered-off machine an
// adversary BOOTS and types at; the offline-imaging bypass is closed only by TPM-sealed measured boot
// + a signed initramfs (DEATHSTROKE.md §12.2 A), which forces the adversary onto this path.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let code = match run(std::env::args().skip(1).collect()) {
        Ok(c) => c,
        Err(e) => { eprintln!("ds-unlock: {e:#}"); 1 }
    };
    std::process::exit(code);
}

struct Cfg { lockout_at: u32, wipe_at: u32, lockout_delay: u64, max_prompts: u32 }

fn run(args: Vec<String>) -> Result<i32> {
    if args.iter().any(|a| a == "--self-test") { return self_test(); }
    let device = flag(&args, "--device").context("--device <luks-dev> required")?;
    let esp = PathBuf::from(flag(&args, "--esp-dir").unwrap_or_else(|| "/ds-esp/deathstroke".into()));
    let map = flag(&args, "--map-name").unwrap_or_else(|| "cryptroot".into());

    std::fs::create_dir_all(&esp).ok();
    let cfg = read_cfg(&esp);
    let duress = load_duress(&esp);

    // A count already at/over the wipe line (e.g. a prior boot hit the limit but power-cut before the
    // erase finished) means erase now, before offering any prompt.
    if read_count(&esp) >= cfg.wipe_at { return do_wipe(&device, &esp, &map); }

    for _ in 0..cfg.max_prompts {
        let secret = prompt_secret(&device)?;

        // 1. duress?
        if let Some(v) = &duress {
            if v.verify(secret.as_bytes()).unwrap_or(false) {
                return do_wipe(&device, &esp, &map);
            }
        }
        // 2. correct passphrase? (cryptsetup opens it)
        if luks_open(&device, &map, &secret) {
            reset_count(&esp);                 // any success clears the counter
            println!("ds-unlock: unlocked.");
            return Ok(0);
        }
        // 3. wrong: increment (fsync) + escalate
        let n = bump_count(&esp)?;
        if n >= cfg.wipe_at {
            eprintln!("\nDEATHSTROKE: attempt limit reached. Destroying this system.");
            return do_wipe(&device, &esp, &map);
        } else if n >= cfg.lockout_at {
            eprintln!("\nDEATHSTROKE WARNING: too many failed attempts. Further failures will DESTROY this system.");
            if cfg.lockout_delay > 0 { std::thread::sleep(std::time::Duration::from_secs(cfg.lockout_delay)); }
        } else {
            eprintln!("No key available with this passphrase.");
        }
    }
    bail!("too many attempts")
}

// ---- counter on the ESP (FAT: plain file "count", fsync best-effort) ----

fn counter_path(esp: &Path) -> PathBuf { esp.join("counter") }
fn read_count(esp: &Path) -> u32 {
    std::fs::read_to_string(counter_path(esp)).ok()
        .and_then(|s| s.split_whitespace().next().and_then(|x| x.parse().ok())).unwrap_or(0)
}
fn write_count(esp: &Path, n: u32) -> Result<()> {
    let p = counter_path(esp);
    std::fs::write(&p, format!("{n}\n")).with_context(|| format!("write {}", p.display()))?;
    if let Ok(f) = std::fs::File::open(&p) { let _ = f.sync_all(); }   // survive a power cut
    // fsync the directory too so the FAT entry is durable
    if let Ok(d) = std::fs::File::open(esp) { let _ = d.sync_all(); }
    Ok(())
}
fn bump_count(esp: &Path) -> Result<u32> { let n = read_count(esp).saturating_add(1); write_count(esp, n)?; Ok(n) }
fn reset_count(esp: &Path) { let _ = std::fs::remove_file(counter_path(esp)); let _ = write_count(esp, 0); }

// ---- config + duress verifier from the ESP ----

fn read_cfg(esp: &Path) -> Cfg {
    let text = std::fs::read_to_string(esp.join("config")).unwrap_or_default();
    let get = |k: &str, d: u64| text.lines().find_map(|l| l.strip_prefix(k).and_then(|v| v.trim().trim_start_matches('=').trim().parse().ok())).unwrap_or(d);
    Cfg {
        lockout_at: get("lockout_at", ds_core::DEFAULT_LOCKOUT_AT as u64) as u32,
        wipe_at: get("wipe_at", ds_core::DEFAULT_WIPE_AT as u64) as u32,
        lockout_delay: get("lockout_delay", 0),
        max_prompts: get("max_prompts", 30) as u32,
    }
}
fn load_duress(esp: &Path) -> Option<ds_core::DuressHash> {
    std::fs::read_to_string(esp.join("duress.hash")).ok().and_then(|s| ds_core::DuressHash::parse(&s).ok())
}

// ---- cryptsetup ----

/// Try to open the LUKS device with the secret. Returns true on success (mapping created).
fn luks_open(device: &str, map: &str, secret: &str) -> bool {
    // feed the passphrase on stdin; --test-passphrase would not create the mapping, so use open.
    let mut child = match Command::new("cryptsetup").args(["open", device, map])
        .stdin(std::process::Stdio::piped()).spawn() { Ok(c) => c, Err(_) => return false };
    if let Some(si) = child.stdin.as_mut() { let _ = si.write_all(secret.as_bytes()); let _ = si.write_all(b"\n"); }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn do_wipe(device: &str, esp: &Path, _map: &str) -> Result<i32> {
    // hand off to ds-erase (journal + header-backup destruction + luksErase). Its own guard applies.
    // ESP dir is passed as the journal location so the resume flag lands where the boot hook reads it.
    let erase = find_ds_erase();
    let st = Command::new(&erase)
        .args(["--fire", "--device", device, "--mode", "erase", "--journal"])
        .arg(esp.join("inprogress"))
        .args(["--header-scan"]).arg(esp)
        .status();
    match st {
        Ok(s) if s.success() => { eprintln!("ds-unlock: crypto-erase complete."); Ok(2) }
        _ => bail!("crypto-erase failed"),
    }
}
fn find_ds_erase() -> String {
    for p in ["/usr/lib/arxos/deathstroke/ds-erase", "/usr/local/bin/ds-erase", "ds-erase"] {
        if Path::new(p).exists() { return p.into(); }
    }
    "ds-erase".into()
}

// ---- prompt ----

fn prompt_secret(device: &str) -> Result<String> {
    // if a scripted secret is supplied (tests), use it; else read a line from the console (no echo is a
    // TODO for the real hook via /dev/tty termios; initramfs prompts are typically plain).
    if let Ok(s) = std::env::var("DS_SECRET") { return Ok(s); }
    eprint!("Enter passphrase for {device}: ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).context("read passphrase")?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

// ---- self-test: counter persistence + escalation logic, no LUKS needed ----

fn self_test() -> Result<i32> {
    let dir = format!("/tmp/ds-unlock-selftest.{}", std::process::id());
    let esp = PathBuf::from(&dir); std::fs::create_dir_all(&esp)?;
    struct C(String); impl Drop for C { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    let _c = C(dir.clone());
    let mut ok = true;
    let mut chk = |label: &str, cond: bool| { println!("  {}  {label}", if cond { "PASS" } else { ok = false; "FAIL" }); };

    chk("counter starts at 0", read_count(&esp) == 0);
    chk("bump -> 1", bump_count(&esp)? == 1);
    chk("bump -> 2", bump_count(&esp)? == 2);
    // simulate a REBOOT: a fresh process re-reads the same ESP file -> must still be 2, not reset.
    chk("persists across a 'reboot' (re-read)", read_count(&esp) == 2);
    chk("bump -> 3 after reboot", bump_count(&esp)? == 3);
    reset_count(&esp);
    chk("reset -> 0", read_count(&esp) == 0);
    // config parsing
    std::fs::write(esp.join("config"), "lockout_at = 3\nwipe_at = 5\nlockout_delay = 0\n")?;
    let cfg = read_cfg(&esp);
    chk("config parsed (lockout_at=3, wipe_at=5)", cfg.lockout_at == 3 && cfg.wipe_at == 5);

    println!("{}", if ok { "DS-UNLOCK-SELFTEST: ALL PASS" } else { "DS-UNLOCK-SELFTEST: FAILURES" });
    Ok(if ok { 0 } else { 1 })
}
