// ds-unlock: the pre-boot LUKS unlock manager, run from the initramfs BEFORE the encrypted root is
// mounted (DEATHSTROKE.md §11.F pre-boot layer). It enforces the attempt-trigger policy at the boot
// passphrase, with a counter that PERSISTS across reboots on the unencrypted ESP (an attacker must not
// reset it by power-cycling).
//
// Per attempt, reading from an ESP directory (counter, duress.hash, config):
//   - the entered secret matches the enrolled duress verifier -> destroy the recorded daily slot.
//   - it opens the LUKS device (cryptsetup) -> RESET the counter, done (root can be mounted).
//   - it does neither (wrong) -> INCREMENT + fsync the counter; warn at lockout_at; at wipe_at,
//     destroy the recorded daily slot while preserving the separately verified recovery slot.
//
// The counter + duress verifier live on the ESP because the encrypted /var/lib is unavailable pre-boot.
// HONEST LIMIT (documented, not hidden): the ESP is plaintext, so an OFFLINE attacker who images the
// disk can reset the counter or delete the duress verifier. This layer defends a powered-off machine an
// adversary BOOTS and types at. TPM-sealed measured boot plus a signed boot chain can reduce the
// offline bypass, but its strength depends on the platform, PCR policy, and recovery factors.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

fn main() {
    let code = match run(std::env::args().skip(1).collect()) {
        Ok(c) => c,
        Err(e) => { eprintln!("ds-unlock: {e:#}"); 1 }
    };
    std::process::exit(code);
}

fn run(args: Vec<String>) -> Result<i32> {
    if args.iter().any(|a| a == "--self-test") { return self_test(); }
    let device = flag(&args, "--device").context("--device <luks-dev> required")?;
    let esp = PathBuf::from(flag(&args, "--esp-dir").unwrap_or_else(|| "/ds-esp/deathstroke".into()));
    let map = flag(&args, "--map-name").unwrap_or_else(|| "cryptroot".into());

    if !esp.is_dir() { bail!("armed ESP state directory missing: {}", esp.display()); }
    if !esp.join("armed").is_file() { bail!("armed ESP marker missing"); }
    // Tamper check: the writable ESP verifier/policy must match the copies frozen into the initramfs at
    // arm time. This fails closed if an attacker edited only the plaintext ESP (see verify_against_baked).
    verify_against_baked(&esp)?;
    let cfg = read_cfg(&esp)?;
    let duress = load_duress(&esp)?;
    let daily_slot = read_daily_slot(&esp)?;
    let recovery_slot = read_recovery_slot(&esp)?;
    if daily_slot == recovery_slot { bail!("daily.slot and recovery.slot must be distinct"); }

    // Resume an interrupted destructive transaction before accepting any credential.
    let journal = esp.join(ds_core::JOURNAL_NAME);
    if journal.exists() {
        return resume_wipe(&journal, &device, daily_slot, recovery_slot, &map);
    }

    // A count already at/over the wipe line (e.g. a prior boot hit the limit but power-cut before the
    // erase finished) means erase now, before offering any prompt.
    if read_count(&esp)? >= cfg.wipe_at {
        return do_wipe(&device, &esp, &map, daily_slot, recovery_slot);
    }

    for _ in 0..cfg.max_prompts {
        let mut secret = prompt_secret(&device)?;

        // 1. duress?
        if duress.verify(secret.as_bytes()).context("verify duress code")? {
            secret.zeroize();
            return do_wipe(&device, &esp, &map, daily_slot, recovery_slot);
        }
        // 2. correct passphrase? (cryptsetup opens it)
        let opened = luks_open(&device, &map, &secret)?;
        secret.zeroize();
        if opened {
            reset_count(&esp)?;                 // any success clears the counter
            println!("ds-unlock: unlocked.");
            return Ok(0);
        }
        // 3. wrong: increment (fsync) + escalate
        let n = bump_count(&esp)?;
        if n >= cfg.wipe_at {
            eprintln!("\nDEATHSTROKE: attempt limit reached. Destroying this system.");
            return do_wipe(&device, &esp, &map, daily_slot, recovery_slot);
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
fn read_count(esp: &Path) -> Result<u32> {
    let path = counter_path(esp);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read armed counter {}", path.display()))?;
    let mut fields = text.split_whitespace();
    let count = fields.next().context("armed counter is empty")?
        .parse().context("armed counter is invalid")?;
    if fields.next().is_some() { bail!("armed counter has trailing fields"); }
    Ok(count)
}
fn write_count(esp: &Path, n: u32) -> Result<()> {
    let p = counter_path(esp);
    ds_core::atomic_write(&p, format!("{n}\n").as_bytes(), 0o600)
        .with_context(|| format!("durably write {}", p.display()))
}
fn bump_count(esp: &Path) -> Result<u32> { let n = read_count(esp)?.saturating_add(1); write_count(esp, n)?; Ok(n) }
fn reset_count(esp: &Path) -> Result<()> { write_count(esp, 0) }

// ---- config + duress verifier from the ESP ----

fn read_cfg(esp: &Path) -> Result<ds_core::Policy> {
    let path = esp.join("config");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read armed policy {}", path.display()))?;
    ds_core::Policy::parse(&text).context("invalid armed policy")
}

/// Cross-check the writable ESP verifier + policy against the copies frozen into the initramfs at arm
/// time (`/etc/arxos/deathstroke/{duress.hash,config}.trusted`, baked by the mkinitcpio install hook).
/// The ESP is a plaintext FAT partition an offline attacker can edit; these baked references live in the
/// initramfs rootfs, so if the two disagree the ESP was tampered with and we FAIL CLOSED rather than
/// honour an attacker-supplied verifier/policy. Bypassing this requires modifying the initramfs itself
/// (closed by a signed UKI + Secure Boot). The reboot-persistent counter is deliberately NOT covered
/// here (it must stay writable); a TPM NV counter is the separate fix for counter rollback. If a baked
/// reference is absent (an initramfs armed before this change) the pair is skipped for backward
/// compatibility; a current `dsctl arm` always bakes both.
fn verify_against_baked(esp: &Path) -> Result<()> {
    let baked_dir = Path::new(ds_core::CONFIG_DIR);
    for (live, trusted) in [("duress.hash", "duress.hash.trusted"), ("config", "config.trusted")] {
        let bpath = baked_dir.join(trusted);
        if !bpath.is_file() { continue; } // no frozen reference (pre-change arm): nothing to compare
        let baked = std::fs::read_to_string(&bpath)
            .with_context(|| format!("read baked reference {}", bpath.display()))?;
        let onesp = std::fs::read_to_string(esp.join(live))
            .with_context(|| format!("read ESP {live}"))?;
        if baked.trim() != onesp.trim() {
            bail!("ESP {live} does not match the initramfs-baked reference: pre-boot state was tampered \
                   with. Refusing to unlock. Boot from recovery media and re-arm if this was intentional.");
        }
    }
    Ok(())
}
fn load_duress(esp: &Path) -> Result<ds_core::DuressHash> {
    let path = esp.join("duress.hash");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read armed verifier {}", path.display()))?;
    ds_core::DuressHash::parse(&text).context("invalid armed verifier")
}

// ---- cryptsetup ----

/// Try to open the LUKS device with the secret. Returns true on success (mapping created).
fn luks_open(device: &str, map: &str, secret: &str) -> Result<bool> {
    // feed the passphrase on stdin; --test-passphrase would not create the mapping, so use open.
    let mut child = Command::new("cryptsetup").args(["open", device, map])
        .stdin(std::process::Stdio::piped()).spawn().context("spawn cryptsetup open")?;
    if let Some(si) = child.stdin.as_mut() {
        si.write_all(secret.as_bytes()).context("write cryptsetup secret")?;
        si.write_all(b"\n").context("finish cryptsetup secret")?;
    }
    Ok(child.wait().context("wait for cryptsetup open")?.success())
}

fn do_wipe(device: &str, esp: &Path, map: &str, slot: u8, recovery_slot: u8) -> Result<i32> {
    // Destroy only the enrolled daily-passphrase slot. The separately verified recovery slot remains,
    // matching the product contract that the owner can recover with the offline recovery key.
    let erase = find_ds_erase();
    let mut command = Command::new(&erase);
    command.args([
        "--fire", "--device", device, "--mode", "killslot", "--slot", &slot.to_string(),
        "--recovery-slot", &recovery_slot.to_string(), "--journal",
    ])
        .arg(esp.join(ds_core::JOURNAL_NAME))
        .args(["--map-name", map])
        .args(["--header-scan"]).arg(esp);
    if ds_core::test_mode() { command.arg("--test-no-poweroff"); }
    let st = command.status();
    match st {
        Ok(s) if s.success() => { eprintln!("ds-unlock: protected daily-slot destruction complete."); Ok(2) }
        _ => bail!("daily-slot destruction failed"),
    }
}

fn resume_wipe(journal: &Path, device: &str, slot: u8, recovery_slot: u8, map: &str) -> Result<i32> {
    let erase = find_ds_erase();
    let st = Command::new(&erase)
        .arg("--resume").arg("--journal").arg(journal)
        .args([
            "--expected-device", device, "--expected-slot", &slot.to_string(),
            "--expected-recovery-slot", &recovery_slot.to_string(), "--map-name", map,
        ])
        .status();
    match st {
        Ok(s) if s.success() => Ok(2),
        _ => bail!("interrupted daily-slot transaction could not resume"),
    }
}
fn read_daily_slot(esp: &Path) -> Result<u8> {
    let text = std::fs::read_to_string(esp.join("daily.slot")).context("read daily.slot")?;
    let slot: u8 = text.trim().parse().context("invalid daily.slot")?;
    if slot > 31 { bail!("daily.slot outside 0..31"); }
    Ok(slot)
}
fn read_recovery_slot(esp: &Path) -> Result<u8> {
    let text = std::fs::read_to_string(esp.join("recovery.slot")).context("read recovery.slot")?;
    let slot: u8 = text.trim().parse().context("invalid recovery.slot")?;
    if slot > 31 { bail!("recovery.slot outside 0..31"); }
    Ok(slot)
}
fn find_ds_erase() -> String {
    for p in ["/usr/lib/arxos/deathstroke/ds-erase", "/usr/local/bin/ds-erase", "ds-erase"] {
        if Path::new(p).exists() { return p.into(); }
    }
    "ds-erase".into()
}

// ---- prompt ----

fn prompt_secret(device: &str) -> Result<String> {
    // Scripted secrets are test-only; production boot environments cannot inject a credential.
    if ds_core::test_mode() {
        if let Ok(s) = std::env::var("DS_SECRET") { return Ok(s); }
    }

    // When Plymouth is running (the normal boot), the graphical splash OWNS the console: a plain
    // eprint!/stdin read is drawn OVER and the user sees a splash with NO passphrase field and no
    // idea input is wanted (the boot looks hung). So ask Plymouth for the password — this triggers
    // the ArxOS theme's password_callback, rendering the branded "Enter passphrase to unlock ArxOS"
    // field with masked bullets, and returns what the user typed. This is what makes the prompt
    // VISIBLE. The lockout/wipe counter logic stays here in ds-unlock, one plymouth prompt per try.
    if plymouth_active() {
        let out = std::process::Command::new("plymouth")
            .args(["ask-for-password", "--prompt", "Enter passphrase to unlock ArxOS"])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                // plymouth writes the password to stdout with a trailing newline.
                let s = String::from_utf8_lossy(&o.stdout);
                return Ok(s.trim_end_matches(['\n', '\r']).to_string());
            }
        }
        // plymouth present but the ask failed: fall through to the plain console prompt below so a
        // passphrase can still be entered (never leave the user with no way in).
    }

    // Fallback (no plymouth, or ask-for-password failed): plain console prompt. Kept for the
    // no-splash path and for resilience.
    rpassword::prompt_password(format!("Enter passphrase for {device}: "))
        .context("read passphrase without terminal echo")
}

/// Is a Plymouth daemon running and answering? (`plymouth --ping` exits 0 only if plymouthd is up.)
fn plymouth_active() -> bool {
    std::process::Command::new("plymouth").arg("--ping").status()
        .map(|s| s.success()).unwrap_or(false)
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

    std::fs::write(esp.join("counter"), "0\n")?;
    std::fs::write(esp.join("armed"), "1\n")?;
    chk("counter starts at 0", read_count(&esp)? == 0);
    chk("bump -> 1", bump_count(&esp)? == 1);
    chk("bump -> 2", bump_count(&esp)? == 2);
    // simulate a REBOOT: a fresh process re-reads the same ESP file -> must still be 2, not reset.
    chk("persists across a 'reboot' (re-read)", read_count(&esp)? == 2);
    chk("bump -> 3 after reboot", bump_count(&esp)? == 3);
    reset_count(&esp)?;
    chk("reset -> 0", read_count(&esp)? == 0);
    // config parsing
    std::fs::write(esp.join("config"), "lockout_at = 3\nwipe_at = 5\nlockout_delay = 0\nmax_prompts = 5\n")?;
    let cfg = read_cfg(&esp)?;
    chk("config parsed (lockout_at=3, wipe_at=5)", cfg.lockout_at == 3 && cfg.wipe_at == 5);

    std::fs::write(esp.join("counter"), "garbage\n")?;
    chk("corrupt armed counter fails closed", read_count(&esp).is_err());
    std::fs::write(esp.join("config"), "lockout_at=0\nwipe_at=5\nmax_prompts=5\n")?;
    chk("invalid armed policy fails closed", read_cfg(&esp).is_err());

    println!("{}", if ok { "DS-UNLOCK-SELFTEST: ALL PASS" } else { "DS-UNLOCK-SELFTEST: FAILURES" });
    Ok(if ok { 0 } else { 1 })
}
