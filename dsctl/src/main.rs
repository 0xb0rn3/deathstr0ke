// dsctl: the setup and control CLI. The non-destructive parts (set the duress code as a hash, verify
// a candidate, show status) are real and testable anywhere. The destructive and system-altering parts
// (enroll a LUKS recovery keyslot, integrate PAM, and rebuild the armed initramfs) only run
// on a machine marked disposable while they are under development. dsctl never stores the duress code,
// only its PBKDF2 hash. It reads and writes only the state dir; arming shells to stock cryptsetup and
// edits /etc/pam.d.

use anyhow::{bail, Context, Result};
use ds_core::{derive_and_zero, DuressHash, DEFAULT_ITERATIONS};
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Value of a `--name value` flag, if present.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("dsctl: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("set-duress") => set_duress(&args),
        Some("verify")     => verify(args.get(1).map(String::as_str)),
        Some("status")     => status(),
        Some("enroll-recovery") => enroll_recovery(&args),
        Some("factors")    => factors(),
        Some("enroll")     => enroll_factor(&args),
        Some("harden")     => harden(&args),
        Some("harden-check") => harden_check(),
        Some("seal-tpm")   => seal_tpm(&args),
        Some("tpm-check")  => tpm_check(),
        Some("deadman")    => deadman(&args),
        Some("checkin")    => checkin(),
        Some("deadman-check") => { return deadman_check().map(|c| std::process::exit(c)); }
        Some("arm")        => arm(),
        Some("disarm")     => disarm(),
        Some("panic")      => panic_wipe(),
        _ => { eprintln!("usage: dsctl set-duress | verify [code] | status | factors | enroll <fido2|tpm2|passphrase> --device <dev> [--pin] | enroll-recovery --device <dev> | arm | disarm | panic"); std::process::exit(2); }
    }
}

// Where PAM finds the module. Boot resume is handled inside the initramfs, where the ESP exists
// before root unlock; the old pre-cryptsetup systemd unit incorrectly pointed into encrypted /var.
const PAM_MODULE: &str = "/usr/lib/security/pam_ds.so";
const SYSTEM_AUTH: &str = "/etc/pam.d/system-auth";
const ARM_MARKER: &str = "deathstr0ke-arm";

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
    // record the slot this factor adds so `arm` recognizes it as intended (not a backdoor slot).
    record_added_slots(&device, || {
        let st = Command::new(&ce[0]).args(&ce[1..]).status().context("systemd-cryptenroll")?;
        if !st.success() { bail!("enroll {kind} failed"); }
        Ok(())
    })?;
    // record the factor as enabled (metadata only; no secret).
    ensure_state_dir()?;
    ds_core::atomic_write(&Path::new(&ds_core::state_dir()).join(format!("factor.{kind}")), b"enrolled\n", 0o600)?;
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
        ds_core::atomic_write(Path::new(&cred), &buf, 0o600)?;
    }
    // the secret the "token" returns for this device = the keyslot's key material.
    let keyfile = format!("{dir}/fido2-sim.key");
    let credential = std::fs::read(&cred)?;
    ds_core::atomic_write(Path::new(&keyfile), &credential, 0o600)?;

    let mut a = vec!["luksAddKey".to_string(), device.to_string(), keyfile.clone()];
    if let Some(ek) = existing_keyfile { a.push("--key-file".into()); a.push(ek); }
    // record the slot this simulated factor adds so `arm` recognizes it as intended.
    record_added_slots(device, || {
        let st = Command::new("cryptsetup").args(&a).status().context("cryptsetup luksAddKey (sim)")?;
        if !st.success() { bail!("simulated fido2 luksAddKey failed"); }
        Ok(())
    })?;
    ds_core::atomic_write(Path::new(&format!("{dir}/factor.fido2")), b"enrolled (simulated)\n", 0o600)?;
    println!("dsctl: fido2 (SIMULATED) enrolled on {device}. The token secret now unlocks a keyslot.");
    println!("       (physical USB handshake unproven in sim; verify with a real key or the VM USB-HID sim.)");
    Ok(())
}

// ---- TPM measured-boot seal (DEATHSTROKE.md §12.6) — the patch that makes everything real ----
//
// Seals a LUKS keyslot to the TPM bound to boot-chain PCRs, so the disk unlocks ONLY on our unmodified
// boot. This forces an offline/foreign-boot adversary back onto our attempt-limited path (they cannot
// boot a foreign kernel to skip the counter or edit the ESP without changing the PCRs and losing the
// key). A PIN is required so mere possession of the powered-off machine does not unlock it. A non-TPM
// factor (passphrase + backup FIDO2) is always kept so a TPM clear / mainboard swap never bricks the user.

/// Read-only audit of TPM readiness + whether a TPM keyslot is enrolled.
fn tpm_check() -> Result<()> {
    let have_tpm = Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists();
    println!("TPM measured-boot readiness");
    println!("  tpm device        : {}", yesno(have_tpm));
    println!("  cryptenroll       : {}", yesno(Path::new("/usr/bin/systemd-cryptenroll").exists()));
    // secure boot state (PCR 7 is only meaningful with Secure Boot on).
    let sb = std::fs::read_dir("/sys/firmware/efi/efivars").ok()
        .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with("SecureBoot-")))
        .unwrap_or(false);
    println!("  efi/secure-boot   : {}", if sb { "efivars present (check SB enabled for PCR7 to bind firmware trust)" } else { "no efivars (BIOS/CSM boot: PCR7 weak)" });
    if let Some(dev) = configured_target() {
        let dump = Command::new("cryptsetup").args(["luksDump", &dev]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let tpm = dump.contains("systemd-tpm2");
        println!("  tpm keyslot on {dev}: {}", if tpm { "ENROLLED (measured-boot seal present)" } else { "not enrolled (run dsctl seal-tpm --device ...)" });
    }
    if !have_tpm { println!("  note: no TPM here; seal on a TPM-capable machine/VM. This is why the seal is a REQUIREMENT (DEATHSTROKE.md §12.6)."); }
    Ok(())
}

/// Seal a LUKS keyslot to the TPM (measured boot). Keeps the passphrase slot. Guarded to a disposable
/// machine while under development (it changes how the disk unlocks at boot).
fn seal_tpm(args: &[String]) -> Result<()> {
    require_root()?;
    guard_disposable("seal-tpm")?;
    if !(Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()) {
        bail!("no TPM device (/dev/tpm*). Seal on a TPM-capable machine/VM.");
    }
    let device = flag(args, "--device").or_else(configured_target)
        .context("seal-tpm needs --device <dev> or a configured target")?;
    // PCRs: 0 firmware, 2 option ROMs, 4 boot loader+kernel, 7 secure-boot state. Bind to our exact boot.
    let pcrs = flag(args, "--pcrs").unwrap_or_else(|| "0+2+4+7".into());
    let with_pin = !args.iter().any(|a| a == "--no-pin");   // PIN on by default (possession alone must not unlock)
    let mut ce = vec!["systemd-cryptenroll".to_string(), "--tpm2-device=auto".into(),
                      format!("--tpm2-pcrs={pcrs}")];
    ce.push(format!("--tpm2-with-pin={}", if with_pin { "yes" } else { "no" }));
    // signed-policy form (optional): survives kernel/initramfs updates without re-enrolling.
    if let Some(pk) = flag(args, "--public-key") { ce.push(format!("--tpm2-public-key={pk}")); }
    ce.push(device.clone());
    println!("dsctl: sealing a keyslot to the TPM on {device} (PCRs {pcrs}{})", if with_pin { ", PIN" } else { "" });
    // record the TPM keyslot so `arm` recognizes it as intended (not a backdoor slot).
    record_added_slots(&device, || {
        let st = Command::new(&ce[0]).args(&ce[1..]).status().context("systemd-cryptenroll tpm2")?;
        if !st.success() { bail!("tpm2 seal failed"); }
        Ok(())
    })?;
    ensure_state_dir()?;
    ds_core::atomic_write(&Path::new(&ds_core::state_dir()).join("factor.tpm2"), format!("sealed pcrs={pcrs}\n").as_bytes(), 0o600)?;
    println!("dsctl: TPM measured-boot seal enrolled. The disk now unlocks only on this unmodified boot chain.");
    println!("       Keep the passphrase + a backup factor: a TPM clear or mainboard change needs them.");
    Ok(())
}

// ---- dead-man switch: destroy the daily slot if the user misses a check-in window (§12.2 C) ----
//
// Defends the "seize it, isolate it, analyze it at leisure" case: if the machine is not re-authed /
// checked in by a deadline, it fires the recovery-safe actor. State is a last-checkin timestamp + a window; a boot-time and
// periodic check compares now-vs-deadline and destroys the recorded daily slot if overdue. `checkin` (run on any
// successful login, or by the user) resets the clock.

fn deadman_state() -> String { format!("{}/deadman", ds_core::state_dir()) }

/// Configure/enable/disable the dead-man switch. `deadman <hours>` sets the window and checks in now;
/// `deadman off` disables it. Non-destructive (writes state only).
fn deadman(args: &[String]) -> Result<()> {
    require_root()?;
    match args.get(1).map(String::as_str) {
        Some("off") | Some("disable") => {
            remove_if_exists(Path::new(&deadman_state()))?;
            println!("dsctl: dead-man switch disabled.");
        }
        Some(h) => {
            let hours: u64 = h.parse().context("deadman <hours> | off")?;
            if hours == 0 { bail!("window must be > 0 hours"); }
            ensure_state_dir()?;
            ds_core::atomic_write(Path::new(&deadman_state()), format!("window_secs={}\nlast_checkin={}\n", hours * 3600, now_unix()).as_bytes(), 0o600)?;
            println!("dsctl: dead-man switch armed. Check in at least every {hours}h (dsctl checkin), or it destroys the daily slot.");
        }
        None => {
            // report status
            match read_deadman() {
                Some((win, last)) => {
                    let due = last + win;
                    let remain = due.saturating_sub(now_unix());
                    println!("dead-man switch: ARMED, window {}h, {}h {}m until daily-slot destruction (checkin to reset)",
                             win / 3600, remain / 3600, (remain % 3600) / 60);
                }
                None => println!("dead-man switch: disabled"),
            }
        }
    }
    Ok(())
}

/// Reset the dead-man clock (run on any successful login, or manually). Silent no-op if not armed.
fn checkin() -> Result<()> {
    require_root()?;
    if let Some((win, _)) = read_deadman() {
        ds_core::atomic_write(Path::new(&deadman_state()), format!("window_secs={win}\nlast_checkin={}\n", now_unix()).as_bytes(), 0o600)?;
        println!("dsctl: checked in. Dead-man clock reset.");
    }
    Ok(())
}

/// The periodic/boot check: if armed AND overdue, fire daily-slot destruction. Called by a timer + at boot.
/// (Exposed as a hidden verb so the packaged timer can call `dsctl deadman-check`.)
fn deadman_check() -> Result<i32> {
    match read_deadman() {
        Some((win, last)) if now_unix() > last + win => {
            eprintln!("DEATHSTROKE: dead-man switch expired (no check-in). Destroying the recorded daily slot.");
            let dev = configured_target().context("no target device configured")?;
            let erase = ["/usr/lib/arxos/deathstroke/ds-erase", "/usr/local/bin/ds-erase", "ds-erase"]
                .iter().find(|p| Path::new(p).exists()).unwrap_or(&"ds-erase").to_string();
            // The product trigger is recovery-safe: ds-erase resolves the recorded daily.slot and
            // preserves recovery.slot. Full LUKS erase requires a separate explicit operator flag.
            let st = Command::new(erase).args(["--fire", "--device", &dev]).status();
            Ok(if st.map(|s| s.success()).unwrap_or(false) { 2 } else { 1 })
        }
        _ => Ok(0),   // not armed or not overdue
    }
}

fn read_deadman() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string(deadman_state()).ok()?;
    let g = |k: &str| s.lines().find_map(|l| l.strip_prefix(k).and_then(|v| v.trim().trim_start_matches('=').trim().parse().ok()));
    Some((g("window_secs")?, g("last_checkin")?))
}
fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The configured erase/LUKS target device (written by enroll-recovery), if any.
fn configured_target() -> Option<String> {
    std::fs::read_to_string(format!("{}/target.device", ds_core::state_dir())).ok()
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn validate_luks_device(device: &str) -> Result<()> {
    if device.is_empty() || device.len() > 4096 || device.contains(['\n', '\r', '\0']) {
        bail!("invalid LUKS device path");
    }
    let resolved = std::fs::canonicalize(device).with_context(|| format!("resolve {device}"))?;
    if !resolved.starts_with("/dev/") { bail!("LUKS device must resolve below /dev"); }
    if !std::fs::metadata(&resolved)?.file_type().is_block_device() {
        bail!("LUKS target is not a block device: {}", resolved.display());
    }
    let status = Command::new("cryptsetup").args(["isLuks", device]).status().context("cryptsetup isLuks")?;
    if !status.success() { bail!("target is not a valid LUKS container: {device}"); }
    Ok(())
}

fn active_keyslots(device: &str) -> Result<BTreeSet<u8>> {
    let out = Command::new("cryptsetup").args(["luksDump", device]).output().context("cryptsetup luksDump")?;
    if !out.status.success() { bail!("luksDump failed on {device}"); }
    let mut slots = BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let trimmed = line.trim_start();
        // LUKS2: keyslots are listed as "<n>: luks2".
        if let Some((number, kind)) = trimmed.split_once(':') {
            if kind.trim_start().starts_with("luks2") {
                if let Ok(slot) = number.trim().parse::<u8>() { slots.insert(slot); }
                continue;
            }
        }
        // LUKS1: keyslots are listed as "Key Slot <n>: ENABLED" (installers still produce LUKS1,
        // e.g. Calamares' default). A DEATHSTROKE toolkit must not fail to arm a valid LUKS1 disk.
        if let Some(rest) = trimmed.strip_prefix("Key Slot ") {
            if let Some((number, state)) = rest.split_once(':') {
                if state.trim().eq_ignore_ascii_case("ENABLED") {
                    if let Ok(slot) = number.trim().parse::<u8>() { slots.insert(slot); }
                }
            }
        }
    }
    if slots.is_empty() { bail!("LUKS container has no active keyslots"); }
    Ok(slots)
}

fn matching_keyslots(device: &str, keyfile: &str) -> Result<Vec<u8>> {
    if !Path::new(keyfile).is_file() { bail!("keyfile does not exist: {keyfile}"); }
    let mut matches = Vec::new();
    for slot in active_keyslots(device)? {
        let status = Command::new("cryptsetup")
            .args(["open", "--test-passphrase", "--key-file", keyfile, "--key-slot", &slot.to_string(), device])
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .status().context("cryptsetup slot verification")?;
        if status.success() { matches.push(slot); }
    }
    Ok(matches)
}

// ---- known-keyslot registry (arm-time backdoor-slot defense) ----
//
// The recovery-preserving trigger destroys ONLY the recorded daily.slot; every other active keyslot
// survives. So an UNRECORDED active keyslot (one a coercer/evil-maid pre-enrolled, or a botched install
// left) would remain a working decryption path after a duress wipe. To close that, dsctl records every
// keyslot it enrolls in `known.slots`, and `arm` refuses if the device carries any active slot that is
// not recorded. This is a fail-closed audit, not destruction: it makes an unaudited slot BLOCK arming
// rather than silently ride along.
fn known_slots_path() -> PathBuf { PathBuf::from(ds_core::state_dir()).join("known.slots") }

fn read_known_slots() -> BTreeSet<u8> {
    let mut s = BTreeSet::new();
    if let Ok(c) = std::fs::read_to_string(known_slots_path()) {
        for tok in c.split(|ch: char| ch == ',' || ch.is_whitespace()) {
            if let Ok(n) = tok.trim().parse::<u8>() { s.insert(n); }
        }
    }
    s
}

fn write_known_slots(slots: &BTreeSet<u8>) -> Result<()> {
    ensure_state_dir()?;
    let body = slots.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    ds_core::atomic_write(&known_slots_path(), format!("{body}\n").as_bytes(), 0o600)
}

/// Add newly-enrolled slots to the registry (union). Best-effort: a registry-write failure must not
/// leave a slot silently unrecorded, so callers surface the error.
fn add_known_slots(new: &BTreeSet<u8>) -> Result<()> {
    if new.is_empty() { return Ok(()); }
    let mut s = read_known_slots();
    s.extend(new.iter().copied());
    write_known_slots(&s)
}

/// Run `op` (which enrolls a keyslot on `device`) and record whatever slot(s) it added into the
/// registry, so a later `arm` recognizes them as intended rather than treating them as backdoor slots.
fn record_added_slots<F: FnOnce() -> Result<()>>(device: &str, op: F) -> Result<()> {
    let before = active_keyslots(device).unwrap_or_default();
    op()?;
    if let Ok(after) = active_keyslots(device) {
        let added: BTreeSet<u8> = after.difference(&before).copied().collect();
        add_known_slots(&added)?;
    }
    Ok(())
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
    ds_core::atomic_write(Path::new(&format!("{dir}/harden.recommend")),
        "kernel_cmdline: init_on_free=1 init_on_alloc=1 slab_nomerge lockdown=confidentiality\n\
         hibernation: disabled (or encrypted swap with a random per-boot key)\n\
         swap: none, zram, or dm-crypt only (never plaintext)\n".as_bytes(), 0o600)?;
    println!("dsctl: KDF hardened. Kernel/swap posture written to {dir}/harden.recommend (audit with `dsctl harden-check`).");
    Ok(())
}

/// Add a LUKS recovery keyslot so the user can always get back in after a keyslot destruction. Needs
/// an existing passphrase to authorise the add (cryptsetup requirement). Destructive-adjacent, so it
/// runs only where marked disposable while under development.
fn enroll_recovery(args: &[String]) -> Result<()> {
    require_root()?;
    guard_disposable("enroll-recovery")?;
    if Path::new(ds_core::ARMED_MARKER).exists() { bail!("disarm before changing recovery slots"); }
    let device = flag(args, "--device").context("enroll-recovery needs --device <luks-dev>")?;
    // key-files keep the test non-interactive: --existing-keyfile authorises, --new-keyfile is enrolled.
    let existing = flag(args, "--existing-keyfile").context("need --existing-keyfile <path>")?;
    let newkey = flag(args, "--new-keyfile").context("need --new-keyfile <path>")?;
    validate_luks_device(&device)?;
    let daily_matches = matching_keyslots(&device, &existing)?;
    if daily_matches.len() != 1 {
        bail!("existing daily credential must match exactly one active slot; matched {daily_matches:?}");
    }
    let before = active_keyslots(&device)?;
    let st = Command::new("cryptsetup")
        .args(["luksAddKey", &device, &newkey, "--key-file", &existing])
        .status().context("cryptsetup luksAddKey")?;
    if !st.success() { bail!("luksAddKey failed on {device}"); }
    let after = active_keyslots(&device)?;
    let added: Vec<u8> = after.difference(&before).copied().collect();
    if added.len() != 1 {
        bail!("recovery enrollment did not add exactly one identifiable slot; added {added:?}");
    }
    let recovery_matches = matching_keyslots(&device, &newkey)?;
    if recovery_matches != added {
        bail!("new recovery credential did not verify only against the added slot");
    }
    ensure_state_dir()?;
    let dir = PathBuf::from(ds_core::state_dir());
    ds_core::atomic_write(&dir.join("recovery.device"), format!("{device}\n").as_bytes(), 0o600)?;
    ds_core::atomic_write(&dir.join("target.device"), format!("{device}\n").as_bytes(), 0o600)?;
    ds_core::atomic_write(&dir.join("daily.slot"), format!("{}\n", daily_matches[0]).as_bytes(), 0o600)?;
    ds_core::atomic_write(&dir.join("recovery.slot"), format!("{}\n", added[0]).as_bytes(), 0o600)?;
    // Baseline the known-slot registry to exactly {daily, recovery}. enroll-recovery is the foundational
    // step, so this establishes the audited set; later factor enrollments add to it, and `arm` refuses any
    // active slot not in it. `after` is the full active set right now, so anything beyond daily+recovery is
    // a pre-existing extra slot the operator must resolve before arming (we do NOT silently trust it).
    let mut baseline = BTreeSet::new();
    baseline.insert(daily_matches[0]);
    baseline.insert(added[0]);
    write_known_slots(&baseline)?;
    let extras: Vec<u8> = after.difference(&baseline).copied().collect();
    if !extras.is_empty() {
        println!("dsctl: NOTE: {extras:?} are active but not daily/recovery; `arm` will refuse until you \
                  remove them (cryptsetup luksKillSlot) or enroll intended factors via dsctl.");
    }
    println!("dsctl: recovery slot {} verified on {device}; protected daily slot {} recorded.", added[0], daily_matches[0]);
    Ok(())
}

/// Arm only after the recovery/daily slots, verifier, policy, ESP mirror, PAM stack, and rebuilt
/// initramfs can all be proven. Any failure restores the original PAM file and removes armed markers.
fn arm() -> Result<()> {
    require_root()?;
    guard_disposable("arm")?;
    if !Path::new(PAM_MODULE).exists() { bail!("{PAM_MODULE} not deployed"); }
    let verifier = std::fs::read_to_string(ds_core::duress_hash_path()).context("read duress verifier")?;
    DuressHash::parse(&verifier).context("invalid duress verifier")?;
    let policy = read_policy()?;
    policy.validate()?;
    let target = configured_target().context("no verified recovery target; run enroll-recovery")?;
    validate_luks_device(&target)?;
    let daily_slot = read_slot("daily.slot")?;
    let recovery_slot = read_slot("recovery.slot")?;
    if daily_slot == recovery_slot { bail!("daily and recovery slots must differ"); }
    let slots = active_keyslots(&target)?;
    if !slots.contains(&daily_slot) || !slots.contains(&recovery_slot) {
        bail!("recorded daily/recovery slots are not both active");
    }
    // Backdoor-slot defense: the duress trigger destroys ONLY the daily slot and keeps recovery, so any
    // OTHER active keyslot would survive a wipe as a decryption path. Refuse to arm unless every active
    // slot was recorded by dsctl (enroll-recovery baselines daily+recovery; factor enrollments add
    // theirs). An unrecorded active slot => stop, so a pre-enrolled/leftover slot cannot ride along.
    let mut known = read_known_slots();
    if !known.contains(&daily_slot) || !known.contains(&recovery_slot) {
        // registry missing or inconsistent (e.g. armed by an older dsctl): rebuild the baseline we can
        // vouch for from the recorded slots, then enforce against it.
        known.insert(daily_slot);
        known.insert(recovery_slot);
        write_known_slots(&known)?;
    }
    let unknown: Vec<u8> = slots.difference(&known).copied().collect();
    if !unknown.is_empty() {
        bail!("refusing to arm: keyslot(s) {unknown:?} on {target} are active but NOT recorded by dsctl. \
               A duress/dead-man wipe destroys only the daily slot, so an unrecorded slot would survive as \
               a decryption path. Inspect with `cryptsetup luksDump {target}`; remove an unwanted slot with \
               `cryptsetup luksKillSlot {target} <n>`, or re-enroll an intended factor via `dsctl enroll` so \
               it is recorded, then arm again.");
    }
    let content = std::fs::read_to_string(SYSTEM_AUTH).with_context(|| format!("read {SYSTEM_AUTH}"))?;
    let local_marker = Path::new(ds_core::ARMED_MARKER).is_file();
    let esp_marker = Path::new(ds_core::ESP_STATE_DIR).join("armed").is_file();
    if content.contains(ARM_MARKER) {
        if local_marker && esp_marker {
            println!("dsctl: already armed and markers are consistent.");
            return Ok(());
        }
        bail!("PAM is marked armed but initramfs/ESP authorization markers are inconsistent; disarm from recovery media");
    }
    if local_marker || esp_marker {
        bail!("authorization marker exists while PAM is unarmed; reconcile with dsctl disarm before arming");
    }
    let updated = arm_pam_stack(&content)?;
    let backup = format!("{SYSTEM_AUTH}.deathstr0ke.bak");
    let mode = std::fs::metadata(SYSTEM_AUTH)?.permissions().mode() & 0o7777;
    ds_core::atomic_write(Path::new(&backup), content.as_bytes(), mode)?;
    let mkinit_path = Path::new("/etc/mkinitcpio.conf");
    let mkinit_original = std::fs::read(mkinit_path).context("snapshot mkinitcpio.conf")?;
    let esp_paths = ["duress.hash", "config", "counter", "daily.slot", "recovery.slot", "armed"]
        .map(|name| Path::new(ds_core::ESP_STATE_DIR).join(name));
    let mut esp_snapshot: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    for path in esp_paths {
        let old = match std::fs::read(&path) {
            Ok(data) => Some(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("snapshot {}", path.display())),
        };
        esp_snapshot.push((path, old));
    }

    let result = (|| -> Result<()> {
        sync_esp_state(&verifier, policy, daily_slot, recovery_slot)?;
        ds_core::atomic_write(Path::new(ds_core::ARMED_MARKER), b"armed=1\n", 0o600)?;
        ensure_deathstroke_hook_before_encrypt()?;
        run_checked("mkinitcpio", &["-P"])?;
        ds_core::atomic_write(&Path::new(ds_core::ESP_STATE_DIR).join("armed"), b"armed=1\n", 0o600)?;
        // PAM is the last commit point: until all pre-boot artifacts are proven, login remains inert.
        ds_core::atomic_write(Path::new(SYSTEM_AUTH), updated.as_bytes(), mode)?;
        Ok(())
    })();
    if let Err(e) = result {
        let mut rollback_errors = Vec::new();
        if let Err(err) = ds_core::atomic_write(Path::new(SYSTEM_AUTH), content.as_bytes(), mode) {
            rollback_errors.push(format!("restore PAM: {err:#}"));
        }
        let mkinit_mode = std::fs::metadata(mkinit_path).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0o644);
        if let Err(err) = ds_core::atomic_write(mkinit_path, &mkinit_original, mkinit_mode) {
            rollback_errors.push(format!("restore mkinitcpio.conf: {err:#}"));
        }
        if let Err(err) = remove_if_exists(Path::new(ds_core::ARMED_MARKER)) {
            rollback_errors.push(format!("remove local armed marker: {err:#}"));
        }
        for (path, old) in esp_snapshot {
            let restored = if let Some(data) = old {
                ds_core::atomic_write(&path, &data, 0o600)
            } else {
                remove_if_exists(&path)
            };
            if let Err(err) = restored {
                rollback_errors.push(format!("restore {}: {err:#}", path.display()));
            }
        }
        if let Err(err) = run_checked("mkinitcpio", &["-P"]) {
            rollback_errors.push(format!("rebuild rolled-back initramfs: {err:#}"));
        }
        if !rollback_errors.is_empty() {
            bail!(
                "arm failed ({e:#}); rollback INCOMPLETE: {}. Boot only through offline recovery media",
                rollback_errors.join("; ")
            );
        }
        return Err(e).context("arm transaction rolled back");
    }
    println!("dsctl: armed. Recovery/daily slots, PAM, ESP state, and initramfs are verified.");
    Ok(())
}

/// Disarm: restore the exact PAM backup, remove both armed markers, and rebuild initramfs so the
/// initramfs-local authorization marker is gone.
fn disarm() -> Result<()> {
    require_root()?;
    let content = std::fs::read_to_string(SYSTEM_AUTH).with_context(|| format!("read {SYSTEM_AUTH}"))?;
    if !content.contains(ARM_MARKER) { println!("dsctl: PAM is not armed; reconciling markers/initramfs."); }
    let bak = format!("{SYSTEM_AUTH}.deathstr0ke.bak");
    let backup = if content.contains(ARM_MARKER) {
        Some(std::fs::read_to_string(&bak)
            .context("PAM backup missing; refusing a partial disarm that could corrupt numeric control jumps")?)
    } else { None };
    let mode = std::fs::metadata(SYSTEM_AUTH)?.permissions().mode() & 0o7777;
    let mkinit_path = Path::new("/etc/mkinitcpio.conf");
    let mkinit_original = std::fs::read(mkinit_path).context("snapshot mkinitcpio.conf")?;
    let mkinit_mode = std::fs::metadata(mkinit_path)?.permissions().mode() & 0o7777;
    let local_was_armed = Path::new(ds_core::ARMED_MARKER).is_file();
    let esp_armed_path = Path::new(ds_core::ESP_STATE_DIR).join("armed");
    let esp_was_armed = esp_armed_path.is_file();
    let disarm_result = (|| -> Result<()> {
        if let Some(original) = &backup {
            ds_core::atomic_write(Path::new(SYSTEM_AUTH), original.as_bytes(), mode)?;
        }
        remove_if_exists(Path::new(ds_core::ARMED_MARKER))?;
        remove_if_exists(&esp_armed_path)?;
        remove_deathstroke_hook()?;
        run_checked("mkinitcpio", &["-P"])
    })();
    if let Err(e) = disarm_result {
        let mut rollback_errors = Vec::new();
        if let Err(err) = ds_core::atomic_write(mkinit_path, &mkinit_original, mkinit_mode) {
            rollback_errors.push(format!("restore mkinitcpio.conf: {err:#}"));
        }
        if local_was_armed {
            if let Err(err) = ds_core::atomic_write(Path::new(ds_core::ARMED_MARKER), b"armed=1\n", 0o600) {
                rollback_errors.push(format!("restore local armed marker: {err:#}"));
            }
        }
        if esp_was_armed {
            if let Err(err) = ds_core::atomic_write(&esp_armed_path, b"armed=1\n", 0o600) {
                rollback_errors.push(format!("restore ESP armed marker: {err:#}"));
            }
        }
        if backup.is_some() {
            if let Err(err) = ds_core::atomic_write(Path::new(SYSTEM_AUTH), content.as_bytes(), mode) {
                rollback_errors.push(format!("restore armed PAM: {err:#}"));
            }
        }
        if let Err(err) = run_checked("mkinitcpio", &["-P"]) {
            rollback_errors.push(format!("rebuild restored armed initramfs: {err:#}"));
        }
        if !rollback_errors.is_empty() {
            bail!(
                "disarm failed ({e:#}); rollback INCOMPLETE: {}. Boot only through offline recovery media",
                rollback_errors.join("; ")
            );
        }
        return Err(e).context("disarm failed; armed PAM, markers, and initramfs restored");
    }
    if backup.is_some() { std::fs::remove_file(&bak).context("remove PAM backup")?; }
    println!("dsctl: disarmed; stock PAM restored and armed markers removed from rebuilt initramfs.");
    Ok(())
}

fn read_policy() -> Result<ds_core::Policy> {
    let path = Path::new(&ds_core::state_dir()).join("config");
    match std::fs::read_to_string(&path) {
        Ok(text) => ds_core::Policy::parse(&text).context("invalid local policy"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ds_core::Policy::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn read_slot(name: &str) -> Result<u8> {
    let path = Path::new(&ds_core::state_dir()).join(name);
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let slot: u8 = text.trim().parse().context("invalid keyslot metadata")?;
    if slot > 31 { bail!("keyslot outside 0..31"); }
    Ok(slot)
}

fn sync_esp_state(verifier: &str, policy: ds_core::Policy, daily: u8, recovery: u8) -> Result<()> {
    let dir = Path::new(ds_core::ESP_STATE_DIR);
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    ds_core::atomic_write(&dir.join("duress.hash"), verifier.as_bytes(), 0o600)?;
    let config = format!(
        "lockout_at={}\nwipe_at={}\nlockout_delay={}\nmax_prompts={}\n",
        policy.lockout_at, policy.wipe_at, policy.lockout_delay, policy.max_prompts
    );
    ds_core::atomic_write(&dir.join("config"), config.as_bytes(), 0o600)?;
    ds_core::atomic_write(&dir.join("counter"), b"0\n", 0o600)?;
    ds_core::atomic_write(&dir.join("daily.slot"), format!("{daily}\n").as_bytes(), 0o600)?;
    ds_core::atomic_write(&dir.join("recovery.slot"), format!("{recovery}\n").as_bytes(), 0o600)?;
    Ok(())
}

fn ensure_deathstroke_hook_before_encrypt() -> Result<()> {
    let path = Path::new("/etc/mkinitcpio.conf");
    let original = std::fs::read_to_string(path).context("read /etc/mkinitcpio.conf")?;
    let mut changed = false;
    let mut saw_hooks = false;
    let mut out = Vec::new();
    for line in original.lines() {
        if line.trim_start().starts_with("HOOKS=") {
            saw_hooks = true;
            let death = line.find("deathstroke");
            let encrypt = line.find("encrypt").or_else(|| line.find("sd-encrypt"));
            if let (Some(d), Some(e)) = (death, encrypt) {
                if d > e { bail!("deathstroke hook must precede encrypt/sd-encrypt"); }
                out.push(line.to_string());
            } else if let Some(e) = encrypt {
                let mut updated = line.to_string();
                updated.insert_str(e, "deathstroke ");
                out.push(updated);
                changed = true;
            } else {
                bail!("HOOKS has no encrypt or sd-encrypt hook");
            }
        } else {
            out.push(line.to_string());
        }
    }
    if !saw_hooks { bail!("mkinitcpio.conf has no HOOKS line"); }
    if changed {
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o7777;
        ds_core::atomic_write(path, (out.join("\n") + "\n").as_bytes(), mode)?;
    }
    Ok(())
}

fn remove_deathstroke_hook() -> Result<()> {
    let path = Path::new("/etc/mkinitcpio.conf");
    let original = std::fs::read_to_string(path).context("read /etc/mkinitcpio.conf")?;
    let (updated, changed) = without_deathstroke_hook(&original)?;
    if changed {
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o7777;
        ds_core::atomic_write(path, updated.as_bytes(), mode)?;
    }
    Ok(())
}

fn without_deathstroke_hook(original: &str) -> Result<(String, bool)> {
    let mut changed = false;
    let mut saw_hooks = false;
    let mut out = Vec::new();
    for line in original.lines() {
        if line.trim_start().starts_with("HOOKS=") {
            saw_hooks = true;
            let mut updated = line.to_string();
            while let Some(start) = updated.find("deathstroke") {
                let end = start + "deathstroke".len();
                let before = updated[..start].chars().next_back();
                let after = updated[end..].chars().next();
                let before_ok = before.is_none_or(|c| c.is_whitespace() || c == '(' || c == '"');
                let after_ok = after.is_none_or(|c| c.is_whitespace() || c == ')' || c == '"');
                if !before_ok || !after_ok {
                    bail!("could not safely remove deathstroke token from HOOKS");
                }
                let remove_end = match after {
                    Some(c) if c.is_whitespace() => end + c.len_utf8(),
                    _ => end,
                };
                updated.replace_range(start..remove_end, "");
                changed = true;
            }
            out.push(updated);
        } else {
            out.push(line.to_string());
        }
    }
    if !saw_hooks { bail!("mkinitcpio.conf has no HOOKS line"); }
    Ok((out.join("\n") + "\n", changed))
}

fn arm_pam_stack(content: &str) -> Result<String> {
    if content.contains(ARM_MARKER) { bail!("PAM stack is already marked armed"); }
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let auth_positions: Vec<usize> = lines.iter().enumerate()
        .filter_map(|(i, line)| is_auth_rule(line).then_some(i)).collect();
    let first = *auth_positions.first().context("PAM stack has no auth rules")?;
    let pam_unix_auth = auth_positions.iter().position(|&i| lines[i].contains("pam_unix.so"))
        .context("unsupported PAM stack: no pam_unix auth rule")?;
    let faillock_fail_auth = auth_positions.iter().position(|&i| {
        lines[i].contains("pam_faillock.so") && lines[i].split_whitespace().any(|p| p == "authfail")
    }).context("unsupported PAM stack: no pam_faillock authfail rule")?;
    let faillock_succ_raw = auth_positions.iter().find_map(|&i| {
        (lines[i].contains("pam_faillock.so") && lines[i].split_whitespace().any(|p| p == "authsucc")).then_some(i)
    }).context("unsupported PAM stack: no pam_faillock authsucc rule")?;
    if faillock_fail_auth <= pam_unix_auth { bail!("unsupported PAM order: authfail is not after pam_unix"); }

    // Inserting our authfail before pam_faillock changes numeric success jumps that previously skipped
    // the original authfail rule. Increase every crossing jump so successful authentication still
    // lands at the same original module.
    for auth_index in 0..faillock_fail_auth {
        let raw = auth_positions[auth_index];
        if let Some(jump) = success_jump(&lines[raw]) {
            if auth_index + jump >= faillock_fail_auth {
                lines[raw] = replace_success_jump(&lines[raw], jump + 1)?;
            }
        }
    }
    let fail_raw = auth_positions[faillock_fail_auth];
    let authfail = format!("auth       [default=die]               {PAM_MODULE} authfail # {ARM_MARKER}");
    lines.insert(fail_raw, authfail);
    let succ_raw = if faillock_succ_raw >= fail_raw { faillock_succ_raw + 1 } else { faillock_succ_raw };
    let authsucc = format!("auth       optional                    {PAM_MODULE} authsucc # {ARM_MARKER}");
    lines.insert(succ_raw + 1, authsucc);
    let preauth = format!("auth       [success=ignore ignore=ignore default=die] {PAM_MODULE} # {ARM_MARKER}");
    lines.insert(first, preauth);
    Ok(lines.join("\n") + "\n")
}

fn is_auth_rule(line: &str) -> bool {
    let trimmed = line.trim_start().trim_start_matches('-');
    trimmed.split_whitespace().next() == Some("auth")
}

fn success_jump(line: &str) -> Option<usize> {
    let start = line.find("success=")? + "success=".len();
    let digits: String = line[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() { None } else { digits.parse().ok() }
}

fn replace_success_jump(line: &str, value: usize) -> Result<String> {
    let start = line.find("success=").context("no success control")? + "success=".len();
    let len = line[start..].chars().take_while(|c| c.is_ascii_digit()).count();
    if len == 0 { bail!("success control is not numeric"); }
    let mut out = line.to_string();
    out.replace_range(start..start + len, &value.to_string());
    Ok(out)
}

fn run_checked(bin: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(bin).args(args).status().with_context(|| format!("run {bin}"))?;
    if !status.success() { bail!("{bin} {} failed", args.join(" ")); }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

/// Prompt for a duress code (twice), derive a PBKDF2 verifier, write it to the state dir 0600. The
/// plaintext code is scrubbed from memory immediately after derivation (zeroize). Non-destructive.
fn set_duress(args: &[String]) -> Result<()> {
    require_root()?;
    if Path::new(ds_core::ARMED_MARKER).exists() { bail!("disarm before changing the duress verifier"); }
    let policy = enrollment_policy(args)?;
    let mut code = read_secret("Duress code: ")?;
    let mut again = read_secret("Confirm duress code: ")?;
    if code != again {
        code.zeroize_now();
        again.zeroize_now();
        bail!("codes did not match");
    }
    again.zeroize_now();
    if code.len() < 6 {
        code.zeroize_now();
        bail!("duress code too short (min 6 chars)");
    }
    let h = derive_and_zero(code, DEFAULT_ITERATIONS)?;
    let path = ds_core::duress_hash_path();
    ensure_state_dir()?;
    let config = format!(
        "lockout_at={}\nwipe_at={}\nlockout_delay={}\nmax_prompts={}\n",
        policy.lockout_at, policy.wipe_at, policy.lockout_delay, policy.max_prompts
    );
    ds_core::atomic_write(&Path::new(&ds_core::state_dir()).join("config"), config.as_bytes(), 0o600)?;
    write_0600(&path, h.serialize().as_bytes())?;
    println!("dsctl: duress verifier written to {path} (hash only; the code is not stored).");
    Ok(())
}

fn enrollment_policy(args: &[String]) -> Result<ds_core::Policy> {
    let mut policy = ds_core::Policy::default();
    let mut seen = BTreeSet::new();
    let mut options = args.iter().skip(1);
    while let Some(name) = options.next() {
        if !seen.insert(name) { bail!("duplicate policy option {name}"); }
        let value = options.next().with_context(|| format!("missing value for {name}"))?;
        match name.as_str() {
            "--lockout-at" => policy.lockout_at = value.parse().context("invalid --lockout-at")?,
            "--wipe-at" => policy.wipe_at = value.parse().context("invalid --wipe-at")?,
            "--lockout-delay" => policy.lockout_delay = value.parse().context("invalid --lockout-delay")?,
            "--max-prompts" => policy.max_prompts = value.parse().context("invalid --max-prompts")?,
            _ => bail!("unknown set-duress option {name}"),
        }
    }
    if !seen.iter().any(|s| s.as_str() == "--max-prompts") {
        policy.max_prompts = policy.max_prompts.max(policy.wipe_at);
    }
    policy.validate()
}

/// Verify a candidate code against the stored verifier (constant-time). For a self-check that the
/// enrolled code is what the user thinks — NEVER fires anything. Reads the code interactively unless
/// passed (passing on argv is only for scripted tests, discouraged in real use).
fn verify(arg: Option<&str>) -> Result<()> {
    let stored = std::fs::read_to_string(ds_core::duress_hash_path())
        .context("no duress verifier enrolled (run `dsctl set-duress`)")?;
    let h = DuressHash::parse(&stored)?;
    let cand = match arg {
        Some(s) if ds_core::test_mode() => s.as_bytes().to_vec(),
        Some(_) => bail!("passing a secret on argv is disabled; run dsctl verify and enter it at the no-echo prompt"),
        None => read_secret("Code to check: ")?,
    };
    let ok = h.verify(&cand)?;
    let mut cand = cand; cand.zeroize_now();
    if ok { println!("dsctl: MATCH — this code is the enrolled duress code."); }
    else   { println!("dsctl: no match."); }
    Ok(())
}

/// `dsctl panic`: a deliberate, discoverable duress trigger for a booted+unlocked session, for users
/// who will not think to type the duress phrase at a password prompt. Requires root, requires the
/// machine be ARMED, and confirms intent by re-entering the enrolled duress phrase (so it can never
/// fire by accident). On a correct phrase it runs the SAME recovery-safe crypto-erase that pam_ds and
/// the dead-man switch use: the daily keyslot is destroyed (the disk passphrase stops working) while
/// the offline recovery keyslot survives, so the owner can still restore. Refuses on an un-armed
/// machine (no ARMED marker) and on a wrong phrase.
fn panic_wipe() -> Result<()> {
    require_root()?;
    if !Path::new(ds_core::ARMED_MARKER).exists() {
        bail!("DEATHSTROKE is not armed on this machine; there is nothing to trigger");
    }
    let stored = std::fs::read_to_string(ds_core::duress_hash_path())
        .context("no duress verifier enrolled (run `dsctl set-duress`)")?;
    let h = DuressHash::parse(&stored)?;
    eprintln!("DEATHSTROKE panic: this destroys the daily encryption key right now.");
    eprintln!("The disk passphrase stops working; your offline recovery key still does.");
    let mut cand = read_secret("Enter your duress phrase to confirm the wipe: ")?;
    let ok = h.verify(&cand)?;
    cand.zeroize_now();
    if !ok { bail!("phrase does not match the enrolled duress phrase; no action taken"); }
    let dev = configured_target()
        .context("no target device recorded (run `dsctl enroll-recovery --device <luks>`)")?;
    // Test builds may point at a specific ds-erase (same rule as DS_STATE_DIR); release ignores it.
    let erase = ds_core::test_mode().then(|| std::env::var("DS_ERASE_BIN").ok()).flatten()
        .or_else(|| ["/usr/lib/arxos/deathstroke/ds-erase", "/usr/local/bin/ds-erase"]
            .iter().find(|p| Path::new(p).exists()).map(|s| s.to_string()))
        .unwrap_or_else(|| "ds-erase".to_string());
    eprintln!("dsctl: firing recovery-safe crypto-erase on {dev} ...");
    let st = Command::new(erase).args(["--fire", "--device", &dev]).status()
        .context("spawn ds-erase")?;
    if !st.success() { bail!("ds-erase did not complete successfully"); }
    Ok(())
}

fn status() -> Result<()> {
    let enrolled = Path::new(&ds_core::duress_hash_path()).exists();
    let pam_armed = std::fs::read_to_string(SYSTEM_AUTH).map(|c| c.contains(ARM_MARKER)).unwrap_or(false);
    let local_armed = Path::new(ds_core::ARMED_MARKER).is_file();
    let esp_armed = Path::new(ds_core::ESP_STATE_DIR).join("armed").is_file();
    let armed = pam_armed && local_armed && esp_armed;
    let inconsistent = pam_armed || local_armed || esp_armed;
    let recov = std::fs::read_to_string(format!("{}/recovery.device", ds_core::state_dir())).ok();
    let marker = Path::new(ds_core::DISPOSABLE_MARKER).exists();
    println!("status");
    println!("  duress code enrolled : {}", yesno(enrolled));
    println!("  armed (in auth path) : {}", yesno(armed));
    if inconsistent && !armed { println!("  integrity             : INCONSISTENT ARMED STATE — recover/disarm before boot"); }
    println!("  recovery keyslot     : {}", recov.as_deref().map(|d| format!("enrolled on {}", d.trim())).unwrap_or_else(|| "none".into()));
    println!("  environment          : {}", if marker { "disposable (destructive ops permitted)" } else { "not marked disposable (destructive ops refused)" });
    Ok(())
}

/// Destructive and system-altering operations run only on a machine marked disposable while they are
/// under development.
fn guard_disposable(op: &str) -> Result<()> {
    if !Path::new(ds_core::DISPOSABLE_MARKER).exists() {
        bail!("SAFETY GUARD: `{op}` refused. This machine is not marked disposable ({} absent).", ds_core::DISPOSABLE_MARKER);
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
    let dir = ds_core::state_dir();
    std::fs::create_dir_all(&dir).context("create state dir")?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).context("chmod state dir")?;
    Ok(())
}
fn write_0600(path: &str, data: &[u8]) -> Result<()> {
    ds_core::atomic_write(Path::new(path), data, 0o600)
}
fn read_secret(prompt: &str) -> Result<Vec<u8>> {
    if !std::io::stdin().is_terminal() {
        let mut secret = String::new();
        std::io::stdin().read_line(&mut secret).context("read piped secret")?;
        return Ok(secret.trim_end_matches(['\n', '\r']).as_bytes().to_vec());
    }
    let secret = rpassword::prompt_password(prompt).context("read secret without echo")?;
    Ok(secret.into_bytes())
}
fn yesno(b: bool) -> &'static str { if b { "yes" } else { "no" } }

// tiny helper so we can scrub a Vec without importing the trait everywhere.
trait ZeroizeNow { fn zeroize_now(&mut self); }
impl ZeroizeNow for Vec<u8> { fn zeroize_now(&mut self) { use zeroize::Zeroize; self.zeroize(); } }

#[cfg(test)]
mod tests {
    use super::*;

    // The arm-time backdoor-slot defense: the known-slot registry round-trips, and the set-difference
    // that `arm` uses flags exactly the active slots that were never recorded by dsctl.
    #[test]
    fn known_slot_registry_flags_unrecorded_slots() {
        // state_dir() only honors DS_STATE_DIR when DS_TEST_MODE=1 and the path is under /tmp.
        let dir = std::path::Path::new("/tmp").join(format!("ds-known-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("DS_TEST_MODE", "1");
        std::env::set_var("DS_STATE_DIR", dir.to_str().unwrap());
        // enroll-recovery baselines exactly {daily=0, recovery=1}
        let mut baseline = BTreeSet::new();
        baseline.insert(0u8); baseline.insert(1u8);
        write_known_slots(&baseline).unwrap();
        assert_eq!(read_known_slots(), baseline, "registry must round-trip");
        // a factor enrollment records its slot (2); now {0,1,2} are all known
        let mut factor = BTreeSet::new(); factor.insert(2u8);
        add_known_slots(&factor).unwrap();
        assert_eq!(read_known_slots(), BTreeSet::from([0u8, 1, 2]));
        // an out-of-band slot (3) that dsctl never recorded is the one `arm` must refuse
        let active = BTreeSet::from([0u8, 1, 2, 3]);
        let unknown: Vec<u8> = active.difference(&read_known_slots()).copied().collect();
        assert_eq!(unknown, vec![3u8], "only the unrecorded slot is flagged");
        // with no stray slot, nothing is flagged
        let clean = BTreeSet::from([0u8, 1, 2]);
        assert!(clean.difference(&read_known_slots()).copied().collect::<Vec<u8>>().is_empty());
        std::env::remove_var("DS_STATE_DIR");
        std::env::remove_var("DS_TEST_MODE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    const ARCH_SYSTEM_AUTH: &str = r#"#%PAM-1.0
auth       required                    pam_faillock.so      preauth
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc
account    required                    pam_unix.so
"#;

    #[test]
    fn arch_pam_transform_preserves_success_jump_targets() {
        let out = arm_pam_stack(ARCH_SYSTEM_AUTH).unwrap();
        assert!(out.contains("[success=3 default=ignore]  pam_systemd_home.so"));
        assert!(out.contains("[success=2 default=bad]     pam_unix.so"));
        assert_eq!(out.matches("pam_ds.so").count(), 3);
        let fail = out.find("pam_ds.so authfail").unwrap();
        let stock_fail = out.find("pam_faillock.so      authfail").unwrap();
        assert!(fail < stock_fail);
        let stock_succ = out.find("pam_faillock.so      authsucc").unwrap();
        let success = out.find("pam_ds.so authsucc").unwrap();
        assert!(success > stock_succ);
    }

    #[test]
    fn refuses_unknown_pam_layout() {
        assert!(arm_pam_stack("auth required pam_unix.so\n").is_err());
    }

    #[test]
    fn installer_policy_options_are_applied_or_rejected() {
        let parse = |values: &[&str]| enrollment_policy(&values.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let policy = parse(&["set-duress", "--lockout-at", "4", "--wipe-at", "8"]).unwrap();
        assert_eq!(policy.lockout_at, 4);
        assert_eq!(policy.wipe_at, 8);
        assert_eq!(policy.max_prompts, 8);
        assert!(parse(&["set-duress", "--wipe-at"]).is_err());
        assert!(parse(&["set-duress", "--wipe-at", "21"]).is_err());
        assert!(parse(&["set-duress", "--unknown", "1"]).is_err());
        assert!(parse(&["set-duress", "--wipe-at", "6", "--wipe-at", "7"]).is_err());
    }

    #[test]
    fn disarm_removes_only_the_hook_token() {
        let input = "MODULES=()\nHOOKS=(base udev deathstroke encrypt filesystems)\n";
        let (out, changed) = without_deathstroke_hook(input).unwrap();
        assert!(changed);
        assert_eq!(out, "MODULES=()\nHOOKS=(base udev encrypt filesystems)\n");
        assert!(without_deathstroke_hook("HOOKS=(base mydeathstroke encrypt)\n").is_err());
    }
}
