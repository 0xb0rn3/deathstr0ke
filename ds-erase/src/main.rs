// ds-erase: the crypto-erase actor. Destructive by design. It destroys LUKS keyslots so the disk
// becomes undecryptable. It shells to stock `cryptsetup`, so it carries no crypto of its own and
// stays working across upstream releases.
//
// SAFETY: `--fire` against a real device only runs on a machine explicitly marked disposable (a
// marker file that is never shipped). `--self-test` exercises the same erase code against a loopback
// LUKS volume it creates and removes in /tmp, so it is safe to run anywhere.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const JOURNAL_VERSION: u8 = 1;
const MAX_SCAN_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase { Prepared, BackupsHandled, KeyslotsDestroyed }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EraseMode { KillSlot, Erase }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Journal {
    version: u8,
    phase: Phase,
    device: String,
    mode: EraseMode,
    slot: Option<u8>,
    recovery_slot: Option<u8>,
    map_name: Option<String>,
    header_scan: Vec<String>,
}

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("ds-erase: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<()> {
    if args.iter().any(|a| a == "--test-no-poweroff") && !ds_core::test_mode() {
        bail!("--test-no-poweroff requires a debug build with DS_TEST_MODE=1; no action taken");
    }
    match args.first().map(String::as_str) {
        Some("--check")     => { report_guard(); Ok(()) }
        Some("--self-test") => self_test(),
        Some("--resume")    => resume(&args),
        Some("--fire")      => fire(&args),
        _ => { eprintln!("usage: ds-erase --check | --self-test | --fire [--device <dev>] [--mode killslot --slot N --recovery-slot N | --mode erase --destroy-recovery] | --resume --journal <path> --expected-device <dev> --expected-slot N --expected-recovery-slot N"); std::process::exit(2); }
    }
}

// ---- the real crypto-erase primitives (product logic; shared by --fire and --self-test) ----

/// Destroy ONE keyslot (the in-use daily key). A recovery keyslot in another slot survives — this is
/// so the user can still recover with their key.
fn luks_kill_slot(device: &str, slot: u8) -> Result<()> {
    let st = Command::new("cryptsetup").args(["luksKillSlot", "--batch-mode", device, &slot.to_string()])
        .status().context("spawn cryptsetup luksKillSlot")?;
    if !st.success() { bail!("luksKillSlot {slot} on {device} failed"); }
    Ok(())
}

/// Destroy ALL keyslots — the full crypto-erase. The ciphertext becomes permanently undecryptable
/// (no keyslot can derive the master key). This is the fast path: instant, no data overwrite.
fn luks_erase(device: &str) -> Result<()> {
    let st = Command::new("cryptsetup").args(["luksErase", "--batch-mode", device])
        .status().context("spawn cryptsetup luksErase")?;
    if !st.success() { bail!("luksErase on {device} failed"); }
    Ok(())
}

/// Active LUKS keyslots, handling BOTH LUKS2 ("<n>: luks2") and LUKS1 ("Key Slot <n>: ENABLED").
/// Installers still produce LUKS1 (Calamares' default), so the erase engine must read both formats or
/// it will misjudge a LUKS1 container as having zero slots and skip/refuse a real erase.
fn active_slot_set(device: &str) -> Result<std::collections::BTreeSet<u8>> {
    let out = Command::new("cryptsetup").args(["luksDump", device]).output().context("cryptsetup luksDump")?;
    if !out.status.success() { bail!("luksDump failed on {device}"); }
    let mut slots = std::collections::BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let trimmed = line.trim_start();
        // LUKS2: keyslots are listed as "<n>: luks2".
        if let Some((number, kind)) = trimmed.split_once(':') {
            if kind.trim_start().starts_with("luks2") {
                if let Ok(slot) = number.trim().parse::<u8>() { slots.insert(slot); }
                continue;
            }
        }
        // LUKS1: keyslots are listed as "Key Slot <n>: ENABLED".
        if let Some(rest) = trimmed.strip_prefix("Key Slot ") {
            if let Some((number, state)) = rest.split_once(':') {
                if state.trim().eq_ignore_ascii_case("ENABLED") {
                    if let Ok(slot) = number.trim().parse::<u8>() { slots.insert(slot); }
                }
            }
        }
    }
    Ok(slots)
}

/// Count active LUKS keyslots (0 after a successful erase).
fn active_keyslots(device: &str) -> Result<usize> {
    Ok(active_slot_set(device)?.len())
}

// ---- in-progress journal (the power-loss resume flag) ----

/// One journal location everywhere: the state directory on the unencrypted ESP. The initramfs mounts
/// that ESP at `/ds-esp` and passes `/ds-esp/deathstroke/inprogress` explicitly.
const DEFAULT_JOURNAL: &str = "/boot/efi/deathstroke/inprogress";

fn journal_dir(journal: &str) -> String {
    Path::new(journal).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "/boot".into())
}

/// The pre-configured device to erase on a duress trigger (dsctl records the LUKS root here). Read from
/// the state dir so `ds-erase --fire` with no arguments (as pam_ds calls it) knows what to destroy.
fn configured_target() -> Option<String> {
    std::fs::read_to_string(format!("{}/target.device", ds_core::state_dir())).ok()
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn write_journal(path: &Path, journal: &Journal) -> Result<()> {
    let parent = path.parent().context("journal path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create journal dir {}", parent.display()))?;
    let tmp = parent.join(format!(".inprogress.tmp.{}", std::process::id()));
    let data = serde_json::to_vec(journal).context("serialize journal")?;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)
            .with_context(|| format!("create journal temp {}", tmp.display()))?;
        file.write_all(&data).context("write journal")?;
        file.write_all(b"\n").context("finish journal")?;
        file.sync_all().context("fsync journal")?;
        fs::rename(&tmp, path).with_context(|| format!("rename journal into {}", path.display()))?;
        fs::File::open(parent)?.sync_all().context("fsync journal directory")?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&tmp); }
    result
}

fn read_journal(path: &Path) -> Result<Journal> {
    let data = fs::read(path).with_context(|| format!("read journal {}", path.display()))?;
    if data.len() > 64 * 1024 { bail!("journal exceeds 64 KiB"); }
    let journal: Journal = serde_json::from_slice(&data).context("parse journal")?;
    if journal.version != JOURNAL_VERSION { bail!("unsupported journal version {}", journal.version); }
    validate_mode_slots(journal.mode, journal.slot, journal.recovery_slot)?;
    if journal.header_scan.len() > 32 { bail!("too many journal scan roots"); }
    for path in &journal.header_scan { validate_text_field("header scan path", path)?; }
    validate_scan_roots(path, &journal.header_scan)?;
    validate_text_field("device", &journal.device)?;
    if let Some(map) = &journal.map_name { validate_map_name(map)?; }
    Ok(journal)
}

fn remove_journal(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("remove journal {}", path.display())),
    }
    if let Some(parent) = path.parent() { fs::File::open(parent)?.sync_all()?; }
    Ok(())
}

// ---- LUKS header-backup destruction (the forensic catch) ----

/// LUKS magic: "LUKS" 0xba 0xbe at offset 0. Both LUKS1 and LUKS2 headers (and their `luksHeaderBackup`
/// files) begin with it, so this identifies a header-backup file regardless of the file's name.
const LUKS_MAGIC: &[u8] = &[b'L', b'U', b'K', b'S', 0xba, 0xbe];

fn is_luks_header_file(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 6];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut buf)).is_ok() && buf == LUKS_MAGIC
}

/// Remove LUKS-header backup files under explicitly configured roots. Directory walking is recursive,
/// bounded, and never follows symlinks. This only removes backups the operator placed under those
/// roots; it cannot make claims about unknown/offline copies or physical flash remanence.
fn destroy_header_backups(paths: &[String]) -> Result<usize> {
    let mut stack: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let mut visited = 0usize;
    let mut destroyed = 0usize;
    while let Some(path) = stack.pop() {
        visited += 1;
        if visited > MAX_SCAN_ENTRIES { bail!("header scan exceeds {MAX_SCAN_ENTRIES} entries"); }
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("stat scan path {}", path.display())),
        };
        if meta.file_type().is_symlink() { continue; }
        if meta.is_dir() {
            for entry in fs::read_dir(&path).with_context(|| format!("read scan dir {}", path.display()))? {
                stack.push(entry?.path());
            }
        } else if meta.is_file() && is_luks_header_file(&path) {
            erase_header_file(&path)?;
            destroyed += 1;
        }
    }
    Ok(destroyed)
}

fn erase_header_file(path: &Path) -> Result<()> {
    // Best-effort overwrite plus unlink. Filesystem/device remapping can retain older physical cells;
    // callers and documentation must not describe this as guaranteed physical erasure.
    let status = Command::new("shred").args(["-u", "-z", "-n", "1"]).arg(path).status();
    if status.map(|s| s.success()).unwrap_or(false) { return Ok(()); }
    fs::remove_file(path).with_context(|| format!("remove header backup {}", path.display()))
}

// ---- --fire (guarded) ----

fn fire(args: &[String]) -> Result<()> {
    guard()?;
    let device = flag(args, "--device").or_else(configured_target)
        .context("--fire needs --device <dev> or a configured target.device")?;
    validate_target(&device)?;
    let (mode, slot, recovery_slot) = parse_mode(args)?;
    let journal_path = PathBuf::from(flag(args, "--journal").unwrap_or_else(|| DEFAULT_JOURNAL.into()));
    validate_journal_path(&journal_path)?;
    if journal_path.exists() { bail!("journal already exists; use --resume --journal {}", journal_path.display()); }
    let mut scan: Vec<String> = args_multi(args, "--header-scan");
    if scan.is_empty() { scan.push(journal_dir(&journal_path.to_string_lossy())); }
    validate_scan_roots(&journal_path, &scan)?;
    let mut journal = Journal {
        version: JOURNAL_VERSION,
        phase: Phase::Prepared,
        device,
        mode,
        slot,
        recovery_slot,
        map_name: flag(args, "--map-name"),
        header_scan: scan,
    };
    if let Some(map) = &journal.map_name { validate_map_name(map)?; }
    write_journal(&journal_path, &journal)?;
    run_transaction(&journal_path, &mut journal, test_no_poweroff(args))
}

fn resume(args: &[String]) -> Result<()> {
    guard()?;
    let path = flag(args, "--journal").context("--resume requires --journal <ESP-state/inprogress>")?;
    let expected_device = flag(args, "--expected-device").context("--resume requires --expected-device from the trusted boot configuration")?;
    let expected_slot: u8 = flag(args, "--expected-slot").context("--resume requires --expected-slot")?
        .parse().context("bad --expected-slot")?;
    let expected_recovery_slot: u8 = flag(args, "--expected-recovery-slot")
        .context("--resume requires --expected-recovery-slot")?
        .parse().context("bad --expected-recovery-slot")?;
    validate_mode_slots(
        EraseMode::KillSlot,
        Some(expected_slot),
        Some(expected_recovery_slot),
    )?;
    let journal_path = PathBuf::from(path);
    validate_journal_path(&journal_path)?;
    let mut journal = read_journal(&journal_path)?;
    if journal.mode != EraseMode::KillSlot
        || journal.slot != Some(expected_slot)
        || journal.recovery_slot != Some(expected_recovery_slot)
    {
        bail!("journal mode/daily/recovery slots do not match the trusted boot expectation");
    }
    let journal_device = fs::canonicalize(&journal.device).context("resolve journal device")?;
    let expected_device = fs::canonicalize(&expected_device).context("resolve expected device")?;
    if journal_device != expected_device { bail!("journal device does not match the trusted boot target"); }
    if let Some(expected_map) = flag(args, "--map-name") {
        validate_map_name(&expected_map)?;
        if journal.map_name.as_deref() != Some(expected_map.as_str()) {
            bail!("journal mapping name does not match the trusted boot configuration");
        }
    }
    validate_target(&journal.device)?;
    run_transaction(&journal_path, &mut journal, test_no_poweroff(args))
}

fn run_transaction(path: &Path, journal: &mut Journal, no_poweroff: bool) -> Result<()> {
    if journal.phase == Phase::Prepared {
        let destroyed = destroy_header_backups(&journal.header_scan)?;
        eprintln!("ds-erase: removed {destroyed} discovered LUKS header backup(s) under configured roots");
        journal.phase = Phase::BackupsHandled;
        write_journal(path, journal)?;
    }

    if journal.phase == Phase::BackupsHandled {
        match journal.mode {
            EraseMode::KillSlot => {
                let slot = journal.slot.context("killslot journal missing slot")?;
                let recovery = journal.recovery_slot.context("killslot journal missing recovery slot")?;
                if !keyslot_active(&journal.device, recovery)? {
                    bail!("verified recovery slot {recovery} is not active; refusing daily-slot destruction");
                }
                if keyslot_active(&journal.device, slot)? { luks_kill_slot(&journal.device, slot)?; }
            }
            EraseMode::Erase => {
                if active_keyslots(&journal.device)? > 0 { luks_erase(&journal.device)?; }
            }
        }
        verify_keyslot_outcome(journal)?;
        journal.phase = Phase::KeyslotsDestroyed;
        write_journal(path, journal)?;
    }

    if journal.phase == Phase::KeyslotsDestroyed {
        verify_keyslot_outcome(journal)?;
        if no_poweroff {
            remove_journal(path)?;
            return Ok(());
        }
        quiesce_network_and_sessions();
        if let Some(map) = &journal.map_name {
            let _ = Command::new("cryptsetup").args(["close", map]).status();
        }
        request_poweroff()?;
        remove_journal(path)?;
    }
    Ok(())
}

// ---- --self-test: exercise the REAL primitives on a disposable loopback (safe anywhere) ----

fn self_test() -> Result<()> {
    require_root().context("self-test needs root (device-mapper)")?;
    if !have("cryptsetup") || !have("losetup") { bail!("need cryptsetup + losetup"); }
    let dir = format!("/tmp/ds-erase-selftest.{}", std::process::id());
    std::fs::create_dir_all(&dir)?;
    let img = format!("{dir}/vault.img");
    let (k0, k1) = (format!("{dir}/k0"), format!("{dir}/k1"));
    std::fs::write(&k0, b"daily-key")?;
    std::fs::write(&k1, b"recovery-key")?;

    // cleanup guard: always detach the loop + remove the dir, even on error.
    struct Cleanup { loop_dev: Option<String>, dir: String }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(l) = &self.loop_dev { let _ = Command::new("losetup").args(["-d", l]).status(); }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    let mut cu = Cleanup { loop_dev: None, dir: dir.clone() };

    run_ok("dd", &["if=/dev/zero", &format!("of={img}"), "bs=1M", "count=32", "status=none"])?;
    let loop_dev = Command::new("losetup").args(["-f", "--show", &img]).output()?;
    let loop_dev = String::from_utf8_lossy(&loop_dev.stdout).trim().to_string();
    if loop_dev.is_empty() { bail!("losetup gave no device"); }
    cu.loop_dev = Some(loop_dev.clone());

    run_ok("cryptsetup", &["luksFormat", "--type", "luks2", "--batch-mode", &loop_dev, &k0])?;
    run_ok("cryptsetup", &["luksAddKey", &loop_dev, &k1, "--key-file", &k0])?;

    let mut ok = true;
    let opens = |kf: &str| Command::new("cryptsetup").args(["open", "--test-passphrase", "--key-file", kf, &loop_dev]).status().map(|s| s.success()).unwrap_or(false);

    check(&mut ok, "both keys open initially", opens(&k0) && opens(&k1));

    // Header backups inside an explicitly configured root are removed recursively. A separate backup
    // outside the root demonstrates the honest limit: unknown/offline copies remain recoverable.
    let bkdir = format!("{dir}/backups"); std::fs::create_dir_all(&bkdir)?;
    let hdr = format!("{bkdir}/hdr.bak");
    let stash_dir = format!("{bkdir}/deeper"); std::fs::create_dir_all(&stash_dir)?;
    let nested = format!("{stash_dir}/nested.hdr");
    let stash = format!("{dir}/offline-copy.hdr");
    run_ok("cryptsetup", &["luksHeaderBackup", &loop_dev, "--header-backup-file", &hdr])?;
    run_ok("cryptsetup", &["luksHeaderBackup", &loop_dev, "--header-backup-file", &nested])?;
    run_ok("cryptsetup", &["luksHeaderBackup", &loop_dev, "--header-backup-file", &stash])?;
    check(&mut ok, "LUKS header backup detected as a header file", is_luks_header_file(Path::new(&hdr)));
    let n = destroy_header_backups(&[bkdir.clone()])?;
    check(&mut ok, "configured backup tree removed recursively", n == 2 && !Path::new(&hdr).exists() && !Path::new(&nested).exists());
    check(&mut ok, "unknown external backup remains outside explicit scan roots", Path::new(&stash).exists());

    // phase A: kill the daily slot via the PRODUCT function; recovery must survive.
    luks_kill_slot(&loop_dev, 0)?;
    check(&mut ok, "daily key destroyed (slot 0 no longer opens)", !opens(&k0));
    check(&mut ok, "recovery key SURVIVES the killslot", opens(&k1));

    // Phase B simulates a power cut after backup handling. Re-reading the durable journal and running
    // the real resume state machine must finish the erase idempotently without requesting host poweroff.
    let jnl = PathBuf::from(format!("{dir}/inprogress"));
    let mut journal = Journal {
        version: JOURNAL_VERSION,
        phase: Phase::BackupsHandled,
        device: loop_dev.clone(),
        mode: EraseMode::Erase,
        slot: None,
        recovery_slot: None,
        map_name: None,
        header_scan: vec![bkdir],
    };
    write_journal(&jnl, &journal)?;
    journal = read_journal(&jnl)?;
    run_transaction(&jnl, &mut journal, true)?;
    check(&mut ok, "resumed transaction clears journal", !jnl.exists());
    check(&mut ok, "0 keyslots remain after erase", active_keyslots(&loop_dev)? == 0);
    check(&mut ok, "recovery no longer opens — UNDECRYPTABLE", !opens(&k1));

    // why header-backup destruction matters: a backup ds-erase did NOT catch can undo the whole erase.
    // Restore from the stashed header, then the recovery key opens again -> proves the erase is only
    // durable only to the limits of its configured scan roots.
    run_ok("cryptsetup", &["luksHeaderRestore", "--batch-mode", &loop_dev, "--header-backup-file", &stash])?;
    check(&mut ok, "a SURVIVING header backup undoes the erase (why we destroy them)", opens(&k1));

    if ok { println!("ds-erase --self-test: ALL PASS (crypto-erase + journal + header-backup destruction proven)"); Ok(()) }
    else { bail!("self-test had failures"); }
}

// ---- helpers ----

fn guard() -> Result<()> {
    if !Path::new(ds_core::DISPOSABLE_MARKER).exists() {
        bail!("SAFETY GUARD: {} absent. This machine is not marked disposable. Refusing to fire.", ds_core::DISPOSABLE_MARKER);
    }
    Ok(())
}
fn report_guard() {
    match guard() { Ok(()) => println!("ds-erase: guard OK (disposable marker present)"),
                    Err(e) => println!("ds-erase: guard BLOCKS firing here ({e})") }
}
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}
/// All values of a repeatable `--name value` flag.
fn args_multi(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name { if let Some(v) = args.get(i + 1) { out.push(v.clone()); } i += 2; }
        else { i += 1; }
    }
    out
}
fn parse_mode(args: &[String]) -> Result<(EraseMode, Option<u8>, Option<u8>)> {
    let mode = flag(args, "--mode");
    let slot = flag(args, "--slot").map(|s| s.parse::<u8>().context("bad --slot")).transpose()?;
    let recovery = flag(args, "--recovery-slot")
        .map(|s| s.parse::<u8>().context("bad --recovery-slot"))
        .transpose()?;
    let mode = match mode.as_deref() {
        None => {
            if slot.is_some() || recovery.is_some() {
                bail!("slot flags require an explicit --mode killslot");
            }
            let daily = read_recorded_slot("daily.slot")?;
            let recovery = read_recorded_slot("recovery.slot")?;
            validate_mode_slots(EraseMode::KillSlot, Some(daily), Some(recovery))?;
            return Ok((EraseMode::KillSlot, Some(daily), Some(recovery)));
        }
        Some("killslot") => EraseMode::KillSlot,
        Some("erase") if args.iter().any(|a| a == "--destroy-recovery") => EraseMode::Erase,
        Some("erase") => bail!("full erase also destroys recovery; repeat with --destroy-recovery to acknowledge"),
        Some(other) => bail!("unknown --mode '{other}' (killslot|erase)"),
    };
    let recovery = match mode {
        EraseMode::KillSlot => match recovery {
            Some(slot) => Some(slot),
            None => Some(read_recorded_slot("recovery.slot")?),
        },
        EraseMode::Erase => recovery,
    };
    validate_mode_slots(mode, slot, recovery)?;
    Ok((mode, slot, recovery))
}
fn read_recorded_slot(name: &str) -> Result<u8> {
    let text = std::fs::read_to_string(format!("{}/{name}", ds_core::state_dir()))
        .with_context(|| format!("protected {name} is unavailable"))?;
    text.trim().parse().with_context(|| format!("invalid protected {name}"))
}
fn validate_mode_slots(mode: EraseMode, slot: Option<u8>, recovery: Option<u8>) -> Result<()> {
    match (mode, slot, recovery) {
        (EraseMode::KillSlot, Some(daily @ 0..=31), Some(recovery @ 0..=31)) => {
            if daily == recovery { bail!("daily and recovery slots must be distinct"); }
            Ok(())
        }
        (EraseMode::KillSlot, _, _) => {
            bail!("killslot requires distinct --slot and --recovery-slot values in 0..31")
        }
        (EraseMode::Erase, None, None) => Ok(()),
        (EraseMode::Erase, _, _) => bail!("slot flags are invalid with full erase"),
    }
}
fn validate_target(device: &str) -> Result<()> {
    validate_text_field("device", device)?;
    let path = fs::canonicalize(device).with_context(|| format!("resolve target {device}"))?;
    if !path.starts_with("/dev/") { bail!("target must resolve below /dev"); }
    let meta = fs::metadata(&path).with_context(|| format!("stat target {}", path.display()))?;
    if !meta.file_type().is_block_device() { bail!("target is not a block device: {}", path.display()); }
    let status = Command::new("cryptsetup").args(["isLuks", device]).status().context("cryptsetup isLuks")?;
    if !status.success() { bail!("target is not a valid LUKS container: {device}"); }
    Ok(())
}
fn validate_journal_path(path: &Path) -> Result<()> {
    if !path.is_absolute() { bail!("journal path must be absolute"); }
    let parent = path.parent().context("journal has no parent")?;
    if path.file_name().and_then(|n| n.to_str()) != Some(ds_core::JOURNAL_NAME) {
        bail!("journal filename must be {}", ds_core::JOURNAL_NAME);
    }
    if !parent.ends_with("deathstroke") { bail!("journal must be inside a deathstroke ESP state directory"); }
    Ok(())
}
fn validate_scan_roots(journal: &Path, roots: &[String]) -> Result<()> {
    let parent = journal.parent().context("journal has no parent")?;
    let parent = fs::canonicalize(parent).with_context(|| format!("resolve journal directory {}", parent.display()))?;
    for root in roots {
        let resolved = fs::canonicalize(root).with_context(|| format!("resolve header scan root {root}"))?;
        if !resolved.starts_with(&parent) {
            bail!("header scan root must stay inside journal ESP directory: {root}");
        }
    }
    Ok(())
}
fn validate_text_field(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.contains(['\n', '\r', '\0']) {
        bail!("invalid {label}");
    }
    Ok(())
}
fn validate_map_name(map: &str) -> Result<()> {
    if map.is_empty() || map.len() > 127 || !map.bytes().all(|b| b.is_ascii_alphanumeric() || b"+_.-".contains(&b)) {
        bail!("invalid dm-crypt mapping name");
    }
    Ok(())
}
fn keyslot_active(device: &str, slot: u8) -> Result<bool> {
    Ok(active_slot_set(device)?.contains(&slot))
}
fn verify_keyslot_outcome(journal: &Journal) -> Result<()> {
    match journal.mode {
        EraseMode::KillSlot => {
            let daily = journal.slot.context("killslot journal missing daily slot")?;
            let recovery = journal.recovery_slot.context("killslot journal missing recovery slot")?;
            if keyslot_active(&journal.device, daily)? {
                bail!("daily slot {daily} remains active after destruction attempt");
            }
            if !keyslot_active(&journal.device, recovery)? {
                bail!("recovery slot {recovery} is not active after daily-slot destruction");
            }
            Ok(())
        }
        EraseMode::Erase => {
            if active_keyslots(&journal.device)? != 0 {
                bail!("full erase returned with active keyslots remaining");
            }
            Ok(())
        }
    }
}
fn test_no_poweroff(args: &[String]) -> bool {
    args.iter().any(|a| a == "--test-no-poweroff")
        && ds_core::test_mode()
}
fn quiesce_network_and_sessions() {
    let _ = Command::new("nmcli").args(["networking", "off"]).status();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" { let _ = Command::new("ip").args(["link", "set", "dev", &name, "down"]).status(); }
        }
    }
    let _ = Command::new("loginctl").arg("terminate-seat").arg("seat0").status();
}
fn request_poweroff() -> Result<()> {
    for (bin, args) in [
        ("systemctl", &["poweroff", "--force", "--force"][..]),
        ("poweroff", &["-f"][..]),
    ] {
        if Command::new(bin).args(args).status().map(|s| s.success()).unwrap_or(false) { return Ok(()); }
    }
    bail!("keyslots destroyed but forced poweroff request failed; journal retained for retry")
}
fn have(bin: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {bin}"))
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}
fn require_root() -> Result<()> {
    let uid = std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:").map(|v| v.split_whitespace().nth(1).unwrap_or("1").to_string())))
        .unwrap_or_else(|| "1".into());
    if uid != "0" { bail!("must run as root"); } Ok(())
}
fn run_ok(bin: &str, args: &[&str]) -> Result<()> {
    let st = Command::new(bin).args(args).status().with_context(|| format!("spawn {bin}"))?;
    if !st.success() { bail!("{bin} {} failed", args.join(" ")); } Ok(())
}
fn check(ok: &mut bool, label: &str, cond: bool) {
    if cond { println!("  PASS  {label}"); } else { println!("  FAIL  {label}"); *ok = false; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_roundtrip_and_tamper_boundaries() {
        let base = PathBuf::from(format!("/tmp/ds-journal-test.{}/deathstroke", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let path = base.join(ds_core::JOURNAL_NAME);
        let journal = Journal {
            version: JOURNAL_VERSION,
            phase: Phase::Prepared,
            device: "/dev/loop999".into(),
            mode: EraseMode::KillSlot,
            slot: Some(2),
            recovery_slot: Some(3),
            map_name: Some("cryptroot".into()),
            header_scan: vec![base.to_string_lossy().to_string()],
        };
        write_journal(&path, &journal).unwrap();
        assert_eq!(read_journal(&path).unwrap(), journal);

        let mut outside = journal.clone();
        outside.header_scan = vec!["/tmp".into()];
        write_journal(&path, &outside).unwrap();
        assert!(read_journal(&path).is_err(), "tampered scan roots must not escape the ESP state dir");

        let mut bad = journal;
        bad.version = JOURNAL_VERSION + 1;
        write_journal(&path, &bad).unwrap();
        assert!(read_journal(&path).is_err(), "unknown journal versions must fail closed");
        let _ = fs::remove_dir_all(base.parent().unwrap());
    }
}
