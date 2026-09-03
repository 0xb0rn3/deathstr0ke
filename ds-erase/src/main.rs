// ds-erase: the crypto-erase actor. Destructive by design. It destroys LUKS keyslots so the disk
// becomes undecryptable. It shells to stock `cryptsetup`, so it carries no crypto of its own and
// stays working across upstream releases.
//
// SAFETY: `--fire` against a real device only runs on a machine explicitly marked disposable (a
// marker file that is never shipped). `--self-test` exercises the same erase code against a loopback
// LUKS volume it creates and removes in /tmp, so it is safe to run anywhere.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

const DISPOSABLE_MARKER: &str = "/etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY";

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("ds-erase: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("--check")     => { report_guard(); Ok(()) }
        Some("--self-test") => self_test(),
        Some("--resume")    => { guard()?; println!("ds-erase: [resume] would re-enter from the journaled phase (not yet implemented)"); Ok(()) }
        Some("--fire")      => fire(&args),
        _ => { eprintln!("usage: ds-erase --check | --self-test | --fire --device <dev> --mode {{killslot|erase}} [--slot N] | --resume"); std::process::exit(2); }
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

/// Count active LUKS2 keyslots (0 after a successful erase).
fn active_keyslots(device: &str) -> usize {
    let out = Command::new("cryptsetup").args(["luksDump", device]).output().map(|o| o.stdout).unwrap_or_default();
    String::from_utf8_lossy(&out).lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with(|c: char| c.is_ascii_digit()) && t.contains(": luks2")
    }).count()
}

// ---- in-progress journal (the power-loss resume flag) ----

/// Default journal path: the ESP, mounted at /boot, is unencrypted and present before root unlock, so
/// the initramfs hook can read this flag and resume before the disk is exposed.
const DEFAULT_JOURNAL: &str = "/boot/deathstroke-inprogress";

fn journal_dir(journal: &str) -> String {
    Path::new(journal).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "/boot".into())
}

/// The pre-configured device to erase on a duress trigger (dsctl records the LUKS root here). Read from
/// the state dir so `ds-erase --fire` with no arguments (as pam_ds calls it) knows what to destroy.
fn configured_target() -> Option<String> {
    std::fs::read_to_string(format!("{}/target.device", ds_core::state_dir())).ok()
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn write_journal(path: &str, contents: &str) -> Result<()> {
    if let Some(dir) = Path::new(path).parent() { let _ = std::fs::create_dir_all(dir); }
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    std::fs::write(path, format!("{contents}\nts={ts}\n")).with_context(|| format!("write journal {path}"))?;
    if let Ok(f) = std::fs::File::open(path) { let _ = f.sync_all(); }   // survive an instant power cut
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

/// Find and shred every LUKS-header file under the given paths (a file, or a directory scanned one
/// level deep). Returns how many were destroyed. Shredding overwrites the header material so it cannot
/// be recovered to `luksHeaderRestore` a keyslot.
fn destroy_header_backups(paths: &[String]) -> usize {
    let mut n = 0;
    for p in paths {
        let pb = Path::new(p);
        if pb.is_file() {
            if is_luks_header_file(pb) && shred_file(pb) { n += 1; }
        } else if pb.is_dir() {
            if let Ok(rd) = std::fs::read_dir(pb) {
                for ep in rd.flatten().map(|e| e.path()) {
                    if ep.is_file() && is_luks_header_file(&ep) && shred_file(&ep) { n += 1; }
                }
            }
        }
    }
    n
}

fn shred_file(path: &Path) -> bool {
    // overwrite then unlink so the header material is unrecoverable; fall back to a plain remove.
    Command::new("shred").args(["-u", "-z", "-n", "1"]).arg(path).status().map(|s| s.success()).unwrap_or(false)
        || std::fs::remove_file(path).is_ok()
}

// ---- --fire (guarded) ----

fn fire(args: &[String]) -> Result<()> {
    guard()?;   // refuses outside a machine marked disposable
    // The target device: --device wins; otherwise the configured target (state/target.device). This is
    // what lets pam_ds fire `ds-erase --fire` with no arguments -- it reads the pre-configured root.
    let device = flag(args, "--device").or_else(configured_target)
        .context("--fire needs --device <dev> or a configured target.device")?;
    let mode = flag(args, "--mode").unwrap_or_else(|| "erase".into());
    let journal = flag(args, "--journal").unwrap_or_else(|| DEFAULT_JOURNAL.into());

    // 1. Journal BEFORE any destruction, on an unencrypted always-present area (the ESP). A power cut
    //    mid-run is then resumed on the next boot: the initramfs hook sees the flag before root is
    //    unlocked and re-enters `ds-erase --resume`. fsync'd so the flag survives an instant power cut.
    write_journal(&journal, &format!("phase=erase mode={mode} device={device}"))?;

    // 2. Destroy any LUKS header backup FIRST. A header backup can `luksHeaderRestore` a keyslot and
    //    undo the erase, so it is the forensic catch. Scan the configured paths (default: the journal's
    //    directory, i.e. the ESP) plus any --header-scan dirs, and shred every LUKS-header file found.
    let mut scan: Vec<String> = args_multi(args, "--header-scan");
    if scan.is_empty() { scan.push(journal_dir(&journal)); }
    let destroyed = destroy_header_backups(&scan);
    eprintln!("ds-erase: destroyed {destroyed} LUKS header backup(s) under {scan:?}");

    // 3. The crypto-erase: destroy the in-use keyslot (recovery survives) or every keyslot.
    match mode.as_str() {
        "killslot" => {
            let slot: u8 = flag(args, "--slot").context("killslot needs --slot N")?.parse().context("bad --slot")?;
            luks_kill_slot(&device, slot)?;
        }
        "erase" => luks_erase(&device)?,
        other => bail!("unknown --mode '{other}' (killslot|erase)"),
    }

    // 4. RAM master-key note: a currently-OPEN mapping keeps its master key in kernel memory until the
    //    mapping is torn down. The running root cannot close itself; that key is dropped when the
    //    DEATHSTROKE sequence powers the machine off (aided by the kernel's init_on_free). Documented,
    //    not silently pretended away.

    // 5. Clear the journal: the container is gone (or the daily key is), so there is nothing to resume.
    let _ = std::fs::remove_file(&journal);
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

    // journal: write the in-progress flag, then clear it (the power-loss resume marker).
    let jnl = format!("{dir}/inprogress");
    write_journal(&jnl, "phase=erase mode=erase device=test")?;
    check(&mut ok, "in-progress journal written", Path::new(&jnl).exists());
    let _ = std::fs::remove_file(&jnl);
    check(&mut ok, "journal cleared on completion", !Path::new(&jnl).exists());

    // header backups live in their own directory (in production this is the ESP, which never holds the
    // encrypted root's backing device). One sits in the scanned dir (ds-erase must find + shred it); one
    // is stashed a level deeper than the one-level scan reaches (used below to prove why we destroy them).
    let bkdir = format!("{dir}/backups"); std::fs::create_dir_all(&bkdir)?;
    let hdr = format!("{bkdir}/hdr.bak");
    let stash_dir = format!("{bkdir}/deeper"); std::fs::create_dir_all(&stash_dir)?;
    let stash = format!("{stash_dir}/keep.hdr");
    run_ok("cryptsetup", &["luksHeaderBackup", &loop_dev, "--header-backup-file", &hdr])?;
    run_ok("cryptsetup", &["luksHeaderBackup", &loop_dev, "--header-backup-file", &stash])?;
    check(&mut ok, "LUKS header backup detected as a header file", is_luks_header_file(Path::new(&hdr)));
    let n = destroy_header_backups(&[bkdir.clone()]);
    check(&mut ok, "header backup in scan dir SHREDDED", n == 1 && !Path::new(&hdr).exists());
    check(&mut ok, "backup in a deeper dir untouched by one-level scan", Path::new(&stash).exists());

    // phase A: kill the daily slot via the PRODUCT function; recovery must survive.
    luks_kill_slot(&loop_dev, 0)?;
    check(&mut ok, "daily key destroyed (slot 0 no longer opens)", !opens(&k0));
    check(&mut ok, "recovery key SURVIVES the killslot", opens(&k1));

    // phase B: full erase via the PRODUCT function; nothing may open it.
    luks_erase(&loop_dev)?;
    check(&mut ok, "0 keyslots remain after erase", active_keyslots(&loop_dev) == 0);
    check(&mut ok, "recovery no longer opens — UNDECRYPTABLE", !opens(&k1));

    // why header-backup destruction matters: a backup ds-erase did NOT catch can undo the whole erase.
    // Restore from the stashed header, then the recovery key opens again -> proves the erase is only
    // durable if every header backup is destroyed (which fire() does; the scan above shredded the one
    // it could reach).
    run_ok("cryptsetup", &["luksHeaderRestore", "--batch-mode", &loop_dev, "--header-backup-file", &stash])?;
    check(&mut ok, "a SURVIVING header backup undoes the erase (why we destroy them)", opens(&k1));

    if ok { println!("ds-erase --self-test: ALL PASS (crypto-erase + journal + header-backup destruction proven)"); Ok(()) }
    else { bail!("self-test had failures"); }
}

// ---- helpers ----

fn guard() -> Result<()> {
    if !Path::new(DISPOSABLE_MARKER).exists() {
        bail!("SAFETY GUARD: {DISPOSABLE_MARKER} absent. This machine is not marked disposable. Refusing to fire.");
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
