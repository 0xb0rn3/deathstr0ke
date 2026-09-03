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

// ---- --fire (guarded) ----

fn fire(args: &[String]) -> Result<()> {
    guard()?;   // refuses outside a machine marked disposable
    let device = flag(args, "--device").context("--fire needs --device <dev>")?;
    let mode = flag(args, "--mode").unwrap_or_else(|| "erase".into());
    match mode.as_str() {
        "killslot" => {
            let slot: u8 = flag(args, "--slot").context("killslot needs --slot N")?.parse().context("bad --slot")?;
            luks_kill_slot(&device, slot)
        }
        "erase" => luks_erase(&device),
        other => bail!("unknown --mode '{other}' (killslot|erase)"),
    }
    // NOTE: the full sequence also (1) writes the in-progress journal before this, (2) zeroes the
    // in-RAM master key, (3) finds and destroys any LUKS header backup. In progress.
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

    // phase A: kill the daily slot via the PRODUCT function; recovery must survive.
    luks_kill_slot(&loop_dev, 0)?;
    check(&mut ok, "daily key destroyed (slot 0 no longer opens)", !opens(&k0));
    check(&mut ok, "recovery key SURVIVES the killslot", opens(&k1));

    // phase B: full erase via the PRODUCT function; nothing may open it.
    luks_erase(&loop_dev)?;
    check(&mut ok, "0 keyslots remain after erase", active_keyslots(&loop_dev) == 0);
    check(&mut ok, "recovery no longer opens — UNDECRYPTABLE", !opens(&k1));

    if ok { println!("ds-erase --self-test: ALL PASS (crypto-erase model proven via the product code)"); Ok(()) }
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
