// ds-core: the shared, non-destructive logic. The duress-code hash (derive and constant-time
// verify) and the on-disk state paths. Pure and unit-testable; nothing here touches LUKS, PAM, or
// the disk beyond the state files. The components that do destructive work (ds-erase, the arming in
// dsctl) build on this. No hand-rolled crypto: PBKDF2-HMAC-SHA256 from the RustCrypto crates,
// constant-time compare from `subtle`, secrets scrubbed with `zeroize`.

use anyhow::{bail, Context, Result};
use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Reserved on-disk locations (match the install.sh layout).
pub const CONFIG_DIR: &str = "/etc/arxos/deathstroke";
pub const STATE_DIR: &str = "/var/lib/arxos/deathstroke";
pub const LIB_DIR: &str = "/usr/lib/arxos/deathstroke";
pub const ARMED_MARKER: &str = "/etc/arxos/deathstroke/ARMED";
pub const DISPOSABLE_MARKER: &str =
    "/etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY";
pub const ESP_STATE_DIR: &str = "/boot/efi/deathstroke";
pub const JOURNAL_NAME: &str = "inprogress";

/// Runtime overrides are available only in debug/test builds. Release binaries ignore them.
pub fn test_mode() -> bool {
    cfg!(debug_assertions) && std::env::var("DS_TEST_MODE").as_deref() == Ok("1")
}

/// The state directory. Tests may override it only when they also set `DS_TEST_MODE=1` and use an
/// absolute path below `/tmp`; production PAM/service environments cannot redirect security state.
pub fn state_dir() -> String {
    if test_mode() {
        if let Ok(path) = std::env::var("DS_STATE_DIR") {
            let p = Path::new(&path);
            if p.is_absolute() && p.starts_with("/tmp")
                && !p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return path;
            }
        }
    }
    STATE_DIR.to_string()
}
pub fn duress_hash_path() -> String { format!("{}/duress.hash", state_dir()) }
/// KDF cost. 600k PBKDF2-HMAC-SHA256 iterations is the current OWASP-class floor; the value is stored
/// alongside the hash so it can be raised later without invalidating existing enrollments.
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const MIN_ITERATIONS: u32 = 100_000;
pub const MAX_ITERATIONS: u32 = 5_000_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32; // SHA-256 output

/// A stored duress verifier: `pbkdf2_sha256$<iter>$<salt_b16>$<hash_b16>`. Contains NO secret — it is
/// the KDF output, safe to persist. The code itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuressHash {
    pub iterations: u32,
    pub salt: [u8; SALT_LEN],
    pub hash: [u8; HASH_LEN],
}

impl DuressHash {
    /// Derive a verifier from a duress code with a fresh random salt. The plaintext `code` is
    /// scrubbed from memory by the caller (see `derive_and_zero`); this fn does not retain it.
    pub fn derive(code: &[u8], iterations: u32) -> Result<Self> {
        validate_iterations(iterations)?;
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("csprng: {e}"))?;
        let hash = pbkdf2_sha256(code, &salt, iterations)?;
        Ok(Self { iterations, salt, hash })
    }

    /// Constant-time check of a candidate code against this verifier. Constant-time so a timing
    /// side-channel cannot distinguish a near-miss (the whole point under an adversary).
    pub fn verify(&self, candidate: &[u8]) -> Result<bool> {
        let got = pbkdf2_sha256(candidate, &self.salt, self.iterations)?;
        Ok(got.ct_eq(&self.hash).into())
    }

    pub fn serialize(&self) -> String {
        format!("pbkdf2_sha256${}${}${}", self.iterations, hex(&self.salt), hex(&self.hash))
    }

    pub fn parse(s: &str) -> Result<Self> {
        let f: Vec<&str> = s.trim().split('$').collect();
        if f.len() != 4 || f[0] != "pbkdf2_sha256" { bail!("not a pbkdf2_sha256 verifier"); }
        let iterations: u32 = f[1].parse().context("bad iteration count")?;
        validate_iterations(iterations)?;
        let salt_v = unhex(f[2])?; let hash_v = unhex(f[3])?;
        if salt_v.len() != SALT_LEN { bail!("bad salt length"); }
        if hash_v.len() != HASH_LEN { bail!("bad hash length"); }
        let mut salt = [0u8; SALT_LEN]; salt.copy_from_slice(&salt_v);
        let mut hash = [0u8; HASH_LEN]; hash.copy_from_slice(&hash_v);
        Ok(Self { iterations, salt, hash })
    }
}

fn validate_iterations(iterations: u32) -> Result<()> {
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        bail!("PBKDF2 iterations outside safe range {MIN_ITERATIONS}..={MAX_ITERATIONS}");
    }
    Ok(())
}

/// Derive a verifier and scrub the plaintext code buffer afterward.
pub fn derive_and_zero(mut code: Vec<u8>, iterations: u32) -> Result<DuressHash> {
    let out = DuressHash::derive(&code, iterations);
    code.zeroize();
    out
}

fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iterations: u32) -> Result<[u8; HASH_LEN]> {
    let mut out = [0u8; HASH_LEN];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(pw, salt, iterations, &mut out)
        .map_err(|e| anyhow::anyhow!("pbkdf2: {e}"))?;
    Ok(out)
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.is_ascii() { bail!("non-ASCII hex input"); }
    if s.len() % 2 != 0 { bail!("odd hex length"); }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("bad hex"))
        .collect()
}

/// The arming state, written by dsctl (and read by an auditor). Mirrors the scaffold STATE file.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct State {
    pub armed: bool,
    pub pam_integrated: bool,
    pub recovery_keyslot: Option<u8>,
    pub recovery_device: Option<String>,
}

// ---- authentication-attempt policy (3-strikes-then-wipe; DEATHSTROKE.md §11.F) ----
//
// A CONSECUTIVE wrong-password counter, persisted so it survives a reboot/power-cycle (an attacker
// must not reset it by rebooting). It is reset on ANY successful auth, so a legitimate fat-finger
// followed by a success clears it and only sustained failure (an attacker) escalates.
//   at `lockout_at` consecutive failures  -> lock out for a cooldown + show the wipe WARNING
//   at `wipe_at`    consecutive failures  -> fire the crypto-erase
// Thresholds are configurable; defaults below. The counter file is one line: "count last_fail_unix".

pub const DEFAULT_LOCKOUT_AT: u32 = 3;   // lockout + wipe warning
pub const DEFAULT_WIPE_AT: u32 = 5;      // continued failures past the warning -> wipe
pub const DEFAULT_COOLDOWN_SECS: u64 = 300;
pub const DEFAULT_MAX_PROMPTS: u32 = 5;
pub const MAX_WIPE_AT: u32 = 20;
pub const MAX_LOCKOUT_DELAY_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub lockout_at: u32,
    pub wipe_at: u32,
    pub lockout_delay: u64,
    pub max_prompts: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            lockout_at: DEFAULT_LOCKOUT_AT,
            wipe_at: DEFAULT_WIPE_AT,
            lockout_delay: 0,
            max_prompts: DEFAULT_MAX_PROMPTS,
        }
    }
}

impl Policy {
    pub fn validate(self) -> Result<Self> {
        if self.lockout_at == 0
            || self.lockout_at >= self.wipe_at
            || self.wipe_at > MAX_WIPE_AT
            || self.max_prompts == 0
            || self.max_prompts > MAX_WIPE_AT
            || self.wipe_at > self.max_prompts
            || self.lockout_delay > MAX_LOCKOUT_DELAY_SECS
        {
            bail!(
                "invalid policy: require 1 <= lockout_at < wipe_at <= max_prompts <= {MAX_WIPE_AT}, and lockout_delay <= {MAX_LOCKOUT_DELAY_SECS}"
            );
        }
        Ok(self)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut policy = Policy::default();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .context("policy lines must be key=value")?;
            let key = key.trim();
            let value = value.trim();
            match key {
                "lockout_at" => policy.lockout_at = value.parse().context("bad lockout_at")?,
                "wipe_at" => policy.wipe_at = value.parse().context("bad wipe_at")?,
                "lockout_delay" => {
                    policy.lockout_delay = value.parse().context("bad lockout_delay")?
                }
                "max_prompts" => policy.max_prompts = value.parse().context("bad max_prompts")?,
                other => bail!("unknown policy key {other}"),
            }
        }
        policy.validate()
    }
}

pub fn attempts_path() -> String { format!("{}/attempts", state_dir()) }

/// The persisted attempt state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attempts { pub count: u32, pub last_fail: u64 }

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Read the counter. A missing file is a clean start; malformed or unreadable armed state is an
/// error and must never silently weaken the attempt limit.
pub fn read_attempts() -> Result<Attempts> {
    match fs::read_to_string(attempts_path()) {
        Ok(s) => {
            let mut it = s.split_whitespace();
            let count = it.next().context("attempt counter missing count")?.parse().context("bad attempt count")?;
            let last_fail = it.next().context("attempt counter missing timestamp")?.parse().context("bad attempt timestamp")?;
            if it.next().is_some() { bail!("attempt counter has trailing fields"); }
            Ok(Attempts { count, last_fail })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Attempts::default()),
        Err(e) => Err(e).context("read attempt counter"),
    }
}

fn write_attempts(a: Attempts) -> Result<()> {
    let path = attempts_path();
    atomic_write(Path::new(&path), format!("{} {}\n", a.count, a.last_fail).as_bytes(), 0o600)
}

/// Record one consecutive failure; returns the new count. fsync'd so a power cut cannot lose it.
pub fn record_failure() -> Result<u32> {
    let mut a = read_attempts()?;
    a.count = a.count.saturating_add(1);
    a.last_fail = now_secs();
    write_attempts(a)?;
    Ok(a.count)
}

/// Reset the counter (call on ANY successful auth).
pub fn reset_attempts() -> Result<()> {
    match fs::remove_file(attempts_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove attempt counter"),
    }
}

/// Seconds of lockout remaining, if currently locked out (count >= lockout_at and within cooldown).
pub fn lockout_remaining(lockout_at: u32, cooldown: u64) -> Result<Option<u64>> {
    let a = read_attempts()?;
    if a.count < lockout_at { return Ok(None); }
    let elapsed = now_secs().saturating_sub(a.last_fail);
    Ok(if elapsed < cooldown { Some(cooldown - elapsed) } else { None })
}

/// Replace a root-owned state/config file without a window of broad permissions. The file and its
/// parent directory are fsync'd so a successful return means the rename is durable.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    if !parent.exists() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", parent.display()))?;
    }
    if fs::symlink_metadata(parent)?.file_type().is_symlink() {
        bail!("refusing symlink parent {}", parent.display());
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() { bail!("refusing symlink target {}", path.display()); }
    }
    let name = path.file_name().and_then(|n| n.to_str()).context("invalid file name")?;
    let tmp = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(data).with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all().with_context(|| format!("fsync {}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
        let dir = fs::File::open(parent).with_context(|| format!("open {}", parent.display()))?;
        dir.sync_all().with_context(|| format!("fsync {}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Whether the current count means we should fire the wipe.
pub fn should_wipe(count: u32, wipe_at: u32) -> bool { count >= wipe_at }

/// Whether this failure is the one that first crosses the lockout line (=> show the wipe warning).
pub fn crossed_lockout(count: u32, lockout_at: u32) -> bool { count >= lockout_at }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_verify() {
        // low iterations here only to keep the test fast; production uses DEFAULT_ITERATIONS.
        let h = DuressHash::derive(b"correct horse", MIN_ITERATIONS).unwrap();
        assert!(h.verify(b"correct horse").unwrap(), "the right code must verify");
        assert!(!h.verify(b"correct hors").unwrap(), "a near-miss must NOT verify");
        assert!(!h.verify(b"").unwrap(), "empty must not verify");
    }

    #[test]
    fn serialize_parse_roundtrip() {
        let h = DuressHash::derive(b"duress-123", MIN_ITERATIONS).unwrap();
        let s = h.serialize();
        assert!(s.starts_with(&format!("pbkdf2_sha256${MIN_ITERATIONS}$")));
        let back = DuressHash::parse(&s).unwrap();
        assert_eq!(h, back);
        assert!(back.verify(b"duress-123").unwrap());
    }

    #[test]
    fn distinct_salts_give_distinct_hashes() {
        let a = DuressHash::derive(b"same", MIN_ITERATIONS).unwrap();
        let b = DuressHash::derive(b"same", MIN_ITERATIONS).unwrap();
        assert_ne!(a.salt, b.salt, "each enrollment must use a fresh salt");
        assert_ne!(a.hash, b.hash, "same code + different salt => different hash");
    }

    #[test]
    fn pbkdf2_matches_rfc6070_vector() {
        // RFC 6070 is HMAC-SHA1; RustCrypto's own SHA-256 vector (c=1) is used here to pin our wiring.
        // password="password", salt="salt", c=1, dkLen=32.
        let out = pbkdf2_sha256(b"password", b"salt", 1).unwrap();
        assert_eq!(hex(&out), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    }

    #[test]
    fn attempt_counter_increments_resets_locks_and_wipes() {
        // isolate the counter file to a temp dir via DS_STATE_DIR so the test never touches real state.
        let dir = format!("/tmp/ds-core-attempts.{}", std::process::id());
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("DS_TEST_MODE", "1");
        std::env::set_var("DS_STATE_DIR", &dir);
        reset_attempts().unwrap();

        assert_eq!(read_attempts().unwrap().count, 0, "starts at zero");
        assert_eq!(record_failure().unwrap(), 1);
        assert_eq!(record_failure().unwrap(), 2, "consecutive failures accumulate");
        // not yet locked out at 2 with a threshold of 3
        assert!(lockout_remaining(DEFAULT_LOCKOUT_AT, DEFAULT_COOLDOWN_SECS).unwrap().is_none());
        let c3 = record_failure().unwrap();
        assert_eq!(c3, 3);
        assert!(crossed_lockout(c3, DEFAULT_LOCKOUT_AT), "3rd failure crosses the lockout line (warn)");
        assert!(!should_wipe(c3, DEFAULT_WIPE_AT), "3 is lockout+warn, not yet wipe");
        // now locked out within the cooldown window
        assert!(lockout_remaining(DEFAULT_LOCKOUT_AT, DEFAULT_COOLDOWN_SECS).unwrap().is_some());
        // a success resets everything
        reset_attempts().unwrap();
        assert_eq!(read_attempts().unwrap().count, 0, "any success clears the counter");
        assert!(lockout_remaining(DEFAULT_LOCKOUT_AT, DEFAULT_COOLDOWN_SECS).unwrap().is_none());
        // continued failures reach the wipe threshold
        let mut last = 0;
        for _ in 0..DEFAULT_WIPE_AT { last = record_failure().unwrap(); }
        assert_eq!(last, DEFAULT_WIPE_AT);
        assert!(should_wipe(last, DEFAULT_WIPE_AT), "reaching wipe_at means fire the wipe");
        // an expired cooldown is no longer a lockout (cooldown of 0 seconds)
        assert!(lockout_remaining(DEFAULT_LOCKOUT_AT, 0).unwrap().is_none(), "past the cooldown, not locked");

        std::fs::write(format!("{dir}/attempts"), "garbage\n").unwrap();
        assert!(read_attempts().is_err(), "corrupt armed counter must not become zero");

        std::env::remove_var("DS_STATE_DIR");
        std::env::remove_var("DS_TEST_MODE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_unbounded_verifier_cost() {
        assert!(DuressHash::derive(b"x", MIN_ITERATIONS - 1).is_err());
        let salt = "00".repeat(SALT_LEN);
        let hash = "00".repeat(HASH_LEN);
        assert!(DuressHash::parse(&format!("pbkdf2_sha256$0${salt}${hash}")).is_err());
        assert!(DuressHash::parse(&format!(
            "pbkdf2_sha256${}${salt}${hash}",
            MAX_ITERATIONS + 1
        ))
        .is_err());
    }

    #[test]
    fn malformed_unicode_verifier_is_an_error() {
        assert!(unhex("0\u{e9}0").is_err());
        assert!(DuressHash::parse(&format!(
            "pbkdf2_sha256${MIN_ITERATIONS}$0\u{e9}0${}", "00".repeat(HASH_LEN)
        )).is_err());
    }

    #[test]
    fn policy_is_strict_and_bounded() {
        let p = Policy::parse("lockout_at=3\nwipe_at=5\nlockout_delay=0\nmax_prompts=5\n").unwrap();
        assert_eq!(p, Policy::default());
        assert!(Policy::parse("lockout_at=0\nwipe_at=5\nmax_prompts=5\n").is_err());
        assert!(Policy::parse("lockout_at=5\nwipe_at=5\nmax_prompts=5\n").is_err());
        assert!(Policy::parse("lockout_at=3\nwipe_at=5\nmax_prompts=4\n").is_err());
        assert!(Policy::parse("lockout_at=3\nwipe_at=21\nmax_prompts=21\n").is_err());
        assert!(Policy::parse("lockout_at=3\nwipe_at=5\nunknown=1\n").is_err());
    }

}
