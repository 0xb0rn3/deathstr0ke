// ds-core: the shared, non-destructive logic. The duress-code hash (derive and constant-time
// verify) and the on-disk state paths. Pure and unit-testable; nothing here touches LUKS, PAM, or
// the disk beyond the state files. The components that do destructive work (ds-erase, the arming in
// dsctl) build on this. No hand-rolled crypto: PBKDF2-HMAC-SHA256 from the RustCrypto crates,
// constant-time compare from `subtle`, secrets scrubbed with `zeroize`.

use anyhow::{bail, Context, Result};
use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Reserved on-disk locations (match the install.sh layout).
pub const CONFIG_DIR: &str = "/etc/arxos/deathstroke";
pub const STATE_DIR: &str = "/var/lib/arxos/deathstroke";
pub const LIB_DIR: &str = "/usr/lib/arxos/deathstroke";

/// The state directory. `DS_STATE_DIR` overrides it, which keeps tests off the real system paths and
/// lets an unprivileged harness exercise the same code. Production leaves it unset (the default).
pub fn state_dir() -> String {
    std::env::var("DS_STATE_DIR").unwrap_or_else(|_| STATE_DIR.to_string())
}
pub fn duress_hash_path() -> String { format!("{}/duress.hash", state_dir()) }
pub fn state_path() -> String { format!("{}/STATE", state_dir()) }
pub fn in_progress_path() -> String { format!("{}/in-progress", state_dir()) }

/// KDF cost. 600k PBKDF2-HMAC-SHA256 iterations is the current OWASP-class floor; the value is stored
/// alongside the hash so it can be raised later without invalidating existing enrollments.
pub const DEFAULT_ITERATIONS: u32 = 600_000;
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
        let salt_v = unhex(f[2])?; let hash_v = unhex(f[3])?;
        if salt_v.len() != SALT_LEN { bail!("bad salt length"); }
        if hash_v.len() != HASH_LEN { bail!("bad hash length"); }
        let mut salt = [0u8; SALT_LEN]; salt.copy_from_slice(&salt_v);
        let mut hash = [0u8; HASH_LEN]; hash.copy_from_slice(&hash_v);
        Ok(Self { iterations, salt, hash })
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_verify() {
        // low iterations here only to keep the test fast; production uses DEFAULT_ITERATIONS.
        let h = DuressHash::derive(b"correct horse", 1000).unwrap();
        assert!(h.verify(b"correct horse").unwrap(), "the right code must verify");
        assert!(!h.verify(b"correct hors").unwrap(), "a near-miss must NOT verify");
        assert!(!h.verify(b"").unwrap(), "empty must not verify");
    }

    #[test]
    fn serialize_parse_roundtrip() {
        let h = DuressHash::derive(b"duress-123", 2000).unwrap();
        let s = h.serialize();
        assert!(s.starts_with("pbkdf2_sha256$2000$"));
        let back = DuressHash::parse(&s).unwrap();
        assert_eq!(h, back);
        assert!(back.verify(b"duress-123").unwrap());
    }

    #[test]
    fn distinct_salts_give_distinct_hashes() {
        let a = DuressHash::derive(b"same", 1000).unwrap();
        let b = DuressHash::derive(b"same", 1000).unwrap();
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
}
