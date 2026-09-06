<div align="center">

<img src="branding.png" alt="deathstr0ke" width="100%">

# deathstr0ke

**Duress crypto-erase and anti-forensics for Linux.**

Rust · LUKS keyslot destruction · PAM duress code · TPM measured-boot seal · fail-closed

<sub>Every destructive path stays inert until you run <code>dsctl arm</code>; <code>dsctl disarm</code> re-engages the guard.</sub>

</div>

## Overview

deathstr0ke is a last-resort protection layer for an encrypted Linux machine. Under
coercion or seizure it renders the disk's data cryptographically unrecoverable in
milliseconds by destroying the LUKS keyslots, so there is no slow overwrite to wait
on and nothing to interrupt. A recovery key enrolled ahead of time is the only way
back in.

It fires from a duress phrase entered at any password prompt — the pre-boot disk
unlock, the login screen, the lock screen, or a terminal — which looks like an ordinary
wrong password and never opens a session. Those same surfaces enforce an attempt limit:
after a set number of wrong tries they wipe as well. A duress match tears down the
network state, closes the session, and destroys the keyslots.

The crypto path runs on stock `cryptsetup` (`luksErase`, `luksKillSlot`), so there is
no patched crypto to carry across upstream releases. The whole toolkit, including the
PAM module, is written in Rust.

## TPM measured-boot seal

The hard case is an offline adversary who never enters a prompt, so deathstr0ke can seal
a LUKS keyslot to the **TPM, bound to the boot-chain PCRs**. The disk then unlocks only
on the unmodified ArxOS boot chain: booting a foreign kernel to skip the attempt counter,
or editing the ESP, changes the PCRs and loses the key — which forces the adversary back
onto the attempt-limited path. A **PIN** is required, so mere possession of the
powered-off machine does not unlock it, and a non-TPM factor (passphrase, optional FIDO2)
is always kept so a TPM clear or mainboard swap never bricks the owner. `dsctl tpm-check`
audits readiness (TPM device, `systemd-cryptenroll`, Secure Boot / PCR-7 state) without
changing anything.

This is the userspace half of the kernel's measured-boot support — `linux-arxos` ships
`TCG_TPM` and IMA.

## Limits

deathstr0ke does not defeat physics and does not pretend to. A hard power cut mid-run is
survived by journaling progress and resuming on the next boot, with the drive held locked
until the work finishes. RAM captured before the code is ever entered is outside its reach
— though the `linux-arxos` `init_on_free` + hibernation-off hardening narrows that window.
These are stated plainly rather than hidden.

## Components

| Component | Role |
|-----------|------|
| `ds-core` | Duress-code hashing (PBKDF2-HMAC-SHA256), constant-time verification, secret zeroing |
| `ds-erase` | LUKS crypto-erase: kill the in-use keyslot, or erase every slot |
| `dsctl` | Setup and control: set the duress code, enroll a recovery key, seal to the TPM, arm, disarm, status |
| `pam_ds` | PAM module that recognises the duress code at every prompt, with a consecutive-failure attempt limit |
| `ds-unlock` | Pre-boot LUKS unlock manager (initramfs hook): duress phrase, attempt limit, and unlock before root mounts |

## Usage

Set it up and arm it with `dsctl`:

```sh
sudo dsctl set-duress          # set the duress phrase (hashed with PBKDF2, never stored in clear)
sudo dsctl enroll-recovery     # enroll the recovery key — the only way back in after a wipe
sudo dsctl tpm-check           # audit TPM / Secure Boot readiness (read-only)
sudo dsctl seal-tpm            # seal a keyslot to the TPM + boot PCRs, protected by a PIN
sudo dsctl arm                 # drop the guard: duress + attempt-limit go live
sudo dsctl status              # what is armed, which slots, TPM state
sudo dsctl disarm              # re-engage the guard (non-destructive)
```

`arm` / `disarm` is the switch between inert and live; while disarmed, every destructive path
refuses to run.

## The arm guard

Every destructive operation refuses to run unless the machine is armed (`dsctl arm`), so it can
never fire by accident on a system you have not explicitly armed. `ds-erase --self-test` exercises
the erase path against a disposable loopback volume it creates and removes on its own.

## Build & install

```sh
cargo build --release
cargo test -p ds-core
sudo ./install.sh        # binaries + PAM module + the pre-boot mkinitcpio hook (inert until armed)
```

`install.sh` places the `ds-*` binaries and `pam_ds.so`, and installs the `mkinitcpio`
hook (`mkinitcpio/{install,hooks}/deathstroke`) that runs `ds-unlock` before the root
filesystem is mounted. On ArxOS the installer is also offered as an opt-in during setup;
everything stays inert until `dsctl arm`.

## Status

Complete. `ds-core`, `ds-erase`, `pam_ds`, `dsctl` (with TPM seal / check), and the `ds-unlock`
pre-boot manager are all implemented, with the mkinitcpio hook and installer in place. The
full-system suite — duress-code fire, LUKS crypto-erase, recovery survival, and clean disarm —
has passed on a disposable VM.

---

<div align="center">
<sub>An <a href="https://arxos.uk">ArxOS</a> project, by <a href="https://stingraylabs.pages.dev">Stingray Labs</a>.</sub>
</div>
