<div align="center">

<img src="branding.png" alt="deathstr0ke" width="100%">

# deathstr0ke

**Duress crypto-erase and anti-forensics for Linux.**

Rust · LUKS keyslot destruction · PAM duress code · fail-closed

<sub>Work in progress. The destructive paths are locked behind an explicit guard while the tool is under development.</sub>

</div>

## Overview

deathstr0ke is a last-resort protection layer for an encrypted Linux machine. Under
coercion or seizure it renders the disk's data cryptographically unrecoverable in
milliseconds by destroying the LUKS keyslots, so there is no slow overwrite to wait
on and nothing to interrupt. A recovery key enrolled ahead of time is the only way
back in.

It fires from a duress code entered at the login or unlock prompt, which looks like
an ordinary wrong password and never opens a session, or from a panic command. The
sequence tears down the network state, closes the session, and destroys the keyslots.

The crypto path runs on stock `cryptsetup` (`luksErase`, `luksKillSlot`), so there is
no patched crypto to carry across upstream releases. The whole toolkit, including the
PAM module, is written in Rust.

## Limits

deathstr0ke does not defeat physics and does not pretend to. A hard power cut mid-run
is survived by journaling progress and resuming on the next boot, with the drive held
locked until the work finishes. RAM captured before the code is ever entered is outside
its reach. These are stated plainly rather than hidden.

## Components

| Component | Role |
|-----------|------|
| `ds-core` | Duress-code hashing (PBKDF2-HMAC-SHA256), constant-time verification, secret zeroing |
| `ds-erase` | LUKS crypto-erase: kill the in-use keyslot, or erase every slot |
| `dsctl` | Setup and control: set the duress code, enroll a recovery key, arm, disarm, status |
| `pam_ds` | PAM module that recognises the duress code at the prompt |

## Safety during development

Every destructive operation refuses to run unless a marker file is present, so it
cannot fire on a working machine while the tool is being built. `ds-erase --self-test`
exercises the erase path against a disposable loopback volume it creates and removes
on its own.

## Build

```sh
cargo build --release
cargo test -p ds-core
```

## Status

`ds-core` and the `ds-erase` crypto path are implemented and tested. Arming, the PAM
module, and boot-time resume are in progress.

---

<div align="center">
<sub>Part of the ArxOS project.</sub>
</div>
