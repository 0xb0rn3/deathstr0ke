# boot-resume integration test

Proves the power-loss / reboot **resume guarantee**: the deathstr0ke initramfs hook runs and re-enters
**before the encrypted root is unlocked**, so cutting power mid-erase does not let an adversary boot
around it. Runs entirely inside a QEMU guest (no host mounts, no host device-mapper), so it is safe to
run on a workstation and it proves the toolkit is OS-independent (this uses vanilla Arch).

## What it does
1. **install** — boots the Arch ISO (direct kernel, serial-driven), installs a LUKS + btrfs system onto
   the guest disk with the deathstr0ke resume hook ordered **before** the `encrypt` hook.
2. **boot A (normal)** — the hook must be silent (no flag) and the system must log in after unlock.
3. **boot B (resume)** — with the in-progress flag set on the ESP, the hook must fire **before** the LUKS
   prompt, write its resumed marker, and clear the flag.

The hook here is a shell stub that prints/records what it did; in production it re-enters
`ds-erase --resume`. The test proves the *ordering + trigger*, which is the hard part.

## Requirements
`qemu-system-x86_64` + KVM, `bsdtar`, and an OVMF firmware (`edk2-ovmf`).

## One-time setup (in this directory, or set `DS_TEST_DIR`)
```sh
# 1. the Arch ISO
curl -LO https://geo.mirror.pkgbuild.com/iso/latest/archlinux-x86_64.iso
# 2. extract its kernel + initramfs without mounting
bsdtar xf archlinux-x86_64.iso arch/boot/x86_64/vmlinuz-linux arch/boot/x86_64/initramfs-linux.img -C .
mkdir -p qemu-boot && mv arch qemu-boot/
# 3. the target disk
qemu-img create -f qcow2 ds-luks-btrfs.qcow2 12G
# 4. the ISO's volume label (drive.py needs it; override with DS_ISO_LABEL)
blkid -o value -s LABEL archlinux-x86_64.iso
```

## Run
```sh
python3 drive.py          # full: install + both boot phases
python3 drive.py boot      # re-run only the two boot phases against the already-installed disk
```
Expected tail: `BOOT-RESUME: ALL PASS` (6/6).

## Env overrides
`DS_TEST_DIR` (work dir) · `DS_ISO` · `DS_DISK` · `DS_ISO_LABEL` · `OVMF_CODE` · `OVMF_VARS`.

## Notes for whoever maintains this
- There are **two** passphrase prompts at boot (the initramfs `encrypt` hook and systemd) — the driver
  feeds the passphrase to every one; never `expect()` on a string that also appears in the typed
  command (use `printf 'X=%s'` output markers, or the command echo false-matches).
- `guest-install.sh` sets a direct public DNS resolver and verifies a mirror is reachable before
  `pacstrap`, because QEMU's built-in DNS forwarder is unreliable.
