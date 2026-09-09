# Boot-resume acceptance gate

The previous files in this directory installed a stand-in initramfs hook that touched and removed a
fake flag. They did not execute `ds-unlock`, `ds-erase --resume`, validate a journal, or destroy a
keyslot. They were removed so they cannot be mistaken for product verification.

The journal state machine is exercised safely by the Rust tests and the loopback suites. The actual
pre-root boot path must be verified from a newly rebuilt ArxOS ISO in a disposable QEMU/KVM guest.
That release gate is intentionally not replaced by another simulation.

## Required VM evidence

1. Install the rebuilt ISO through Calamares with LUKS, DEATHSTROKE enabled, and a new non-default
   user. Confirm the exact UUID-backed `/`, `/boot`, and `/boot/efi` fstab entries before reboot.
2. Confirm `/boot/efi/deathstroke/` contains `armed`, `duress.hash`, `config`, `counter`,
   `daily.slot`, and `recovery.slot`; no `inprogress` journal exists before a trigger.
3. Boot normally through the real `mkinitcpio/hooks/deathstroke` and `ds-unlock`; confirm the daily
   credential opens the recorded daily slot and reaches the installed desktop.
4. On a scratch copy of the guest disk, interrupt the actor after each durable phase (`prepared`,
   `backups_handled`, and `keyslots_destroyed`). Reboot after each interruption. The real initramfs
   must detect `/boot/efi/deathstroke/inprogress`, validate its device/slot/mapping against trusted
   boot configuration, and refuse ordinary root unlock until `ds-erase --resume` finishes.
5. Confirm the daily credential no longer opens the LUKS container, the recorded offline recovery
   credential still opens its distinct slot, and the journal is durably removed after the test-only
   no-poweroff completion. A production trigger must instead quiesce the seat/network and power off.
6. Repeat normal and duress authentication through the installed login, lock, and `sudo` PAM
   surfaces, then run `dsctl disarm` and prove exact PAM restoration plus a rebuilt inert initramfs.
7. Save serial logs, keyslot inventories, journal snapshots, first-boot screenshots, and ISO SHA-256
   in the ArxOS coordination Markdown. Do not mark the feature release-ready without that evidence.

Never point the acceptance procedure at a host disk or a VM containing non-disposable data.
