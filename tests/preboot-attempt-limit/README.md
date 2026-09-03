# pre-boot attempt-limit test (adversarial)

Proves the pre-boot LUKS 3-strikes-then-wipe (ds-unlock, the initramfs unlock manager) survives the
key exploit: an attacker CANNOT reset the counter by power-cycling. Runs ds-unlock against a real LUKS
scratch with its counter on a real FAT "ESP" (a persistent 2nd disk), across FIVE actual VM reboots.

Verifies (10/10): counter climbs on wrong tries and PERSISTS across reboots; a correct passphrase
resets it; the reset persists; continued failures reach wipe_at and crypto-erase the scratch; a duress
code wipes instantly. Scratch-intact-before-wipe is asserted so an empty device cannot fake a pass.

Needs qemu+KVM, an Arch ISO, and the extracted kernel/initramfs (see the boot-resume test README for the
one-time setup). Disks are identified by /dev/disk/by-id/virtio-<serial>, robust against enumeration
order. `python3 preboot-test.py` -> expect PREBOOT-ATTEMPT-LIMIT: ALL PASS.

HONEST LIMIT (documented in ds-unlock): the ESP is plaintext, so an OFFLINE attacker who images the disk
can reset the counter or delete the duress verifier. This layer defends a powered-off machine an
adversary BOOTS and types at. The offline-imaging bypass is closed only by TPM-sealed measured boot +
a signed initramfs (DEATHSTROKE.md §12.2 A), which forces the adversary onto this path.
