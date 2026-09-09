# Pre-boot attempt-limit gate

The retired harness in this directory predated verified daily/recovery slot metadata and expected all
keyslots to disappear. It is incompatible with the recovery-preserving product contract and must not
be cited as current evidence.

Counter parsing, bounded policy, persistence behavior, corruption handling, and trigger selection are
covered by `ds-unlock --self-test`, the Rust unit tests, and the safe loopback/PAM suites. The actual
pre-boot prompt and reboot-persistence behavior must be exercised through the real installed
initramfs as part of [`../boot-resume/README.md`](../boot-resume/README.md).
