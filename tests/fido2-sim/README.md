# simulated FIDO2 keyslot test

Proves `dsctl enroll fido2 --simulate` enrolls a token-style secret as a LUKS keyslot that unlocks the
device, that the passphrase still works alongside it, and that a wrong secret is rejected. Runs on a
/tmp loopback (safe anywhere) as root on a machine marked disposable.

Does NOT exercise the physical USB handshake (`systemd-cryptenroll --fido2` over real USB-HID) -- that
needs a real YubiKey, or the VM USB-HID simulation. This proves the keyslot mechanics + our code.

    DSCTL=/path/to/dsctl sudo bash run.sh    # expect FIDO2-SIM: ALL PASS
