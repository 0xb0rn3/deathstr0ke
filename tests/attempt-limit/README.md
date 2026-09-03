# attempt-limit test

Proves the 3-strikes-then-wipe policy against REAL PAM in an isolated service (never touches
system-auth). Covers every post-boot surface at once because they all use PAM.

Verifies: correct password authenticates and resets the counter; consecutive wrong tries accumulate; a
correct password after failures resets (fat-finger recovery); at lockout_at (3) a wipe warning shows;
at wipe_at (5) the wipe fires; the duress code wipes instantly regardless of the counter.

Run as root on a machine marked disposable. The "wipe" is a harmless touch (DS_FIRE_CMD).

    MOD=/path/to/libpam_ds.so HARNESS=/path/to/pam-harness sudo bash run.sh   # expect ATTEMPT-LIMIT: ALL PASS

The pam-harness is tests/duress-e2e/pam-harness.c (gcc pam-harness.c -o pam-harness -lpam).
Thresholds: DS_LOCKOUT_AT, DS_WIPE_AT, DS_LOCKOUT_DELAY (0 in tests), DS_COOLDOWN.
