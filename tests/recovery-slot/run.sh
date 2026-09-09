#!/usr/bin/env bash
# Safe loopback proof for recovery enrollment and slot identification. Never targets a host disk.
set -euo pipefail
DSCTL=${DSCTL:?set DSCTL to the dsctl binary under test}
DSE=${DSE:?set DSE to the ds-erase binary under test}
export DS_TEST_MODE=1
export DS_STATE_DIR=/tmp/ds-recovery-slot-state.$$
WORK=/tmp/ds-recovery-slot.$$
MARKER=/etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY
made_marker=0
loop=""
cleanup(){
    [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    rm -rf "$WORK" "$DS_STATE_DIR"
    if [ "$made_marker" = 1 ]; then rm -f "$MARKER"; fi
    return 0
}
trap cleanup EXIT

mkdir -p "$WORK" "$DS_STATE_DIR" /etc/arxos/deathstroke
if [ ! -e "$MARKER" ]; then touch "$MARKER"; made_marker=1; fi
printf 'daily-test-key' > "$WORK/daily"
printf 'offline-recovery-test-key' > "$WORK/recovery"
dd if=/dev/zero of="$WORK/vault.img" bs=1M count=32 status=none
loop=$(losetup -f --show "$WORK/vault.img")
cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --batch-mode "$loop" "$WORK/daily" >/dev/null

"$DSCTL" enroll-recovery --device "$loop" \
    --existing-keyfile "$WORK/daily" --new-keyfile "$WORK/recovery"

[ "$(cat "$DS_STATE_DIR/daily.slot")" = 0 ]
[ "$(cat "$DS_STATE_DIR/recovery.slot")" = 1 ]
cryptsetup open --test-passphrase --key-file "$WORK/daily" --key-slot 0 "$loop"
cryptsetup open --test-passphrase --key-file "$WORK/recovery" --key-slot 1 "$loop"
mkdir -p "$WORK/deathstroke"
"$DSE" --fire --device "$loop" --journal "$WORK/deathstroke/inprogress" \
    --header-scan "$WORK/deathstroke" --test-no-poweroff
if cryptsetup open --test-passphrase --key-file "$WORK/daily" "$loop" 2>/dev/null; then
    echo "daily credential still opens after trigger" >&2; exit 1
fi
cryptsetup open --test-passphrase --key-file "$WORK/recovery" "$loop"
[ ! -e "$WORK/deathstroke/inprogress" ]
printf 'RECOVERY-SLOT: ALL PASS (daily slot removed, recovery survives, journal cleared)\n'
