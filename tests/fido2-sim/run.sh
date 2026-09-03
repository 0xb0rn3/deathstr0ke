#!/usr/bin/env bash
# Simulated-FIDO2 keyslot test: prove that `dsctl enroll fido2 --simulate` enrolls a token-style secret
# as a LUKS keyslot that then UNLOCKS the device. Runs on a /tmp loopback (safe anywhere); needs root
# and the disposable marker. Does NOT exercise the physical USB handshake (needs a real key / VM sim).
set -u
P(){ echo "  PASS  $*"; }; F(){ echo "  FAIL  $*"; FAILED=1; }; FAILED=0
DSCTL=${DSCTL:-/tmp/dsctl}
export DS_STATE_DIR=/tmp/ds-fido2-state
rm -rf "$DS_STATE_DIR"; mkdir -p "$DS_STATE_DIR"
# the guard reads the real path, so mark disposable there
install -d -m700 /etc/arxos/deathstroke 2>/dev/null
touch /etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY

W=/tmp/ds-fido2; rm -rf "$W"; mkdir -p "$W"
printf 'daily-pass' > "$W/pw"
dd if=/dev/zero of="$W/vault.img" bs=1M count=32 status=none
LOOP=$(losetup -f --show "$W/vault.img")
cryptsetup luksFormat --type luks2 --batch-mode "$LOOP" "$W/pw" >/dev/null 2>&1
b=$(cryptsetup luksDump "$LOOP" | grep -cE '^  [0-9]+: luks2')
echo "  loop=$LOOP  slots_before=$b"

echo "== enroll simulated fido2 (adds a token-secret keyslot; passphrase authorises) =="
"$DSCTL" enroll fido2 --device "$LOOP" --simulate --existing-keyfile "$W/pw" >/tmp/f2.log 2>&1
sed 's/^/    /' /tmp/f2.log
a=$(cryptsetup luksDump "$LOOP" | grep -cE '^  [0-9]+: luks2')
[ "$a" -eq $((b+1)) ] && P "a new keyslot was added ($b -> $a)" || F "no keyslot added ($b -> $a)"
[ -f "$DS_STATE_DIR/fido2-sim.key" ] && P "token secret (keyfile) present" || F "no keyfile"

echo "== the token secret UNLOCKS the device =="
cryptsetup open --test-passphrase --key-file "$DS_STATE_DIR/fido2-sim.key" "$LOOP" 2>/dev/null \
  && P "simulated FIDO2 secret opens the LUKS device" || F "token secret did not open it"
echo "== the original passphrase STILL works (factor coexists, nothing removed) =="
cryptsetup open --test-passphrase --key-file "$W/pw" "$LOOP" 2>/dev/null \
  && P "passphrase still opens it (factor coexists)" || F "passphrase broke"
echo "== a wrong secret does NOT open it =="
printf 'wrong-secret-000000000000000000' > "$W/bad"
cryptsetup open --test-passphrase --key-file "$W/bad" "$LOOP" 2>/dev/null \
  && F "a wrong secret opened it (should not)" || P "wrong secret correctly rejected"

losetup -d "$LOOP" 2>/dev/null; rm -rf "$W" "$DS_STATE_DIR"
echo
[ $FAILED -eq 0 ] && echo "FIDO2-SIM: ALL PASS" || echo "FIDO2-SIM: FAILURES ABOVE"
