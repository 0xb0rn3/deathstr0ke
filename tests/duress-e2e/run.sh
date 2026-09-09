#!/usr/bin/env bash
# End-to-end DEATHSTROKE duress chain against a disposable /tmp loopback device.
# Proves: entering the duress code through the REAL PAM stack -> pam_ds -> REAL ds-erase -> a scratch
# LUKS device is crypto-erased. A normal password logs in and leaves the scratch intact. No stand-ins.
# The test never installs/replaces product binaries or PAM modules. It creates one isolated PAM
# service and requires explicit paths to the build artifacts under test.
set -u
DSCTL=${DSCTL:?set DSCTL to the dsctl binary under test}
DSE=${DSE:?set DSE to the ds-erase binary under test}
MOD=${MOD:?set MOD to libpam_ds.so under test}
HARNESS=${HARNESS:?set HARNESS to the PAM harness}
CODE="redoktober-duress"; USERPW="daily-test-password"
export DS_TEST_MODE=1
export DS_STATE_DIR=/tmp/ds-e2e-state.$$
P(){ echo "  PASS  $*"; }; F(){ echo "  FAIL  $*"; FAILED=1; }; FAILED=0
W=/tmp/ds-e2e.$$
SVC=/etc/pam.d/ds-e2e-$$
SERVICE=${SVC##*/}
MARKER=/etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY
made_marker=0
LOOP=""
cleanup(){
  rm -f "$SVC"
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
  rm -rf "$W" "$DS_STATE_DIR"
  if [ "$made_marker" = 1 ]; then rm -f "$MARKER"; fi
  return 0
}
trap cleanup EXIT

echo "== isolated test setup =="
mkdir -p "$W" "$DS_STATE_DIR" /etc/arxos/deathstroke
if [ ! -e "$MARKER" ]; then touch "$MARKER"; made_marker=1; fi

echo "== set duress code (stored as hash) =="
printf '%s\n%s\n' "$CODE" "$CODE" | "$DSCTL" set-duress >/dev/null 2>&1
test -f "$DS_STATE_DIR/duress.hash" && P "duress code enrolled (hash only)" || F "no duress hash"

echo "== scratch LUKS target (NOT the VM root) =="
printf 'unlock-key' > "$W/key"
printf 'offline-recovery-key' > "$W/recovery"
dd if=/dev/zero of="$W/vault.img" bs=1M count=32 status=none
LOOP=$(losetup -f --show "$W/vault.img")
cryptsetup luksFormat --type luks2 --batch-mode "$LOOP" "$W/key" >/dev/null 2>&1
"$DSCTL" enroll-recovery --device "$LOOP" --existing-keyfile "$W/key" --new-keyfile "$W/recovery" >"$W/enroll.log" 2>&1 || {
  sed 's/^/    /' "$W/enroll.log"; exit 1;
}
slots(){ cryptsetup luksDump "$LOOP" 2>/dev/null | grep -cE '^  [0-9]+: luks2'; }
echo "  scratch target=$LOOP  slots=$(slots)"

echo "== isolated PAM service + real guarded erase actor =="
mkdir -p "$W/deathstroke"
FIRE="$W/fire.sh"
cat > "$FIRE" <<EOF
#!/bin/sh
exec "$DSE" --fire --device "$LOOP" --journal "$W/deathstroke/inprogress" --header-scan "$W/deathstroke" --test-no-poweroff
EOF
chmod 700 "$FIRE"
export DS_FIRE_CMD="$FIRE"
PERMIT=$(ls /usr/lib/security/pam_permit.so /lib/security/pam_permit.so 2>/dev/null | head -1)
PAMEXEC=$(ls /usr/lib/security/pam_exec.so /lib/security/pam_exec.so 2>/dev/null | head -1)
CHECK="$W/pwcheck.sh"
cat > "$CHECK" <<EOF
#!/bin/sh
read -r pw
[ "\$pw" = "$USERPW" ]
EOF
chmod 700 "$CHECK"
cat > "$SVC" <<EOF
auth [success=ignore ignore=ignore default=die] $MOD
auth [success=1 default=ignore] $PAMEXEC expose_authtok quiet $CHECK
auth [default=die] $MOD authfail
auth sufficient $MOD authsucc
auth required $PERMIT
account required $PERMIT
EOF

echo
echo "== CASE 1: NORMAL password -> logs in, does NOT fire, scratch intact =="
b=$(slots)
"$HARNESS" "$SERVICE" tester "$USERPW" >"$W/h1" 2>&1; rc=$?
sleep 3
a=$(slots)
sed 's/^/    /' "$W/h1"
{ [ $rc -eq 0 ] && [ "$a" = "$b" ] && [ "$a" -ge 1 ]; } \
  && P "normal password logs in (rc=0); scratch UNTOUCHED ($a slots)" \
  || F "normal case wrong (rc=$rc slots $b->$a)"

echo
echo "== CASE 2: DURESS code -> auth FAILS + daily slot dies while recovery survives =="
"$HARNESS" "$SERVICE" tester "$CODE" >"$W/h2" 2>&1; rc=$?
# pam_ds spawns ds-erase asynchronously (auth must not hang); poll for the erase.
for i in $(seq 1 30); do [ "$(slots)" = 1 ] && break; sleep 1; done
a=$(slots)
sed 's/^/    /' "$W/h2"
recovery_ok=0; daily_gone=0
cryptsetup open --test-passphrase --key-file "$W/recovery" "$LOOP" 2>/dev/null && recovery_ok=1
cryptsetup open --test-passphrase --key-file "$W/key" "$LOOP" 2>/dev/null || daily_gone=1
{ [ $rc -ne 0 ] && [ "$a" = 1 ] && [ "$recovery_ok" = 1 ] && [ "$daily_gone" = 1 ]; } \
  && P "DURESS code: auth failed; daily slot destroyed; offline recovery slot survives" \
  || F "duress chain wrong (rc=$rc, slots=$a)"

echo
echo "== cleanup =="
[ $FAILED -eq 0 ] && echo "E2E-DURESS: ALL PASS" || echo "E2E-DURESS: FAILURES ABOVE"
exit "$FAILED"
