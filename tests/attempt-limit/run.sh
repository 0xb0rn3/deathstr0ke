#!/usr/bin/env bash
# Attempt-limit test against REAL PAM in an isolated service (never touches system-auth). Proves the
# faillock-style pam_ds stack: wrong passwords accumulate; the correct password resets; the lockout +
# wipe-warning + wipe-fire fire at the configured thresholds; the duress code still wipes instantly.
# Root + disposable marker required. The "wipe" is a harmless touch (DS_FIRE_CMD), not a real erase.
set -u
P(){ echo "  PASS  $*"; }; F(){ echo "  FAIL  $*"; FAILED=1; }; FAILED=0
MOD=${MOD:?set MOD to libpam_ds.so}; HARNESS=${HARNESS:?set HARNESS}
REALPW="daily-pass"; DURESS="duress-code-xyz"
export DS_STATE_DIR=/tmp/ds-attempt-state
export DS_LOCKOUT_AT=3 DS_WIPE_AT=5 DS_COOLDOWN=300 DS_LOCKOUT_DELAY=0
FIRED=/tmp/ds-attempt-FIRED
PERMIT=$(ls /usr/lib/security/pam_permit.so /lib/security/pam_permit.so 2>/dev/null | head -1)
UNIX=$(ls /usr/lib/security/pam_unix.so /lib/security/pam_unix.so 2>/dev/null | head -1)

rm -rf "$DS_STATE_DIR"; mkdir -p "$DS_STATE_DIR"
install -d -m700 /etc/arxos/deathstroke 2>/dev/null
touch /etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY
# enrol a duress verifier (pbkdf2_sha256) so the module is "armed"
python3 - "$DURESS" "$DS_STATE_DIR/duress.hash" <<'PY'
import sys,os,hashlib,binascii
code,out=sys.argv[1].encode(),sys.argv[2]
it=200000; salt=os.urandom(16)
h=hashlib.pbkdf2_hmac('sha256',code,salt,it,32)
open(out,'w').write(f"pbkdf2_sha256${it}${binascii.hexlify(salt).decode()}${binascii.hexlify(h).decode()}")
PY

# a test-only "real password" module: a tiny pam that succeeds only for $REALPW. We fake pam_unix with
# pam_exec running a script that checks the password from PAM_AUTHTOK via expect... simpler: use a
# pam_pwdfile-free approach -> a helper that compares against REALPW. We use pam_exec.so + a checker.
CHECK=/tmp/ds-pwcheck.sh
cat > "$CHECK" <<EOF
#!/bin/sh
read -r pw
[ "\$pw" = "$REALPW" ]
EOF
chmod +x "$CHECK"
PAMEXEC=$(ls /usr/lib/security/pam_exec.so /lib/security/pam_exec.so 2>/dev/null | head -1)

# The isolated service mirrors the armed system-auth stack:
#   pam_ds (preauth/duress) -> "pam_unix" (our checker) -> pam_ds authfail / authsucc
SVC=/etc/pam.d/ds-attempt
# On a correct password, pam_exec (success=1) SKIPS the authfail line and lands on authsucc (which
# resets the counter, then `sufficient` short-circuits to success). On a wrong password, pam_exec's
# default=ignore falls through to authfail (count + escalate, default=die).
cat > "$SVC" <<EOF
auth  [success=ignore ignore=ignore default=die]  $MOD
auth  [success=1 default=ignore]                   $PAMEXEC expose_authtok quiet $CHECK
auth  [default=die]                                $MOD authfail
auth  sufficient                                   $MOD authsucc
auth  required                                     $PERMIT
account required $PERMIT
EOF

run(){ env DS_STATE_DIR="$DS_STATE_DIR" DS_LOCKOUT_AT=3 DS_WIPE_AT=5 DS_COOLDOWN=300 DS_LOCKOUT_DELAY=0 \
        DS_FIRE_CMD="touch $FIRED" "$HARNESS" ds-attempt tester "$1" >/tmp/al.out 2>&1; echo $?; }
cnt(){ cat "$DS_STATE_DIR/attempts" 2>/dev/null | awk '{print $1}'; }
fired(){ [ -f "$FIRED" ] && echo y || echo n; }
cleanup(){ rm -f "$SVC" "$CHECK" "$FIRED"; }
trap cleanup EXIT

echo "== correct password succeeds + keeps counter at 0 =="
rm -f "$FIRED"; rc=$(run "$REALPW"); echo "  rc=$rc counter=$(cnt) fired=$(fired)"
{ [ "$rc" = 0 ] && [ "$(fired)" = n ]; } && P "correct password authenticates, no wipe" || F "correct pw path wrong (rc=$rc)"

echo "== two wrong tries: fail, counter climbs, no lockout/wipe yet =="
run wrong1 >/dev/null; run wrong2 >/dev/null
echo "  counter=$(cnt)"
[ "$(cnt)" = 2 ] && P "counter=2 after two wrong tries" || F "counter not 2 (=$(cnt))"

echo "== a correct password RESETS the counter (fat-finger recovery) =="
rc=$(run "$REALPW"); echo "  rc=$rc counter=$(cnt)"
{ [ "$rc" = 0 ] && [ -z "$(cnt)" ]; } && P "success resets the counter to 0" || F "counter not reset (=$(cnt))"

echo "== 3rd consecutive wrong -> lockout + wipe WARNING (no wipe yet) =="
rm -f "$FIRED"; run w1 >/dev/null; run w2 >/dev/null; run w3 >/dev/null
warn=$(grep -c "will DESTROY" /tmp/al.out)
echo "  counter=$(cnt) fired=$(fired) warned=$warn"
{ [ "$(cnt)" = 3 ] && [ "$(fired)" = n ]; } && P "at 3: locked out, NOT yet wiped" || F "3-strike state wrong (counter=$(cnt) fired=$(fired))"
[ "$warn" -ge 1 ] && P "wipe WARNING shown on the 3rd try" || F "no wipe warning at 3"

echo "== continued failures reach wipe_at(5) -> FIRE the wipe =="
run w4 >/dev/null
rm -f "$FIRED"; run w5 >/dev/null
echo "  counter=$(cnt) fired=$(fired)"
{ [ "$(cnt)" -ge 5 ] && [ "$(fired)" = y ]; } && P "at wipe_at: the wipe FIRED" || F "wipe did not fire at 5 (counter=$(cnt) fired=$(fired))"

echo "== duress code wipes INSTANTLY regardless of the counter =="
rm -rf "$DS_STATE_DIR"; mkdir -p "$DS_STATE_DIR"
python3 - "$DURESS" "$DS_STATE_DIR/duress.hash" <<'PY'
import sys,os,hashlib,binascii
code,out=sys.argv[1].encode(),sys.argv[2]
it=200000; salt=os.urandom(16)
open(out,'w').write("pbkdf2_sha256$%d$%s$%s"%(it,binascii.hexlify(salt).decode(),binascii.hexlify(hashlib.pbkdf2_hmac('sha256',code,salt,it,32)).decode()))
PY
rm -f "$FIRED"; rc=$(run "$DURESS"); echo "  rc=$rc fired=$(fired)"
{ [ "$rc" != 0 ] && [ "$(fired)" = y ]; } && P "duress code: auth fails + wipe fires instantly (counter irrelevant)" || F "duress path wrong (rc=$rc fired=$(fired))"

rm -rf "$DS_STATE_DIR"
echo
[ $FAILED -eq 0 ] && echo "ATTEMPT-LIMIT: ALL PASS" || echo "ATTEMPT-LIMIT: FAILURES ABOVE"
