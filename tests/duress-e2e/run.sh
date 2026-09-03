#!/usr/bin/env bash
# End-to-end DEATHSTROKE duress chain, run as root INSIDE the disposable arxos-ds-test VM.
# Proves: entering the duress code through the REAL PAM stack -> pam_ds -> REAL ds-erase -> a scratch
# LUKS device is crypto-erased. A normal password logs in and leaves the scratch intact. No stand-ins.
# The erase target is a /tmp loopback, NOT the VM root, so the VM survives to report + re-run.
set -u
CODE="redoktober-duress"; USERPW="arxos"
P(){ echo "  PASS  $*"; }; F(){ echo "  FAIL  $*"; FAILED=1; }; FAILED=0

echo "== deploy =="
install -d -m700 /etc/arxos/deathstroke /var/lib/arxos/deathstroke
install -d -m755 /usr/lib/arxos/deathstroke
install -m755 /tmp/ds-erase /usr/lib/arxos/deathstroke/ds-erase
install -m755 /tmp/dsctl /usr/local/bin/dsctl
install -m755 /tmp/libpam_ds.so /usr/lib/security/pam_ds.so
touch /etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY
gcc /tmp/ds-e2e-harness.c -o /tmp/harness -lpam || { echo "harness build failed"; exit 1; }

echo "== set duress code (stored as hash) =="
printf '%s\n%s\n' "$CODE" "$CODE" | dsctl set-duress >/dev/null 2>&1
test -f /var/lib/arxos/deathstroke/duress.hash && P "duress code enrolled (hash only)" || F "no duress hash"

echo "== scratch LUKS target (NOT the VM root) =="
W=/tmp/ds-e2e; rm -rf "$W"; mkdir -p "$W"
printf 'unlock-key' > "$W/key"
dd if=/dev/zero of="$W/vault.img" bs=1M count=32 status=none
LOOP=$(losetup -f --show "$W/vault.img")
cryptsetup luksFormat --type luks2 --batch-mode "$LOOP" "$W/key" >/dev/null 2>&1
echo -n "$LOOP" > /var/lib/arxos/deathstroke/target.device
slots(){ cryptsetup luksDump "$LOOP" 2>/dev/null | grep -cE '^  [0-9]+: luks2'; }
echo "  scratch target=$LOOP  slots=$(slots)"

echo "== arm (pam_ds into the real system-auth) =="
dsctl arm >/dev/null 2>&1
grep -q deathstr0ke-arm /etc/pam.d/system-auth && P "armed: pam_ds is in system-auth" || F "arm failed"
printf 'auth include system-auth\naccount include system-auth\n' > /etc/pam.d/ds-e2e

echo
echo "== CASE 1: NORMAL password -> logs in, does NOT fire, scratch intact =="
b=$(slots)
/tmp/harness ds-e2e arxos "$USERPW" >/tmp/h1 2>&1; rc=$?
sleep 3
a=$(slots)
sed 's/^/    /' /tmp/h1
{ [ $rc -eq 0 ] && [ "$a" = "$b" ] && [ "$a" -ge 1 ]; } \
  && P "normal password logs in (rc=0); scratch UNTOUCHED ($a slots)" \
  || F "normal case wrong (rc=$rc slots $b->$a)"

echo
echo "== CASE 2: DURESS code -> auth FAILS + REAL ds-erase wipes the scratch to 0 slots =="
/tmp/harness ds-e2e arxos "$CODE" >/tmp/h2 2>&1; rc=$?
# pam_ds spawns ds-erase asynchronously (auth must not hang); poll for the erase.
for i in $(seq 1 30); do [ "$(slots)" = 0 ] && break; sleep 1; done
a=$(slots)
sed 's/^/    /' /tmp/h2
{ [ $rc -ne 0 ] && [ "$a" = 0 ]; } \
  && P "DURESS code: auth FAILED (rc=$rc) AND scratch crypto-erased to 0 slots via PAM->ds-erase" \
  || F "duress chain wrong (rc=$rc, slots=$a)"

echo
echo "== cleanup =="
dsctl disarm >/dev/null 2>&1
grep -q deathstr0ke-arm /etc/pam.d/system-auth && F "still armed after disarm" || P "disarmed (system-auth restored)"
rm -f /etc/pam.d/ds-e2e; losetup -d "$LOOP" 2>/dev/null; rm -rf "$W"

echo
[ $FAILED -eq 0 ] && echo "E2E-DURESS: ALL PASS" || echo "E2E-DURESS: FAILURES ABOVE"
