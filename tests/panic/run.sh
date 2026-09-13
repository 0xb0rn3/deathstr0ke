#!/usr/bin/env bash
# Validates `dsctl panic` (the deliberate duress trigger): refuses when un-armed, refuses on a wrong
# phrase, and on the correct phrase invokes ds-erase --fire against the recorded target. The real
# recovery-safe erase (kill daily slot, recovery survives) is proven separately by tests/recovery-slot;
# here we point the test-only DS_ERASE_BIN at a stub so nothing is destroyed and the host ESP is never
# touched. Run from the repo root after: cargo build -p dsctl.
set -euo pipefail
export DS_TEST_MODE=1
export DS_STATE_DIR=/tmp/ds-panic-state.$$
DSCTL=${DSCTL:-target/debug/dsctl}
ARMED=/etc/arxos/deathstroke/ARMED
STUB=/tmp/ds-panic-stub.$$; CALLED=/tmp/ds-panic-called.$$
export DS_ERASE_BIN="$STUB"
PHRASE="wipe-me-now-9271"
made_dir=0

cleanup(){ set +e; rm -rf "$DS_STATE_DIR" "$STUB" "$CALLED"; rm -f "$ARMED"
  [ "$made_dir" = 1 ] && rmdir /etc/arxos/deathstroke /etc/arxos 2>/dev/null; true; }
trap cleanup EXIT

mkdir -p "$DS_STATE_DIR"
[ -d /etc/arxos/deathstroke ] || { mkdir -p /etc/arxos/deathstroke; made_dir=1; }

# ds-erase stub: records the args it was called with, exits success.
printf '#!/bin/sh\necho "$@" > %s\nexit 0\n' "$CALLED" > "$STUB"; chmod +x "$STUB"

# recorded state a real armed machine has
echo "/dev/fake-luks" > "$DS_STATE_DIR/target.device"
echo 0 > "$DS_STATE_DIR/daily.slot"
echo 1 > "$DS_STATE_DIR/recovery.slot"
printf '%s\n%s\n' "$PHRASE" "$PHRASE" | "$DSCTL" set-duress >/dev/null
[ -f "$DS_STATE_DIR/duress.hash" ] || { echo "FAIL: set-duress did not write verifier"; exit 1; }

pass=0
# 1) un-armed -> refuse, stub NOT called
rm -f "$ARMED" "$CALLED"
if printf '%s\n' "$PHRASE" | "$DSCTL" panic >/dev/null 2>&1; then echo "FAIL: panic ran while un-armed"; exit 1; fi
[ ! -f "$CALLED" ] && echo "PASS 1/3 un-armed refused (erase not called)" && pass=$((pass+1))

# 2) armed + wrong phrase -> refuse, stub NOT called
: > "$ARMED"; rm -f "$CALLED"
if printf 'wrong-phrase\n' | "$DSCTL" panic >/dev/null 2>&1; then echo "FAIL: panic ran on wrong phrase"; exit 1; fi
[ ! -f "$CALLED" ] && echo "PASS 2/3 wrong-phrase refused (erase not called)" && pass=$((pass+1))

# 3) armed + correct phrase -> ds-erase --fire --device /dev/fake-luks
: > "$ARMED"; rm -f "$CALLED"
printf '%s\n' "$PHRASE" | "$DSCTL" panic >/dev/null 2>&1 || { echo "FAIL: panic errored on correct phrase"; exit 1; }
if [ -f "$CALLED" ] && grep -q -- '--fire' "$CALLED" && grep -q -- '/dev/fake-luks' "$CALLED"; then
  echo "PASS 3/3 correct phrase fired: $(cat "$CALLED")"; pass=$((pass+1))
else echo "FAIL: erase not invoked correctly ($(cat "$CALLED" 2>/dev/null))"; exit 1; fi

[ "$pass" = 3 ] && echo "ALL PANIC GLUE TESTS PASS (3/3)"
