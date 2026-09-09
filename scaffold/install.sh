#!/usr/bin/env bash
# Installs the inert layout only.
#
# This reserves the directory layout and drops the config-schema reference and the dormant, not
# enabled unit template. It installs no binary into the auth path, provisions no LUKS keyslot,
# enables no service, and touches no file under /etc/pam.d. Idle cost and attack surface stay zero
# until the tool is armed by dsctl.
#
# Safe to run on any machine: it creates empty root-owned dirs and a couple of reference files. It is
# idempotent and reversible (see the commented uninstall at the bottom).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
S=""; [ "$(id -u)" -ne 0 ] && S=sudo

echo "Reserving inert layout (nothing armed, nothing in the auth path)..."

# reserved dirs, root-only, no world access.
$S install -d -m700 -o root -g root /etc/arxos/deathstroke
$S install -d -m700 -o root -g root /var/lib/arxos/deathstroke
$S install -d -m755 -o root -g root /usr/lib/arxos/deathstroke   # where the binaries land

# config-schema reference. Not an active config: armed is false and nothing reads it yet.
$S install -Dm600 "$HERE/deathstroke.conf.example" /etc/arxos/deathstroke/deathstroke.conf.example

# a state marker so dsctl can detect the layout is present, and so the state is auditable.
$S install -Dm644 /dev/stdin /var/lib/arxos/deathstroke/STATE <<'EOF'
state = inert
armed = false
pam_integrated = false
recovery_keyslot = none
note = Layout reserved only. No binary in the auth path, no LUKS keyslot, no enabled service.
EOF

echo "Inert layout installed. Nothing is armed. Verify:  cat /var/lib/arxos/deathstroke/STATE"

# ---- uninstall (reverse it completely) ----
# $S rm -rf /etc/arxos/deathstroke /var/lib/arxos/deathstroke /usr/lib/arxos/deathstroke
