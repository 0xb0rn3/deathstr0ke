#!/usr/bin/env bash
# Deploy the deathstr0ke toolkit onto a system (binaries + PAM module + pre-boot mkinitcpio hook +
# the inert scaffold). Installing does NOT arm anything: no duress code, no LUKS keyslot, no PAM
# line, no enabled unit until `dsctl arm`. Idle cost + attack surface stay zero until armed.
#
# Build first if the release binaries are absent (needs cargo). Idempotent.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
S=""; [ "$(id -u)" -ne 0 ] && S=sudo
BIN="$HERE/target/release"

if [ ! -x "$BIN/dsctl" ] || [ ! -x "$BIN/ds-unlock" ]; then
    echo ">> building release binaries (cargo build --release)"
    ( cd "$HERE" && cargo build --release )
fi

echo ">> installing binaries to /usr/bin"
for b in dsctl ds-erase ds-unlock; do
    [ -x "$BIN/$b" ] && $S install -Dm755 "$BIN/$b" "/usr/bin/$b" || { echo "  !! $b not built"; exit 1; }
done

# pam_ds is a cdylib -> libpam_ds.so; PAM dlopens it from /usr/lib/security/pam_ds.so (dsctl's
# PAM_MODULE constant). Installed but INERT until `dsctl arm` inserts the auth line.
if [ -f "$BIN/libpam_ds.so" ]; then
    echo ">> installing PAM module to /usr/lib/security/pam_ds.so (inert until armed)"
    $S install -Dm755 "$BIN/libpam_ds.so" /usr/lib/security/pam_ds.so
else
    echo "  !! libpam_ds.so not built (pam_ds crate) — PAM surfaces will not arm"
fi

# pre-boot LUKS unlock manager mkinitcpio hook (runs ds-unlock before the encrypt hook). Present but
# inactive until `deathstroke` is added to HOOKS= (the Calamares module / dsctl does that on arm).
echo ">> installing mkinitcpio hook (inactive until listed in HOOKS before encrypt)"
$S install -Dm644 "$HERE/mkinitcpio/install/deathstroke" /etc/initcpio/install/deathstroke
$S install -Dm755 "$HERE/mkinitcpio/hooks/deathstroke"   /etc/initcpio/hooks/deathstroke

# reserve the inert state layout (dirs, config schema, disabled resume-unit template)
echo ">> reserving inert layout"
$S bash "$HERE/scaffold/install.sh"

echo ">> deathstr0ke installed (INERT). Arm with: sudo dsctl set-duress && sudo dsctl enroll-recovery --device <luks> && sudo dsctl arm"
