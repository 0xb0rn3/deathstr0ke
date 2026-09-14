#!/usr/bin/env bash
# ds-seal-boot — DEATHSTROKE boot-integrity sealer (red-team T3/T7 closure).
#
# /boot is unencrypted, so an attacker can strip the pre-boot `deathstroke` initramfs hook and boot the
# stock `encrypt` hook, making the duress prompt inert. This seals the boot: it builds a signed Unified
# Kernel Image (kernel + the armed initramfs + cmdline in ONE PE binary), signs it with a machine key,
# enrolls the cert, and points the firmware at it. With Secure Boot ENFORCING, any modification to the
# initramfs (or kernel/cmdline) invalidates the signature and the firmware refuses to boot it — so the
# hook cannot be stripped. This is a NON-DESTRUCTIVE boot-integrity control: no erasure logic here.
#
# Idempotent. Re-run after every `dsctl arm` (arm rebuilds the initramfs, so the UKI must be re-sealed).
# Usage: ds-seal-boot [--kernel NAME] [--esp DIR] [--reseal-only] [--status]
set -euo pipefail

die(){ echo "ds-seal-boot: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null || die "missing tool: $1 (install sbsigntools/systemd-ukify/sbctl/mokutil)"; }

KVER_PKG="linux-arxos"
ESP="/boot/efi"
KEYDIR="/var/lib/arxos/deathstroke/secureboot"
STATUS_ONLY=0; RESEAL_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --kernel) KVER_PKG="${2:-linux-arxos}"; shift 2;;
        --esp)    ESP="${2:-/boot/efi}"; shift 2;;
        --status) STATUS_ONLY=1; shift;;
        --reseal-only) RESEAL_ONLY=1; shift;;
        --*) die "unknown flag: $1";;
        *) KVER_PKG="$1"; shift;;   # a bare positional is the kernel package name
    esac
done
# ESP-derived paths are resolved AFTER parsing so --esp takes effect.
UKI_DIR="$ESP/EFI/ARXOS"; UKI="$UKI_DIR/arxos-signed.efi"

sb_state(){ mokutil --sb-state 2>/dev/null | head -1 || echo "SecureBoot state unknown"; }
if [ "$STATUS_ONLY" = 1 ]; then
    echo "  $(sb_state)"
    [ -f "$UKI" ] && echo "  signed UKI: $UKI ($(stat -c%s "$UKI") bytes)" || echo "  signed UKI: (none — run ds-seal-boot to seal)"
    [ -f "$KEYDIR/db.crt" ] && echo "  machine key: present" || echo "  machine key: none"
    exit 0
fi

need ukify; need sbsign; need sbverify; need objcopy
[ "$(id -u)" = 0 ] || die "must run as root"

# --- 1. locate the kernel image + its initramfs + cmdline -------------------------------------------
KREL="$(ls /usr/lib/modules 2>/dev/null | grep -E "${KVER_PKG#linux-}|arxos" | head -1)"
KIMG="/boot/vmlinuz-$KVER_PKG"; [ -f "$KIMG" ] || KIMG="/usr/lib/modules/$KREL/vmlinuz"
INITRD="/boot/initramfs-$KVER_PKG.img"
[ -f "$KIMG" ]    || die "kernel image not found for $KVER_PKG"
[ -f "$INITRD" ]  || die "initramfs not found: $INITRD (run mkinitcpio -p $KVER_PKG first)"
CMDLINE="$(cat /etc/kernel/cmdline 2>/dev/null || sed 's/\binitrd=[^ ]*//g; s/\bBOOT_IMAGE=[^ ]*//g' /proc/cmdline)"
[ -n "$CMDLINE" ] || die "no kernel cmdline to embed"

# --- 2. machine Secure Boot key (generated once, 0600, never leaves the box) ------------------------
mkdir -p "$KEYDIR"; chmod 700 "$KEYDIR"
if [ ! -f "$KEYDIR/db.key" ] || [ ! -f "$KEYDIR/db.crt" ]; then
    echo ">> generating machine Secure Boot key"
    openssl req -newkey rsa:2048 -nodes -keyout "$KEYDIR/db.key" -x509 -sha256 -days 3650 \
        -subj "/CN=ArxOS DEATHSTROKE boot ($(hostname 2>/dev/null || echo host))/" -out "$KEYDIR/db.crt"
    chmod 600 "$KEYDIR/db.key" "$KEYDIR/db.crt"
fi

# --- 3. build + sign the UKI ------------------------------------------------------------------------
mkdir -p "$UKI_DIR"
echo ">> building signed UKI ($KVER_PKG, kernel=$KIMG)"
ukify build --linux="$KIMG" --initrd="$INITRD" --cmdline="$CMDLINE" \
    --secureboot-private-key="$KEYDIR/db.key" --secureboot-certificate="$KEYDIR/db.crt" \
    --output="$UKI.tmp"
sbverify --cert "$KEYDIR/db.crt" "$UKI.tmp" >/dev/null || die "signed UKI failed self-verification"
mv -f "$UKI.tmp" "$UKI"
echo ">> sealed: $UKI ($(sbverify --cert "$KEYDIR/db.crt" "$UKI" 2>&1 | head -1))"

# --- 4. enroll the cert + point the firmware at the UKI ---------------------------------------------
if [ "$RESEAL_ONLY" = 0 ]; then
    ENROLLED=0
    if command -v sbctl >/dev/null && sbctl status 2>/dev/null | grep -qi 'setup mode.*enabled\|setup mode.*✓'; then
        echo ">> firmware in setup mode: enrolling keys via sbctl"
        sbctl enroll-keys --yes-this-might-brick-my-machine 2>/dev/null && ENROLLED=1 || true
    fi
    if [ "$ENROLLED" = 0 ] && command -v mokutil >/dev/null; then
        echo ">> requesting MOK enrollment of the machine cert (confirm at the blue MOK screen on next reboot)"
        mokutil --import "$KEYDIR/db.crt" 2>/dev/null || echo "   (mokutil import needs a one-time password + reboot; run it interactively if this failed)"
    fi
    if command -v efibootmgr >/dev/null; then
        DISK="$(findmnt -no SOURCE "$ESP" 2>/dev/null | sed -E 's/p?[0-9]+$//')"
        PART="$(findmnt -no SOURCE "$ESP" 2>/dev/null | grep -oE '[0-9]+$')"
        if [ -n "$DISK" ] && [ -n "$PART" ]; then
            efibootmgr -c -d "$DISK" -p "$PART" -L "ArxOS (sealed)" -l '\EFI\ARXOS\arxos-signed.efi' 2>/dev/null \
                | tail -1 || echo "   (efibootmgr entry may already exist)"
        fi
    fi
fi

echo ">> boot-seal done. $(sb_state)"
echo "   Enforce Secure Boot in firmware so a tampered initramfs (stripped hook) fails signature check."
