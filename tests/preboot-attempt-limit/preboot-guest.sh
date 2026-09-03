#!/usr/bin/env bash
# Guest-side helper for the pre-boot attempt-limit test. Runs inside the archiso guest.
#   /dev/vda = ISO (cdrom on the qemu side is sr0), /dev/vdb = FAT counter "ESP", /dev/vdc = LUKS scratch.
# Downloads ds-unlock + ds-erase from the host once, then each verb runs one attempt / query.
set -u
# identify disks by serial (set on the qemu -device), not vdX order (the ISO is sr0, so ordering
# shifts). Fall back to a short wait for udev to create the by-id symlinks.
CDISK=/dev/disk/by-id/virtio-dscounter    # persistent FAT "ESP" (counter -> survives reboots)
LDISK=/dev/disk/by-id/virtio-dsscratch    # persistent LUKS scratch (the "root" we protect)
for i in $(seq 1 10); do [ -e "$CDISK" ] && [ -e "$LDISK" ] && break; sleep 0.5; done
ESP=/mnt/esp
DSDIR="$ESP/deathstroke"
DURESS="duress-preboot-code"
REALPW="correct-preboot-pass"
export DS_SECRET=""     # set per verb below

fetch() {
  command -v ds-unlock >/dev/null 2>&1 && return
  curl -s "http://10.0.2.2:8891/ds-unlock" -o /usr/local/bin/ds-unlock
  curl -s "http://10.0.2.2:8891/ds-erase"  -o /usr/local/bin/ds-erase
  chmod +x /usr/local/bin/ds-unlock /usr/local/bin/ds-erase
  install -d -m700 /etc/arxos/deathstroke
  touch /etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY   # allow ds-erase in this throwaway
}

mount_esp() { mkdir -p "$ESP"; mount "$CDISK" "$ESP" 2>/dev/null; mkdir -p "$DSDIR"; }
umount_esp() { sync; umount "$ESP" 2>/dev/null; }

slots() { cryptsetup luksDump "$LDISK" 2>/dev/null | grep -cE '^  [0-9]+: luks2'; }

case "${1:-}" in
  setup)
    fetch
    # FAT counter disk (the persistent ESP)
    mkfs.fat -F16 "$CDISK" >/dev/null 2>&1
    mount_esp
    # config + duress verifier on the ESP
    # max_prompts=1 so each `wrong` verb = exactly ONE attempt = ONE increment (the env DS_SECRET is
    # fixed, so more prompts would re-submit the same wrong secret and over-count).
    printf 'lockout_at=3\nwipe_at=5\nlockout_delay=0\nmax_prompts=1\n' > "$DSDIR/config"
    python3 - "$DURESS" "$DSDIR/duress.hash" <<'PY'
import sys,os,hashlib,binascii
c,o=sys.argv[1].encode(),sys.argv[2]; it=100000; s=os.urandom(16)
open(o,'w').write("pbkdf2_sha256$%d$%s$%s"%(it,binascii.hexlify(s).decode(),binascii.hexlify(hashlib.pbkdf2_hmac('sha256',c,s,it,32)).decode()))
PY
    umount_esp
    # LUKS scratch (the protected "root"), opened by REALPW. pbkdf2 (not argon2) so luksFormat does not
    # OOM in the 2G VM, and capture any error instead of hiding it.
    printf '%s' "$REALPW" | cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --batch-mode "$LDISK" - 2>/tmp/fmt.err
    [ "$(slots)" -ge 1 ] || { echo "SETUP-FORMAT-FAILED:"; tail -2 /tmp/fmt.err; }
    echo "SETUP-DONE slots=$(slots)"
    ;;
  reset-scratch)
    printf '%s' "$REALPW" | cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --batch-mode "$LDISK" - 2>/tmp/fmt.err
    echo "SCRATCH-RESET slots=$(slots)"
    ;;
  wrong)
    fetch; mount_esp
    DS_SECRET="definitely-wrong-$RANDOM" ds-unlock --device "$LDISK" --esp-dir "$DSDIR" --map-name ptest 2>&1 | tail -2
    cryptsetup close ptest 2>/dev/null
    umount_esp
    echo "WRONG-DONE count=$(mount_esp; cat "$DSDIR/counter" 2>/dev/null | tr -d "[:space:]"; umount_esp)"
    ;;
  correct)
    fetch; mount_esp
    DS_SECRET="$REALPW" ds-unlock --device "$LDISK" --esp-dir "$DSDIR" --map-name ptest 2>&1 | tail -2
    cryptsetup close ptest 2>/dev/null
    umount_esp
    echo "CORRECT-DONE"
    ;;
  duress)
    fetch; mount_esp
    DS_SECRET="$DURESS" ds-unlock --device "$LDISK" --esp-dir "$DSDIR" --map-name ptest 2>&1 | tail -2
    umount_esp
    echo "DURESS-DONE slots=$(slots)"
    ;;
  count)
    mount_esp; c=$(cat "$DSDIR/counter" 2>/dev/null | tr -d "[:space:]"); umount_esp
    echo "COUNT=${c:-0}"
    ;;
  slots)
    echo "SLOTS=$(slots)"
    ;;
  *) echo "usage: setup|wrong|correct|duress|count|slots|reset-scratch" ;;
esac
