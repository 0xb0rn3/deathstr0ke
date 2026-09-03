#!/usr/bin/env bash
# Runs INSIDE the archiso guest (fetched over HTTP from the host). Installs a LUKS + btrfs vanilla-Arch
# system onto /dev/vda with the deathstr0ke resume-before-unlock initramfs hook. Nothing here touches
# the host: all block devices are the guest's own virtio disk. Prints clear STAGE lines + a final
# sentinel over the serial console so the host driver can follow it.
set -uo pipefail
S(){ echo "STAGE: $*"; }
die(){ echo "GUEST-INSTALL-FAIL: $*"; exit 1; }
PASS=arxos
DEV=/dev/vda
MNT=/mnt

S "network: use a direct public resolver (QEMU's DNS forwarder is unreliable here)"
rm -f /etc/resolv.conf
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
# set the fast mirror BEFORE the reachability probe so the probe validates the real path
cat > /etc/pacman.d/mirrorlist <<MIRR
Server = https://geo.mirror.pkgbuild.com/\$repo/os/\$arch
Server = https://mirror.kumi.systems/archlinux/\$repo/os/\$arch
Server = https://mirror.leaseweb.net/archlinux/\$repo/os/\$arch
MIRR
S "wait until the mirror is actually reachable end-to-end (DNS + HTTPS)"
ok=0
for i in $(seq 1 40); do
    if curl -sf --max-time 8 -o /dev/null "https://geo.mirror.pkgbuild.com/core/os/x86_64/core.db"; then ok=1; break; fi
    sleep 3
done
[ "$ok" = 1 ] || die "no working network path to a mirror after ~2min (DNS/connectivity)"
S "mirror reachable"

S "partition $DEV (512M EFI + rest LUKS)"
sgdisk -Z "$DEV" >/dev/null || die sgdisk
sgdisk -n1:0:+512M -t1:ef00 -c1:EFI "$DEV" >/dev/null || die "sgdisk p1"
sgdisk -n2:0:0     -t2:8309 -c2:cryptroot "$DEV" >/dev/null || die "sgdisk p2"
partprobe "$DEV"; sleep 1
EFI=${DEV}1; ROOTP=${DEV}2

S "LUKS2 format + open (pbkdf2 so it stays simple)"
printf '%s' "$PASS" | cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 "$ROOTP" - || die luksFormat
printf '%s' "$PASS" | cryptsetup open "$ROOTP" cryptroot - || die "luks open"
LUKS_UUID=$(cryptsetup luksUUID "$ROOTP")
S "luks uuid=$LUKS_UUID"

S "mkfs FAT32 + btrfs, subvolumes @ and @home"
mkfs.fat -F32 "$EFI" >/dev/null || die mkfs.fat
mkfs.btrfs -f -L arxosroot /dev/mapper/cryptroot >/dev/null || die mkfs.btrfs
mount /dev/mapper/cryptroot "$MNT"
btrfs subvolume create "$MNT/@" >/dev/null
btrfs subvolume create "$MNT/@home" >/dev/null
umount "$MNT"
mount -o subvol=@,compress=zstd,noatime /dev/mapper/cryptroot "$MNT"
mkdir -p "$MNT/home" "$MNT/boot"
mount -o subvol=@home,compress=zstd,noatime /dev/mapper/cryptroot "$MNT/home"
mount "$EFI" "$MNT/boot"

S "enable parallel downloads"
sed -i 's/^#\?ParallelDownloads.*/ParallelDownloads = 5/' /etc/pacman.conf

S "pacstrap base system (progress streams below)"
# stream a filtered progress to serial; keep the full log for diagnosis on failure.
pacstrap -K "$MNT" base linux btrfs-progs cryptsetup grub efibootmgr sudo 2>&1 \
  | tee /tmp/pac.log | grep -E "downloading|installing|error|warning|failed|:: " || true
if [ ! -e "$MNT/usr/lib/systemd/systemd" ]; then
    echo "--- last 15 lines of pacstrap log ---"; tail -15 /tmp/pac.log
    die "pacstrap incomplete (no systemd in target)"
fi

S "fstab + base config"
genfstab -U "$MNT" >> "$MNT/etc/fstab"
arch-chroot "$MNT" /bin/bash <<CHROOT || die "chroot config"
set -e
ln -sf /usr/share/zoneinfo/UTC /etc/localtime
echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
locale-gen >/dev/null
echo "LANG=en_US.UTF-8" > /etc/locale.conf
echo "arxos-dsluks" > /etc/hostname
echo "root:$PASS" | chpasswd
# serial autologin so the resume boot shows a shell on ttyS0
mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d
printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %%I 115200 linux\n' > /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
# encrypt hook (busybox) reads cryptdevice=UUID:name; deathstroke hook runs BEFORE encrypt.
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect modconf kms keyboard keymap consolefont block deathstroke encrypt filesystems fsck)/' /etc/mkinitcpio.conf
# force vfat into the initramfs so the deathstroke hook can mount the ESP to read its flag
sed -i 's/^MODULES=.*/MODULES=(vfat nls_cp437)/' /etc/mkinitcpio.conf
CHROOT

S "install deathstroke initramfs hook (before encrypt = before root unlock)"
cat > "$MNT/etc/initcpio/install/deathstroke" <<'IHOOK'
#!/bin/bash
build() { add_runscript; }
help()  { echo "deathstroke resume-before-unlock check"; }
IHOOK
cat > "$MNT/etc/initcpio/hooks/deathstroke" <<'RHOOK'
#!/usr/bin/ash
run_hook() {
    local esp="/ds-esp" dev
    mkdir -p "$esp"
    for dev in $(blkid -t TYPE=vfat -o device 2>/dev/null); do
        mount -t vfat "$dev" "$esp" 2>/dev/null && break
    done
    if [ -f "$esp/deathstroke-inprogress" ]; then
        echo ""
        echo "##### DEATHSTROKE-RESUME-HOOK: in-progress flag detected BEFORE root unlock #####"
        echo "resumed-at-boot $(cut -d. -f1 /proc/uptime 2>/dev/null)s" > "$esp/deathstroke-resumed"
        rm -f "$esp/deathstroke-inprogress"
        sync
    else
        echo "##### DEATHSTROKE-RESUME-HOOK: no flag, normal boot #####"
    fi
    umount "$esp" 2>/dev/null || true
}
RHOOK
chmod +x "$MNT/etc/initcpio/install/deathstroke" "$MNT/etc/initcpio/hooks/deathstroke"

S "regenerate initramfs with the hook"
arch-chroot "$MNT" mkinitcpio -P >/tmp/mkinit.log 2>&1 || { tail -8 "$MNT/tmp/mkinit.log" 2>/dev/null; tail -8 /tmp/mkinit.log; die mkinitcpio; }
grep -q deathstroke /tmp/mkinit.log && S "deathstroke hook present in initramfs build" || echo "WARN: hook not in mkinitcpio log"

S "GRUB (unencrypted /boot on ESP; initramfs unlocks LUKS)"
arch-chroot "$MNT" /bin/bash <<CHROOT2 || die grub
set -e
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=$LUKS_UUID:cryptroot root=/dev/mapper/cryptroot console=ttyS0,115200\"|" /etc/default/grub
sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=1/' /etc/default/grub
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=ARXOS --removable >/dev/null 2>&1
grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
CHROOT2

S "teardown"
sync
umount -R "$MNT"
cryptsetup close cryptroot
echo "GUEST-INSTALL-DONE luks_uuid=$LUKS_UUID"
