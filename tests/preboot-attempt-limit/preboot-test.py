#!/usr/bin/env python3
# Adversarial pre-boot attempt-limit test. Boots the Arch ISO in QEMU (no install needed), and inside
# the guest exercises ds-unlock against a REAL LUKS device with its counter on a REAL FAT "ESP", ACROSS
# ACTUAL VM REBOOTS. The exploit we're hunting: can an attacker reset the counter by power-cycling?
# The counter lives on a persistent FAT image attached as a second disk, so a reboot must NOT reset it.
#
# Phases (each a fresh boot of the same VM, same disks):
#   boot1: format the FAT counter disk + a LUKS scratch, enroll a duress verifier, then 2 wrong tries
#   boot2 (REBOOT): counter must still read 2 (persistence). 1 more wrong -> 3 -> warning.
#   boot3 (REBOOT): counter 3. A CORRECT passphrase -> resets to 0 + unlocks.
#   boot4 (REBOOT): fresh 0. Wrong tries climb to wipe_at(5) -> ds-erase wipes the scratch to 0 slots.
#   boot5 (REBOOT): a duress code wipes instantly regardless of counter.
import os, socket, subprocess, threading, time, http.server, functools, sys

HERE = "os.environ.get("DS_TEST_DIR", os.path.dirname(os.path.abspath(__file__)))"
ISO = f"{HERE}/archlinux-x86_64.iso"
KERNEL = f"{HERE}/qemu-boot/arch/boot/x86_64/vmlinuz-linux"
INITRD = f"{HERE}/qemu-boot/arch/boot/x86_64/initramfs-linux.img"
LABEL = "ARCH_202608"
PORT = 8891
SOCK = f"{HERE}/preboot-serial.sock"
COUNTER_DISK = f"{HERE}/preboot-counter.img"   # persistent FAT "ESP" (2nd disk) -> survives reboots
SCRATCH_DISK = f"{HERE}/preboot-scratch.img"   # persistent LUKS scratch (3rd disk)

def log(m): print(m, flush=True)

class Serial:
    def __init__(self, path):
        for _ in range(160):
            try:
                self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.s.connect(path); break
            except (FileNotFoundError, ConnectionRefusedError): time.sleep(0.25)
        else: raise RuntimeError("serial never appeared")
        self.s.settimeout(0.5); self.buf = ""
    def _pump(self):
        try:
            d = self.s.recv(65536)
            if d:
                t = d.decode("utf-8", "ignore"); self.buf += t; sys.stdout.write(t); sys.stdout.flush()
        except (socket.timeout, OSError): pass
    def expect(self, needles, timeout, name=""):
        if isinstance(needles, str): needles = [needles]
        end = time.time() + timeout
        while time.time() < end:
            self._pump()
            for n in needles:
                i = self.buf.find(n)
                if i >= 0: self.buf = self.buf[i+len(n):]; return n
        raise TimeoutError(f"expect {name or needles} timed out")
    def line(self, t): self.s.sendall((t+"\n").encode()); time.sleep(0.05)

def start_http():
    h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=HERE)
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(f"[http] serving on :{PORT}")

def boot():
    if os.path.exists(SOCK): os.remove(SOCK)
    cmd = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-smp", "2", "-m", "2048",
           "-kernel", KERNEL, "-initrd", INITRD,
           "-append", f"archisobasedir=arch archisolabel={LABEL} console=ttyS0,115200 cow_spacesize=1G",
           "-drive", f"file={ISO},media=cdrom",
           # serials so the guest identifies each disk by /dev/disk/by-id/virtio-<serial>, robust
           # against enumeration order (the ISO is sr0, so the virtio disks are vda/vdb not vdb/vdc).
           "-drive", f"file={COUNTER_DISK},if=none,format=raw,id=dcnt",
           "-device", "virtio-blk-pci,drive=dcnt,serial=dscounter",
           "-drive", f"file={SCRATCH_DISK},if=none,format=raw,id=dscr",
           "-device", "virtio-blk-pci,drive=dscr,serial=dsscratch",
           "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
           "-serial", f"unix:{SOCK},server=on,wait=on", "-display", "none", "-no-reboot"]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

def kill(p):
    try: p.terminate(); p.wait(10)
    except Exception:
        try: p.kill()
        except Exception: pass

def get_shell(ser):
    end = time.time() + 240
    while time.time() < end:
        try:
            h = ser.expect(["archiso login:", "root@archiso", "# "], 15, "boot")
            if h == "archiso login:": ser.line("root")
        except TimeoutError: ser.line("")
        ser.line("echo RDY$((6*7))X")
        try: ser.expect("RDY42X", 8); return
        except TimeoutError: continue
    raise RuntimeError("no shell")

def sh(ser, cmd, marker, timeout=60):
    ser.line(cmd + f'; echo {marker}=$?')
    return ser.expect(f"{marker}=", timeout, marker)

RESULTS = {}
def boot_phase(name, script_fn, timeout=300):
    log(f"\n===== {name} =====")
    p = boot()
    try:
        ser = Serial(SOCK); get_shell(ser)
        # fetch the guest helper each boot (ds-unlock + ds-erase pulled over http, plus the phase logic)
        sh(ser, f"curl -s http://10.0.2.2:{PORT}/preboot-guest.sh -o /root/g.sh", "GET", 60)
        script_fn(ser)
    finally:
        kill(p)

def main():
    # (re)create the two persistent disks ONCE (counter FAT + LUKS scratch). They persist across boots.
    subprocess.run(["qemu-img", "create", "-f", "raw", COUNTER_DISK, "32M"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["qemu-img", "create", "-f", "raw", SCRATCH_DISK, "48M"], check=True, stdout=subprocess.DEVNULL)
    start_http()

    def p1(ser):
        out = sh(ser, "bash /root/g.sh setup && bash /root/g.sh wrong && bash /root/g.sh wrong && bash /root/g.sh count", "P1", 120)
        RESULTS['boot1_count'] = ser.expect(["COUNT="], 10) and read_after(ser, "COUNT=")
    def p2(ser):
        RESULTS['boot2_count_persisted'] = phase_count(ser)      # must be 2
        sh(ser, "bash /root/g.sh wrong", "W3", 60)
        RESULTS['boot2_after'] = phase_count(ser)                # 3
    def p3(ser):
        RESULTS['boot3_count'] = phase_count(ser)                # 3
        sh(ser, "bash /root/g.sh correct", "OK", 60)
        RESULTS['boot3_after_correct'] = phase_count(ser)        # 0
    def p4(ser):
        RESULTS['boot4_count'] = phase_count(ser)                # 0
        RESULTS['boot4_slots_before'] = phase_slots(ser)         # must be >=1 (scratch intact)
        for _ in range(5): sh(ser, "bash /root/g.sh wrong", "WN", 90)
        RESULTS['boot4_slots'] = phase_slots(ser)                # 0 (wiped)
    def p5(ser):
        # fresh scratch for the duress test
        sh(ser, "bash /root/g.sh reset-scratch", "RS", 60)
        RESULTS['boot5_slots_before'] = phase_slots(ser)         # must be >=1
        sh(ser, "bash /root/g.sh duress", "DU", 90)
        RESULTS['boot5_duress_slots'] = phase_slots(ser)         # 0 (instant wipe)

    boot_phase("BOOT 1: setup + 2 wrong", p1)
    boot_phase("BOOT 2 (REBOOT): persistence + 3rd wrong", p2)
    boot_phase("BOOT 3 (REBOOT): correct resets", p3)
    boot_phase("BOOT 4 (REBOOT): climb to wipe", p4)
    boot_phase("BOOT 5 (REBOOT): duress instant wipe", p5)

    log("\n================ RESULT ================")
    checks = [
        ("boot1: counter=2 after 2 wrong", RESULTS.get('boot1_count') == "2"),
        ("boot2: counter STILL 2 after reboot (no reset bypass)", RESULTS.get('boot2_count_persisted') == "2"),
        ("boot2: 3rd wrong -> 3", RESULTS.get('boot2_after') == "3"),
        ("boot3: counter 3 across reboot", RESULTS.get('boot3_count') == "3"),
        ("boot3: correct passphrase RESETS -> 0", RESULTS.get('boot3_after_correct') == "0"),
        ("boot4: fresh 0 after reset persisted", RESULTS.get('boot4_count') == "0"),
        ("boot4: scratch intact BEFORE wipe (>=1 slot)", RESULTS.get('boot4_slots_before') not in (None, "0")),
        ("boot4: climb to wipe_at -> scratch ERASED (0 slots)", RESULTS.get('boot4_slots') == "0"),
        ("boot5: scratch intact BEFORE duress (>=1 slot)", RESULTS.get('boot5_slots_before') not in (None, "0")),
        ("boot5: duress code -> instant wipe (0 slots)", RESULTS.get('boot5_duress_slots') == "0"),
    ]
    allok = True
    for n, v in checks: log(f"  [{'PASS' if v else 'FAIL'}] {n}"); allok = allok and v
    log("PREBOOT-ATTEMPT-LIMIT: ALL PASS" if allok else "PREBOOT-ATTEMPT-LIMIT: FAILURES ABOVE")
    sys.exit(0 if allok else 1)

def read_after(ser, tok):
    # after an expect() consumed up to tok, read the following token on the line
    end = time.time() + 8
    while time.time() < end:
        ser._pump()
        line = ser.buf.split("\n", 1)[0]
        v = line.strip().split()[0] if line.strip() else ""
        if v: return v
        time.sleep(0.2)
    return None

def phase_count(ser):
    sh(ser, "bash /root/g.sh count", "C", 30); ser.expect("COUNT=", 10); return read_after(ser, "COUNT=")
def phase_slots(ser):
    sh(ser, "bash /root/g.sh slots", "S", 30); ser.expect("SLOTS=", 10); return read_after(ser, "SLOTS=")

if __name__ == "__main__":
    main()
