#!/usr/bin/env python3
# Zero-dependency QEMU serial driver for the deathstr0ke boot-resume test. Everything runs inside
# guest VMs; the host only launches qemu processes and serves one file over HTTP. No host mounts,
# no host loop/cryptsetup. Three phases:
#   1. install  : boot the Arch ISO (direct kernel), run guest-install.sh over HTTP -> LUKS+btrfs disk
#   2. boot A    : boot the installed disk, prove the hook is SILENT (no flag) and normal boot works,
#                  then set the in-progress flag on the ESP
#   3. boot B    : boot again, prove the hook FIRES before LUKS unlock and clears the flag
import os, sys, socket, subprocess, threading, time, http.server, functools

# Work dir (holds the ISO, extracted kernel/initrd, and the target qcow2). Override with DS_TEST_DIR;
# defaults to this script's own directory. See README.md for the one-time setup (ISO + extract).
HERE = os.environ.get("DS_TEST_DIR", os.path.dirname(os.path.abspath(__file__)))
ISO  = os.environ.get("DS_ISO", f"{HERE}/archlinux-x86_64.iso")
KERNEL = f"{HERE}/qemu-boot/arch/boot/x86_64/vmlinuz-linux"
INITRD = f"{HERE}/qemu-boot/arch/boot/x86_64/initramfs-linux.img"
DISK = os.environ.get("DS_DISK", f"{HERE}/ds-luks-btrfs.qcow2")
LABEL = os.environ.get("DS_ISO_LABEL", "ARCH_202608")   # ISO volume label; `blkid <iso>` to find it
PASS = "arxos"
PORT = 8899
OVMF_CODE = os.environ.get("OVMF_CODE", "/usr/share/edk2/x64/OVMF_CODE.4m.fd")
OVMF_VARS_SRC = os.environ.get("OVMF_VARS", "/usr/share/edk2/x64/OVMF_VARS.4m.fd")
OVMF_VARS = f"{HERE}/ds-OVMF_VARS.fd"
SOCK = f"{HERE}/ds-serial.sock"

def log(m): print(m, flush=True)

class Serial:
    """Connect to QEMU's serial unix socket; buffered expect()/send()."""
    def __init__(self, path):
        for _ in range(120):
            try:
                self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.s.connect(path); break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.25)
        else:
            raise RuntimeError("serial socket never appeared")
        self.s.settimeout(0.5); self.buf = ""
    def _pump(self):
        try:
            d = self.s.recv(65536)
            if d:
                t = d.decode("utf-8", "ignore"); self.buf += t; sys.stdout.write(t); sys.stdout.flush()
        except socket.timeout: pass
        except OSError: pass
    def expect(self, needles, timeout, name=""):
        if isinstance(needles, str): needles = [needles]
        end = time.time() + timeout
        while time.time() < end:
            self._pump()
            for n in needles:
                i = self.buf.find(n)
                if i >= 0:
                    self.buf = self.buf[i+len(n):]; return n
        raise TimeoutError(f"expect {name or needles} timed out after {timeout}s")
    def send(self, text):
        self.s.sendall(text.encode()); time.sleep(0.05)
    def line(self, text): self.send(text + "\n")

def start_http():
    h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=HERE)
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(f"[http] serving {HERE} on :{PORT}")
    return srv

def qemu_common():
    return ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-smp", "4", "-m", "4096",
            "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
            "-serial", f"unix:{SOCK},server=on,wait=on", "-display", "none", "-no-reboot"]

def launch(extra):
    if os.path.exists(SOCK): os.remove(SOCK)
    p = subprocess.Popen(qemu_common() + extra, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return p

def kill(p):
    try: p.terminate(); p.wait(10)
    except Exception:
        try: p.kill()
        except Exception: pass

def get_shell(ser, timeout=180):
    # archiso autologins root on serial; if a login: prompt shows, handle it. Confirm with an echo.
    # Drive early boot to a root shell. Feed the LUKS passphrase to ANY passphrase/password prompt
    # (there can be more than one: the encrypt hook AND systemd), answer a login: prompt, and confirm
    # the shell with a computed marker whose OUTPUT ("RDY42X") differs from the typed command, so the
    # command echo can't false-match.
    end = time.time() + timeout
    while time.time() < end:
        try:
            hit = ser.expect(["passphrase for", "password is required", "Password:",
                              "login:", "]# ", "]#"], 20, "boot")
        except TimeoutError:
            ser.line(""); continue
        low = hit.lower()
        if "passphrase" in low or "password" in low:
            ser.line(PASS)                       # feed the LUKS passphrase, never an echo probe
        elif hit == "login:":
            ser.line("root")
        else:                                     # a shell prompt "]#": confirm it is really a shell
            ser.line("echo RDY$((6*7))X")
            try:
                ser.expect("RDY42X", 8, "shell-probe"); return
            except TimeoutError:
                continue
    raise RuntimeError("no shell")

def phase_install():
    log("\n===== PHASE 1: install (LUKS+btrfs) via archiso guest =====")
    p = launch([
        "-kernel", KERNEL, "-initrd", INITRD,
        "-append", f"archisobasedir=arch archisolabel={LABEL} console=ttyS0,115200 cow_spacesize=2G",
        "-drive", f"file={ISO},media=cdrom",
        "-drive", f"file={DISK},if=virtio,format=qcow2"])
    try:
        ser = Serial(SOCK)
        get_shell(ser, 240)
        log("\n[install] got archiso shell; running guest-install.sh over HTTP")
        ser.line(f"curl -s http://10.0.2.2:{PORT}/guest-install.sh -o /tmp/gi.sh && bash /tmp/gi.sh")
        hit = ser.expect(["GUEST-INSTALL-DONE", "GUEST-INSTALL-FAIL"], 2700, "install")
        if "FAIL" in hit: raise RuntimeError("guest install FAILED")
        log("\n[install] DONE; powering off")
        ser.line("sync; poweroff -f")
        time.sleep(5)
    finally:
        kill(p)

def boot_disk_qemu():
    subprocess.run(["cp", "-f", OVMF_VARS_SRC, OVMF_VARS], check=True)
    return launch([
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={OVMF_VARS}",
        "-drive", f"file={DISK},if=virtio,format=qcow2"])

def phase_bootA():
    log("\n===== PHASE 2: normal boot (hook must be SILENT, login must work) =====")
    p = boot_disk_qemu(); ok = {}
    try:
        ser = Serial(SOCK)
        # the deathstroke hook runs BEFORE encrypt -> its 'no flag' line must appear before the LUKS prompt
        ser.expect("DEATHSTROKE-RESUME-HOOK", 180, "hook-run")
        hookline = ser.expect(["no flag, normal boot", "in-progress flag detected"], 5, "hook-verdict")
        ok["hook_silent"] = ("no flag" in hookline)
        get_shell(ser, 240)   # feeds the LUKS passphrase(s), reaches the root shell
        ok["login_works"] = True   # reaching a shell after the LUKS unlock proves login works
        # clean any stale marker from a prior run so phase 3's marker is provably written this boot.
        # printf 'CLEAN=%s' means the OUTPUT is "CLEAN=done" while the typed command shows only the
        # template -> the command echo can never false-match the assertion.
        ser.line("rm -f /boot/deathstroke-resumed; printf 'CLEAN=%s\\n' done")
        ser.expect("CLEAN=done", 15, "clean")
        log("\n[bootA] setting the in-progress flag on the ESP for phase 3")
        ser.line("touch /boot/deathstroke-inprogress && sync && printf 'FLAG=%s\\n' set")
        ser.expect("FLAG=set", 15, "flag-set"); ok["flag_set"] = True
        ser.line("poweroff -f"); time.sleep(5)
    finally:
        kill(p)
    return ok

def phase_bootB():
    log("\n===== PHASE 3: resume boot (hook must FIRE before unlock, clear the flag) =====")
    p = boot_disk_qemu(); ok = {}
    try:
        ser = Serial(SOCK)
        ser.expect("DEATHSTROKE-RESUME-HOOK", 180, "hook-run")
        verdict = ser.expect(["in-progress flag detected", "no flag, normal boot"], 5, "hook-verdict")
        ok["hook_fired_pre_unlock"] = ("in-progress flag detected" in verdict)
        get_shell(ser, 240)   # feeds the LUKS passphrase(s), reaches the root shell
        ok["login_works"] = True
        # OUTPUT-only markers (the %s template in the typed command can't false-match the assertion).
        ser.line("printf 'MARK=%s\\n' \"$(cat /boot/deathstroke-resumed 2>/dev/null || echo MISSING)\"")
        ok["resumed_marker_written"] = ("resumed-at-boot" in ser.expect(["MARK=resumed-at-boot", "MARK=MISSING"], 15, "marker"))
        ser.line("printf 'FLAG=%s\\n' \"$(test -e /boot/deathstroke-inprogress && echo STILL || echo GONE)\"")
        ok["flag_cleared"] = (ser.expect(["FLAG=GONE", "FLAG=STILL"], 10, "flag-clear") == "FLAG=GONE")
        ser.line("poweroff -f"); time.sleep(5)
    finally:
        kill(p)
    return ok

def main():
    # mode "boot" re-runs only the two boot phases against the already-installed disk (no reinstall).
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode != "boot":
        start_http()
        phase_install()
    a = phase_bootA()
    b = phase_bootB()
    log("\n================ RESULT ================")
    checks = [
        ("normal boot: hook silent (no flag)",      a.get("hook_silent")),
        ("normal boot: login works after unlock",   a.get("login_works")),
        ("normal boot: flag set for phase 3",       a.get("flag_set")),
        ("resume boot: hook FIRED before unlock",   b.get("hook_fired_pre_unlock")),
        ("resume boot: resumed marker written fresh", b.get("resumed_marker_written")),
        ("resume boot: in-progress flag cleared",   b.get("flag_cleared")),
    ]
    allok = True
    for name, v in checks:
        log(f"  [{'PASS' if v else 'FAIL'}] {name}"); allok = allok and bool(v)
    log("BOOT-RESUME: ALL PASS" if allok else "BOOT-RESUME: FAILURES ABOVE")
    sys.exit(0 if allok else 1)

if __name__ == "__main__":
    main()
